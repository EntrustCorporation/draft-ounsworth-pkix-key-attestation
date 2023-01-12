import re
import subprocess
import sys
import tempfile

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_modules.rfc2985 import ExtensionRequest, pkcs_9_at_extensionRequest
from pyasn1_modules.rfc2986 import CertificationRequest
from pyasn1_modules.rfc5280 import (AttributeValue, Certificate,
                                    id_at_commonName, id_at_countryName,
                                    id_at_organizationalUnitName,
                                    id_at_organizationName)

from .asn1 import (ApplicationKeyInformation, AttestationBundle,
                   DeviceInformation, DeviceSubkeyInformation,
                   id_ApplicationKeyInformation, id_AttestationBundle,
                   id_deviceInformation, id_deviceSubkeyInformation,
                   id_SignatureOnly, policies)
from .common import cert_to_der, cert_to_pem, req_to_der

RE_ISSUER = re.compile(b'Issuer: (.*)')
RE_SUBJECT = re.compile(b'Subject: (.*)')

class Attestation:
    def __init__(self, bundle):
        """Construct an attestation

        bundle -- certificate chain received from HSM (list of DER/PEM)"""
        if isinstance(bundle, bytes):
            ab, _ = decode(bundle, asn1Spec=AttestationBundle())
            self.bundle = [cert_to_pem(bytes(cert)) for cert in ab]
        else:
            self.bundle = bundle

    @classmethod
    def fromcsr(cls, csr):
        """Construct an attestation from a CSR that contains one"""
        bundles = []
        csr = req_to_der(csr)
        csr, _ = decode(csr, asn1Spec=CertificationRequest())
        csri = csr[0]
        attributes = csri[3]
        for attribute in attributes:
            if attribute['type'] == pkcs_9_at_extensionRequest:
                values = attribute['values']
                for extreq in values:
                    extreq, _ = decode(extreq, ExtensionRequest())
                    for ext in extreq:
                        if ext['extnID'] == id_AttestationBundle:
                            bundles.append(bytes(ext['extnValue']))
        if len(bundles) == 0:
            raise Exception("no attestation bundle found")
        if len(bundles) > 1:
            # In this mockup we just error if there are multiple bundles
            # but maybe there's some good reason there'd be more than one?
            raise Exception("multiple attestation bundle found")
        return cls(bundles[0])

    def encode(self):
        ab = AttestationBundle()
        ab.extend([cert_to_der(cert) for cert in self.bundle])
        return encode(ab)

    def verify_bundle(self, rootcert):
        """Verify an attestation bundle
        
        rootcert -- root certificate to trust
        """
        with tempfile.TemporaryDirectory() as d:
            with open(f"{d}/cacert.pem", "wb") as f:
                f.write(cert_to_pem(rootcert))
            with open(f"{d}/chain.pem", "wb") as f:
                for cert in self.bundle[:-1]:
                    f.write(cert_to_pem(cert))
            with open(f"{d}/cert.pem", "wb") as f:
                f.write(cert_to_pem(self.bundle[-1]))
            cmd = ["openssl", "verify",
                   "-CAfile", f"{d}/cacert.pem",
                   "-untrusted", f"{d}/chain.pem",
                   f"{d}/cert.pem"]
            print(cmd)
            subprocess.run(cmd, check=True)
        self.verify_order()

    def verify_order(self):
        """Verify that the certificate chain is well-formed
        
        Does not cryptographically verify the certificate chain - use verify() for that."""
        lastCertType = 0
        for cert in self.bundle:
            cert, _ = decode(cert_to_der(cert), asn1Spec=Certificate())
            tbs = cert[0]
            ids = []
            for ext in tbs['extensions']:
                id = ext["extnID"]
                value = ext["extnValue"]
                if id in {id_deviceInformation, id_deviceSubkeyInformation, id_ApplicationKeyInformation}:
                    ids.append(id)
            if len(ids) == 0:
                certType = 0
            elif len(ids) > 1:
                raise Exception("multiple certificate type extensions found")
            elif ids[0] == id_deviceInformation:
                certType = 1
            elif ids[0] == id_deviceSubkeyInformation:
                certType = 2
            elif ids[0] == id_ApplicationKeyInformation:
                certType = 3
            # Can't 'go backwards' e.g. device identity certificate after device delegation certificate
            if certType < lastCertType:
                raise Exception("invalid certificate order")
            if certType == lastCertType:
                if certType == 1:
                    raise Exception("multiple device identity certificates found")
                if certType == 3:
                    raise Exception("multiple key attestation certificates found")
            lastCertType = certType

    def verify(self, rootcert, csr):
        """Verify an attestation bundle and check that it's consistent with a CSR
        
        rootcert -- root certificate to trust
        """
        self.verify_bundle(rootcert)
        cmd = ["openssl", "req", "-pubkey", "-inform", "PEM", "-noout"]
        print(cmd)
        csr_pubkey = subprocess.run(cmd, check=True, input=csr, capture_output=True).stdout
        cmd = ["openssl", "x509", "-pubkey", "-inform", "PEM", "-noout"]
        print(cmd)
        bundle_pubkey = subprocess.run(cmd, check=True, input=self.bundle[-1], capture_output=True).stdout
        if csr_pubkey != bundle_pubkey:
            raise Exception("CSR and attestation bundle mismatch")

    def analyse(self, file=sys.stdout):
        """Write an analysis of the certificate chain"""
        for cert in self.bundle:
            # Formatting distinguished names is hard, so shell out for that bit
            cmd = ["openssl", "x509", "-text", "-noout"]
            formatted = subprocess.run(cmd, check=True, input=cert, capture_output=True).stdout
            issuer = str(RE_ISSUER.search(formatted).group(1), "UTF-8")
            subject = str(RE_SUBJECT.search(formatted).group(1), "UTF-8")
            cert, _ = decode(cert_to_der(cert), asn1Spec=Certificate())
            tbs = cert[0]
            for ext in tbs['extensions']:
                id = ext["extnID"]
                value = ext["extnValue"]
                if id == id_deviceInformation:
                    value, _ = decode(value, DeviceInformation())
                    print(f"Type:        Device identity certificate", file=file)
                    print(f"Vendor:      {value['vendor']}", file=file)
                    print(f"Model:       {value['model']}", file=file)
                    print(f"Serial:      {value['serial']}", file=file)
                elif id == id_deviceSubkeyInformation:
                    value, _ = decode(value, DeviceSubkeyInformation())
                    print(f"Type:        Device delegation certificate", file=file)
                    print(f"Vendor:      {value['vendor']}", file=file)
                    print(f"Model:       {value['model']}", file=file)
                    print(f"Serial:      {value['serial']}", file=file)
                    print(f"SubkeyRole:  {value['role']}", file=file)
                elif id == id_ApplicationKeyInformation:
                    value, _ = decode(value, ApplicationKeyInformation())
                    print(f"Type:        Key attestation certificate", file=file)
                    print(f"Vendor:      {value['vendor']}", file=file)
                    print(f"Model:       {value['model']}", file=file)
                    print(f"Serial:      {value['serial']}", file=file)
                    policy = value['policy']
                    policy = policies.get(policy, policy)
                    print(f"Policy:      {policy}", file=file)
                    vendorinfo = bytes(value['vendorinfo']).hex(' ')
                    print(f"Vendor info: {vendorinfo}", file=file)
            print(f"Issuer:      {issuer}", file=file)
            print(f"Subject:     {subject}", file=file)
            print("", file=file)

