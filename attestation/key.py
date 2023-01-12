import os
import subprocess

from pyasn1.codec.der.encoder import encode

from .asn1 import ApplicationKeyInformation, id_SignatureOnly, id_AttestationBundle


class Key:
    """Some kind of key"""
    def __init__(self, path, subjectName=None):
        self.path = path
        self.subjectName = subjectName

    def generate(self, algorithm="EC", options={"ec_paramgen_curve": "P-521"}):
        """Generate the key"""
        cmd = ["openssl", "genpkey", "-out", self.path, "-algorithm", algorithm]
        for opt, value in options.items():
            cmd.extend(["-pkeyopt", f"{opt}:{value}"])
        print(cmd)
        subprocess.run(cmd, check=True)

    def appkeyinfo(self, device):
        aki = ApplicationKeyInformation()
        aki['vendor'] = device.vendor
        aki['model'] = device.model
        aki['serial'] = device.serial
        aki['policy'] = id_SignatureOnly
        aki['vendorinfo'] = b'vendor-specific information goes here'
        return encode(aki)

    def certreq(self, subjectName, subjectAltName=None, attestation=None):
        """Generate a certificate request

        subjectName -- subject name for this key
        subjectAltName -- full alternative name e.g. "DNS:www.example.com"
        """
        cmd = ["openssl", "req",
                "-new",
                "-subj", subjectName,
                "-key", self.path]
        if subjectAltName is not None:
            cmd += ["-addext", f"subjectAltName={subjectAltName}"]
        if attestation is not None:
            id = str(id_AttestationBundle)
            data = ":".join("%02X" % b for b in attestation)
            cmd += ["-addext", f"{id}=DER:{data}"]
        print(cmd)
        return subprocess.run(cmd, check=True, capture_output=True).stdout
