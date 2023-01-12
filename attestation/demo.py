import os
import subprocess

from .ca import CA
from .common import rootdir
from .device import Device, DeviceSubkey
from .key import Key
from . attestation import Attestation


def run():
    """Run the demo"""

    # Mockup of HSM vendor

    # In this demo, ACME is a hypothetical HSM vendor. They maintain an offline HSM attestation root.
    acme_hsm_root_ca = CA("acme-hsm-root", subjectName="/C=GB/O=ACME/OU=Security/CN=HSM Attestation root")
    acme_hsm_root_ca.generate()
    acme_hsm_root_ca.create_root_cert()

    # Each ACME factory site has an online CA. When a new factory is created the attestation root
    # certifies the factory CA.
    #
    # In principle there could be multiple levels of delegation here; in this example there is just one.
    # There could also be no delegations, i.e. the root is used to sign devices directly.
    acme_factory_uk_ca = CA("acme-factory-uk", subjectName="/C=GB/O=ACME/OU=Production/CN=UK manufacturing CA")
    acme_factory_uk_ca.generate()
    acme_hsm_root_ca.sign_factory_ca(acme_factory_uk_ca)

    # Each HSM has a long-term device identity key. The factory CA certifies this key during the manufacturing process,
    # creating the device identity certificate.
    #
    # In this example HSMs are identified by UUID. Any string will do.
    device = Device("ACME", "SignMaster 9000", "0293b07e-01b4-4836-99d2-8a5d3f9fae6e")
    device.generate()
    acme_factory_uk_ca.sign_device(device)

    # Mockup of HSM

    # HSMs may have multiple intermediate signing keys. These may either reflect different
    # tenants, or they may be replaced when the HSM is reinitialized. The HSM certifies them
    # when they are created, creating device delegation certificates.
    #
    # Again there may be multiple levels of delegation here, for example from the device identity
    # key to a per-tenant key and from that to a per-initialization key (or the other way around).
    # There could also be 0 delegations with the device identity key used to directly sign application keys.
    # In this example there is only one.
    subkey = DeviceSubkey(device, "KOA", "623ea754-ffdb-4c1f-825c-07d16ace1cf6") # Key Origin Attestation
    subkey.generate()
    device.sign_subkey(subkey)

    # When an HSM generates an application key it certifies it using its intermediate
    # signing key (or, potentially, the device identity key).
    #
    # Note that the HSM does not know what the 'real' subject name for the key is
    # (in this example we make one up with UUID). That's not an inherent part of the design
    # but it's a possible use case - the HSM may simply not be able to express the intended
    # subject name (and subjectAltName).
    os.makedirs(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002", exist_ok=True)
    os.makedirs(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/private", exist_ok=True, mode=0o700)
    appkey = Key(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/private/key.pem", "/CN=8ee89f19-83c6-4317-bf0c-6d8a5a257002")
    appkey.generate()
    appkeyCert = subkey.sign_appkey(appkey)

    # Put together the attestation bundle for the key
    attestation = Attestation([acme_factory_uk_ca.cert(), device.cert(), subkey.cert(), appkeyCert])
    
    # Write the raw attestation to a file
    with open(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/attestation.der", "wb") as f:
        f.write(attestation.encode())

    # Display OpenSSL's interpretation of the attestation chain to file
    with open(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/attestation.openssl.txt", "wb") as f:
        for cert in attestation.bundle:
            cmd = ["openssl", "x509", "-text", "-noout"]
            output = subprocess.run(cmd, check=True, input=cert, capture_output=True).stdout
            f.write(output)

    # Mockup of application

    # Make a CSR for the application key
    appkeyreq = appkey.certreq("/O=ACME/OU=Marketing/CN=www.acme.com", "DNS:www.acme.com", attestation.encode())

    # Mockup of third-party CA

    # Verify the self-cert on the CSR
    cmd = ["openssl", "req", "-verify", "-noout"]
    print(cmd)
    subprocess.run(cmd, input=appkeyreq, check=True)
    # Extract the attestation bundle from the CSR
    embedded_attestation = Attestation.fromcsr(appkeyreq)
    # Verify the attestation bundle signature and enforce that it cerfifies the same key as in the CSR
    embedded_attestation.verify(acme_hsm_root_ca.cert(), appkeyreq)

    # Save the CSR for inspection
    with open(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/req.pem", "wb") as f:
        f.write(appkeyreq)
    # ...and get OpenSSL to describe it
    cmd = ["openssl", "req", "-text", "-noout"]
    with open(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/req.openssl.txt", "wb") as f:
        output = subprocess.run(cmd, check=True, input=appkeyreq, capture_output=True).stdout
        f.write(output)

    # Save our analysis of the attestation to a file
    with open(f"{rootdir}/appkeys/8ee89f19-83c6-4317-bf0c-6d8a5a257002/attestation.analysis.txt", "w") as f:
        embedded_attestation.analyse(f)
    # ...and print it out for anyone reading our output
    embedded_attestation.analyse()

    print("OK")