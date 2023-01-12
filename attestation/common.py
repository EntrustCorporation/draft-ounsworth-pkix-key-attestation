import os
import subprocess

# Root directory for demo internal state
rootdir = os.getenv("ATTESTATION_DEMO_ROOT", os.getenv("HOME") + "/attestation-demo")

def cert_der_to_pem(cert):
    cmd = ["openssl", "x509", "-inform", "DER", "-outform", "PEM"]
    return subprocess.run(cmd, check=True, input=cert, capture_output=True).stdout

def cert_pem_to_der(cert):
    cmd = ["openssl", "x509", "-inform", "PEM", "-outform", "DER"]
    return subprocess.run(cmd, check=True, input=cert, capture_output=True).stdout

def cert_to_pem(cert):
    if b'CERTIFICATE' in cert:
        return cert
    else:
        return cert_der_to_pem(cert)

def cert_to_der(cert):
    if b'CERTIFICATE' in cert:
        return cert_pem_to_der(cert)
    else:
        return cert

def req_der_to_pem(req):
    cmd = ["openssl", "req", "-inform", "DER", "-outform", "PEM"]
    return subprocess.run(cmd, check=True, input=req, capture_output=True).stdout

def req_pem_to_der(req):
    cmd = ["openssl", "req", "-inform", "PEM", "-outform", "DER"]
    return subprocess.run(cmd, check=True, input=req, capture_output=True).stdout

def req_to_pem(req):
    if b'REQUEST' in req:
        return req
    else:
        return req_der_to_pem(req)

def req_to_der(req):
    if b'REQUEST' in req:
        return req_pem_to_der(req)
    else:
        return req
