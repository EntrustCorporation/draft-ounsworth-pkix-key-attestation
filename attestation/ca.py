import os
import subprocess
import tempfile

from .asn1 import id_deviceInformation
from .common import rootdir, cert_to_der, cert_to_pem
from .key import Key


class CA:
    def __init__(self, name, subjectName, caroot=None):
        self.name = name
        if caroot is None:
            caroot = f"{rootdir}/ca/{name}"
        self.rootdir = caroot
        self.signingKey = Key(path=f"{self.rootdir}/private/cakey.pem")
        self.subjectName = subjectName
        self.certpath = f"{self.rootdir}/cacert.pem"
        self.confpath = f"{self.rootdir}/openssl.cnf"


    def generate(self, *args, **kwargs):
        """Generate the CA signing key and filesystem furniture.

        Additional arguments are passed to Key()"""
        os.makedirs(f"{self.rootdir}", exist_ok=True)
        os.makedirs(f"{self.rootdir}/newcerts", exist_ok=True)
        os.makedirs(f"{self.rootdir}/private", mode=0o700, exist_ok=True)
        with open(f"{self.rootdir}/index.txt", "w") as f:
            pass
        self.signingKey.generate(*args, **kwargs)
        with open(self.confpath, "w") as f:
            f.write(f"""
oid_section		= new_oids
openssl_conf = default_conf
[ new_oids ]

[ ca ]
default_ca	= CA_default

[ CA_default ]

dir		= {self.rootdir}
certs		= {self.rootdir}/certs
crl_dir		= {self.rootdir}/crl
database	= {self.rootdir}/index.txt
new_certs_dir	= {self.rootdir}/newcerts
certificate	= {self.certpath}
serial		= {self.rootdir}/serial
crlnumber	= {self.rootdir}/crlnumber
crl		= {self.rootdir}/crl.pem
private_key	= {self.signingKey.path}
x509_extensions	= usr_cert		# The extensions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

default_days	= 365000 		# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 3072
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extensions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options.
# default: PrintableString, T61String, BMPString.
# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= GB
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgets Pty Ltd

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

# SET-ex3			= SET extension number 3

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer

basicConstraints = critical,CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2

""")

    def cert(self):
        """Return the CA certificate in PEM format"""
        with open(self.certpath, "rb") as f:
            return f.read()

    def create_root_cert(self):
        """Create a self-signed root certificate

        Use this on root CAs after calling generate()."""
        cmd = ["openssl", "req",
               "-x509",
               "-subj", self.subjectName,
               "-key", self.signingKey.path,
               "-out", self.certpath]
        print(cmd)
        subprocess.run(cmd, check=True)

    def sign_child(self, child, extensions_name="v3_ca", extensions={}):
        """Sign a child CA or key

        child -- CA or Key to sign
        extensions_name -- extensions to select
        extensions -- dict of extensions

        extensions_name can be a name that appears in the config file, and extensions empty.
        In this case the preconfigured extensions will be used.

        Alternatively extensions_name can be a new string and extensions nonempty.
        In this case the extensions dict will be used to supply the extensions.

        The path to the certificate is returned.
        """
        with tempfile.TemporaryDirectory() as d:
            # Add any extensions we've been given.
            if len(extensions) > 0:
                with open(f"{d}/extensions", "w") as f:
                    f.write(f"[{extensions_name}]\n")
                    for ext, value in extensions.items():
                        data = ":".join("%02X" % b for b in value)
                        f.write(f"{ext}=DER:{data}\n")
                    # Add the usual extensions
                    f.write("subjectKeyIdentifier=hash\n")
                    f.write("authorityKeyIdentifier=keyid:always,issuer\n")
                    if isinstance(child, CA):
                        f.write("basicConstraints=critical,CA:true\n")
                    else:
                        f.write("basicConstraints=CA:false\n")
            if isinstance(child, CA):
                childKey = child.signingKey
                certPath = child.certpath
            else:
                childKey = child
                certPath = None
            cmd = ["openssl", "req",
                "-new",
                "-subj", child.subjectName,
                "-key", childKey.path,
                "-out", f"{d}/csr"]
            print(cmd)
            subprocess.run(cmd, check=True)
            cmd = ["openssl", "ca",
                   "-config", self.confpath,
                   "-policy", "policy_anything",
                   "-extensions", extensions_name,
                   "-rand_serial",
                   "-batch",
                   "-in", f"{d}/csr",
                   "-notext"]
            if len(extensions) > 0:
                cmd.extend(["-extfile", f"{d}/extensions"])
            print(cmd)
            cert = subprocess.run(cmd, check=True, capture_output=True).stdout
            # If we are certifying a CA we write the delegation into its directory tree
            # directly. This is a bit of layering violation but it'll do for now.
            if certPath is not None:  
                with open(certPath, "wb") as f:
                    f.write(cert)
            # We always return the certificate
            return cert

    def sign_factory_ca(self, factoryca):
        """Sign a factory CA certificate

        This creates the delegation from a parent CA (self) to a factory CA."""
        return self.sign_child(factoryca)

    def sign_device(self, device):
        """Sign a device identity certificate"""
        return self.sign_child(device, "device_extensions", {
            str(id_deviceInformation): device.deviceinfo()
        })
