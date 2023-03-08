from pyasn1.type import namedtype,univ,char

# I used https://freeoid.pythonanywhere.com/
id_deviceInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1567])
id_deviceSubkeyInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1568])
id_ApplicationKeyInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1569])

id_SignatureOnly = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1570]) # not used any more
id_AttestationBundle = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1571])

id_Recoverable = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1612])
id_Signature = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1613])
id_Decryption = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1614])
id_KeyAgreement = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1615])
id_KeyTransport = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1616])

policies = {
    id_Signature: "Signature",
    id_Decryption: "Decryption",
    id_KeyAgreement: "KeyAgreement",
    id_KeyTransport: "KeyTransport",
}

class DeviceInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('vendor',  char.UTF8String()),
        namedtype.NamedType('model', char.UTF8String()),
        namedtype.NamedType('serial', char.UTF8String()),
    )

class DeviceSubkeyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('vendor',  char.UTF8String()),
        namedtype.NamedType('model', char.UTF8String()),
        namedtype.NamedType('serial', char.UTF8String()),
        namedtype.NamedType('purpose',  char.UTF8String()),
    )

class ApplicationKeyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('vendor',  char.UTF8String()),
        namedtype.NamedType('model', char.UTF8String()),
        namedtype.NamedType('serial', char.UTF8String()),
        namedtype.NamedType('vendorinfo',  univ.OctetString()),
    )

class AttestationBundle(univ.SequenceOf):
    componentType = univ.OctetString()

# TODO product version info too
