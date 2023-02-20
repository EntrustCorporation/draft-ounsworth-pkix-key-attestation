from pyasn1.type import namedtype,univ,char

# I used https://freeoid.pythonanywhere.com/
id_deviceInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1567])
id_deviceSubkeyInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1568])
id_ApplicationKeyInformation = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1569])

id_SignatureOnly = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1570])
id_AttestationBundle = univ.ObjectIdentifier([1, 3, 6, 1, 4, 1, 54392, 5, 1571])

policies = {
    id_SignatureOnly: "SignatureOnly",
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
        namedtype.NamedType('policy',  univ.ObjectIdentifier()),
        namedtype.NamedType('vendorinfo',  univ.OctetString()),
    )

class AttestationBundle(univ.SequenceOf):
    componentType = univ.OctetString()

# TODO product version info too
