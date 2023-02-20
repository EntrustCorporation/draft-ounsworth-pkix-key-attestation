import os

from pyasn1.codec.der.encoder import encode

from .asn1 import (DeviceInformation, DeviceSubkeyInformation,
                   id_ApplicationKeyInformation, id_deviceSubkeyInformation)
from .ca import CA
from .common import rootdir
from .key import Key


class Device(CA):
    """Representation of a single hardware device"""

    def __init__(self, vendor, model, serial):
        """Create the device"""
        # I don't really know what kind of DN an HSM should have so I've
        # just put vendor and serial number in.
        super().__init__(serial, f"/O={vendor}/CN={serial}", caroot=f"{rootdir}/devices/{serial}/device")
        self.vendor = vendor
        self.serial = serial
        self.model = model

    def deviceinfo(self):
        """Return serialized device information in DER format"""
        di = DeviceInformation()
        di['vendor'] = self.vendor
        di['model'] = self.model
        di['serial'] = self.serial
        return encode(di)

    def sign_subkey(self, subkey):
        """Sign a device delegation certificate"""
        return self.sign_child(subkey, "device_extensions", {
            str(id_deviceSubkeyInformation): subkey.subkeyinfo()
        })

class DeviceSubkey(CA):
    """Representation of a subsiduary key in a hardware device"""
    def __init__(self, device, purpose, serial):
        assert purpose != "device" # clash with Device class
        super().__init__(serial, f"/O={device.vendor}/CN={serial}", caroot=f"{rootdir}/devices/{device.serial}/{purpose}")
        self.device = device
        self.purpose = purpose
        self.serial = serial

    def subkeyinfo(self):
        """Return serialized subkey information in DER format"""
        dsi = DeviceSubkeyInformation()
        dsi['vendor'] = self.device.vendor
        dsi['model'] = self.device.model
        dsi['purpose'] = self.purpose
        dsi['serial'] = self.device.serial
        return encode(dsi)

    def sign_appkey(self, appkey):
        """Sign an application key origin certificate"""
        return self.sign_child(appkey, "appkey_extensions", {
            str(id_ApplicationKeyInformation): appkey.appkeyinfo(self.device)
        })
