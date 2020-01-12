from ryu.lib.packet import packet_base
import struct
from hashlib import md5

EAP_CODE_REQUEST  = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS  = 3
EAP_CODE_FAILURE  = 4

EAP_TYPE_IDENTITY     = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK          = 3
EAP_TYPE_MD5CHALLENGE = 4


def get_bytes(data):
    if data: return struct.pack("!{}s".format(len(data)), data)
    else: return ""


class eap(packet_base.PacketBase):
    """
    EAP packet format according to RFC 3748:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Data ...
    +-+-+-+-+

    Request and Response packet format:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |  Type-Data ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    """

    _PACK_STR = '!BBH'
    _EAP_LEN_PACK_STR = '!B'
    _EAP_DATA_PACK_STR = '!{}s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'eap_code', 'identifier', 'eap_type', 'data', 'challenge'
        ]
    }

    def __init__(self, eap_code=EAP_CODE_REQUEST, identifier=0, eap_type=EAP_TYPE_IDENTITY, data=None, challenge=None):
        super(eap, self).__init__()
        self.eap_code = eap_code
        self.identifier = identifier
        self.length = 4
        self.eap_type = eap_type
        self.challenge = get_bytes(challenge)
        self.data = get_bytes(data)
        if self.eap_code in [EAP_CODE_REQUEST, EAP_CODE_RESPONSE]:
            self.length += 1  # +1 type field
            if len(self.challenge) > 0:
                self.length += len(self.challenge) + 1  # +1 value-size
            if len(self.data) > 0:
                self.length += len(self.data)

    @staticmethod
    def calc_md5_challenge(identifier, password, challenge):
        return md5(
            struct.pack("!B", identifier)
            + get_bytes(password)
            + get_bytes(challenge)
        ).digest()

    @classmethod
    def parser(cls, buf):
        assert len(buf) >= cls._MIN_LEN, \
            "the packet is too short (min_len={}, given={}, bytes)".format(cls._MIN_LEN, len(buf))
        (eap_code, identifier, length) = struct.unpack(cls._PACK_STR, buf[:cls._MIN_LEN])
        assert len(buf) == length, \
            "the packet length ({}) does not match with the length field in the packet ({})".format(len(buf), length)
        if eap_code in [EAP_CODE_SUCCESS, EAP_CODE_FAILURE]:
            assert len(buf) == cls._MIN_LEN, \
                "the packet is too long (is={}, should={})".format(len(buf), cls._MIN_LEN)
            return cls(eap_code=eap_code, identifier=identifier)
        assert eap_code in [EAP_CODE_REQUEST, EAP_CODE_RESPONSE], \
            "unknown EAP code, given={}".format(eap_code)
        assert length > cls._MIN_LEN, \
            "the packet is too short, no type field?"
        eap_type = struct.unpack(cls._EAP_LEN_PACK_STR, buf[cls._MIN_LEN:cls._MIN_LEN+1])[0]
        if eap_type == EAP_TYPE_MD5CHALLENGE:
            cl = struct.unpack(cls._EAP_LEN_PACK_STR, buf[cls._MIN_LEN+1:cls._MIN_LEN+2])[0]
            challenge = struct.unpack(cls._EAP_DATA_PACK_STR.format(cl), buf[cls._MIN_LEN+2:cls._MIN_LEN+2+cl])[0]
            data = struct.unpack(cls._EAP_DATA_PACK_STR.format(length-cls._MIN_LEN-2-cl), buf[cls._MIN_LEN+2+cl:])[0]
        else:
            challenge = None
            data = struct.unpack(cls._EAP_DATA_PACK_STR.format(length-cls._MIN_LEN-1), buf[cls._MIN_LEN+1:])[0]
        return cls(eap_code=eap_code, identifier=identifier, eap_type=eap_type, data=data, challenge=challenge)

    def serialize(self, payload, prev):
        res = struct.pack(self._PACK_STR, self.eap_code, self.identifier, self.length)
        if self.eap_code in [EAP_CODE_REQUEST, EAP_CODE_RESPONSE]:
            res += struct.pack(self._EAP_LEN_PACK_STR, self.eap_type)
            if self.challenge and len(self.challenge) > 0:
                l = len(self.challenge)
                res += struct.pack(self._EAP_LEN_PACK_STR, l)
                res += struct.pack(self._EAP_DATA_PACK_STR.format(l), self.challenge)
            if self.data and len(self.data) > 0:
                res += struct.pack(self._EAP_DATA_PACK_STR.format(len(self.data)), self.data)
        return res
