from ryu.lib.packet import packet_base
import struct, random
from hashlib import md5
import hmac

# Codes
RADIUS_CODE_ACCESS_REQUEST      =   1
RADIUS_CODE_ACCESS_ACCEPT       =   2
RADIUS_CODE_ACCESS_REJECT       =   3
RADIUS_CODE_ACCOUNTING_REQUEST  =   4
RADIUS_CODE_ACCOUNTING_RESPONSE =   5
RADIUS_CODE_ACCESS_CHALLENGE    =  11
RADIUS_CODE_STATUS_SERVER       =  12
RADIUS_CODE_STATUS_CLIENT       =  13
RADIUS_CODE_RESERVED            = 255

# Attributes
RADIUS_ATTRIBUTE_USER_NAME = 1
RADIUS_ATTRIBUTE_USER_PASSWORD = 2
RADIUS_ATTRIBUTE_CHAP_PASSWORD = 3
RADIUS_ATTRIBUTE_NAS_IP_ADDR = 4
RADIUS_ATTRIBUTE_NAS_PORT = 5
RADIUS_ATTRIBUTE_SERVICE_TYPE = 6
RADIUS_ATTRIBUTE_FRAMED_PROTOCOL = 7
RADIUS_ATTRIBUTE_FRAMED_IP_ADDR = 8
RADIUS_ATTRIBUTE_FRAMED_IP_NETMASK = 9
RADIUS_ATTRIBUTE_FRAMED_ROUTING = 10
RADIUS_ATTRIBUTE_FILTER_ID = 11
RADIUS_ATTRIBUTE_FRAMED_MTU = 12
RADIUS_ATTRIBUTE_FRAMED_COMPRESSION = 13
RADIUS_ATTRIBUTE_LOGIN_IP_HOST = 14
RADIUS_ATTRIBUTE_LOGIN_SERVICE = 15
RADIUS_ATTRIBUTE_LOGIN_TCP_PORT = 16
# unassigned
RADIUS_ATTRIBUTE_REPLY_MESSAGE = 18
RADIUS_ATTRIBUTE_CALLBACK_NUMBER = 19
RADIUS_ATTRIBUTE_CALLBACK_ID = 20
# unassigned
RADIUS_ATTRIBUTE_FRAMED_ROUTE = 22
RADIUS_ATTRIBUTE_FRAMED_IPX_NETWORK = 23
RADIUS_ATTRIBUTE_STATE = 24
RADIUS_ATTRIBUTE_CLASS = 25
RADIUS_ATTRIBUTE_VENDOR_SPECIFIC = 26
RADIUS_ATTRIBUTE_SESSION_TIMEOUT = 27
RADIUS_ATTRIBUTE_IDLE_TIMEOUT = 28
RADIUS_ATTRIBUTE_TERMINATION_ACTION = 29
RADIUS_ATTRIBUTE_CALLED_STATION_ID = 30
RADIUS_ATTRIBUTE_CALLING_STATION_ID = 31
RADIUS_ATTRIBUTE_NAS_ID = 32
RADIUS_ATTRIBUTE_PROXY_STATE = 33
RADIUS_ATTRIBUTE_LOGIN_LAT_SERVICE = 34
RADIUS_ATTRIBUTE_LOGIN_LAT_NODE = 35
RADIUS_ATTRIBUTE_LOGIN_LAT_GROUP = 36
RADIUS_ATTRIBUTE_FRAMED_ATALK_LINK = 37
RADIUS_ATTRIBUTE_FRAMED_ATALK_NETWORK = 38
RADIUS_ATTRIBUTE_FRAMED_ATALK_ZONE = 39
# 40-59 reserved for accounting
RADIUS_ATTRIBUTE_CHAP_CHALLENGE = 60
RADIUS_ATTRIBUTE_NAS_PORT_TYPE = 61
RADIUS_ATTRIBUTE_PORT_LIMIT = 62
RADIUS_ATTRIBUTE_LOGIN_LAT_PORT = 63

# RFC 2869 - Extensions to RADIUS
RADIUS_ATTRIBUTE_EAP_MESSAGE = 79
RADIUS_ATTRIBUTE_MESSAGE_AUTHENTICATOR = 80
RADIUS_ATTRIBUTE_TUNNEL_PRIVATE_GROUP_ID = 81
RADIUS_ATTRIBUTE_NAS_PORT_ID = 87

# Service Type Attributes
RADIUS_SERVICE_TYPE_LOGIN = 1
RADIUS_SERVICE_TYPE_FRAMED = 2
RADIUS_SERVICE_TYPE_CALLBACK_LOGIN = 3
RADIUS_SERVICE_TYPE_CALLBACK_FRAMED = 4
RADIUS_SERVICE_TYPE_OUTBOUND = 5
RADIUS_SERVICE_TYPE_ADMINISTRATIVE = 6
RADIUS_SERVICE_TYPE_NAS_PROMPT = 7
RADIUS_SERVICE_TYPE_AUTHENTICATE_ONLY = 8
RADIUS_SERVICE_TYPE_CALLBACK_NAS_PROMPT = 9
RADIUS_SERVICE_TYPE_CALL_CHECK = 10
RADIUS_SERVICE_TYPE_CALLBACK_ADMINISTRATIVE = 11

# (RFC 2856: 5.41) NAS_PORT_TYPE Values
RADIUS_NAS_PORT_TYPE_ASYNC = 0
RADIUS_NAS_PORT_TYPE_SYNC = 1
RADIUS_NAS_PORT_TYPE_ISDN_SYNC = 2
RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V_120 = 3
RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V_110 = 4
RADIUS_NAS_PORT_TYPE_VIRTUAL = 5
RADIUS_NAS_PORT_TYPE_PIAFS = 6
RADIUS_NAS_PORT_TYPE_HDLC_CLEAR_CHANNEL = 7
RADIUS_NAS_PORT_TYPE_X_25 = 8
RADIUS_NAS_PORT_TYPE_X_75 = 9
RADIUS_NAS_PORT_TYPE_G_3_FAX = 10
RADIUS_NAS_PORT_TYPE_SDSL = 11
RADIUS_NAS_PORT_TYPE_ADSL_CAP = 12
RADIUS_NAS_PORT_TYPE_ADSL_DMT = 13
RADIUS_NAS_PORT_TYPE_IDSL = 14
RADIUS_NAS_PORT_TYPE_ETHERNET = 15
RADIUS_NAS_PORT_TYPE_XDSL = 16
RADIUS_NAS_PORT_TYPE_CABLE = 17
RADIUS_NAS_PORT_TYPE_WIRELESS_OTHRT = 18
RADIUS_NAS_PORT_TYPE_WIRELESS_802_11 = 19
# Vendor-Specific-Attributes
RADIUS_VENDOR_EAPOUDP = 50000
RADIUS_ATTRIBUTE_EAPOUDP_IMAGE_ID = 1
RADIUS_ATTRIBUTE_EAPOUDP_ALLOWED_IPS = 2


def get_bytes(data):
    if type(data) == bytearray:
        return data
    if type(data) != str:
        data = str(data)
    return bytearray(data)


def get_random_str(n=16):
    # return bytes(random.getrandbits(8) for _ in range(n))  # python3
    return ''.join(chr(random.getrandbits(8)) for _ in xrange(n))


class radius(packet_base.PacketBase):
    """
    RADIUS packet format according to RFC 2865:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                         Authenticator                         |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Attributes ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-


    Attribute format:
     0                   1                   2
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    |     Type      |    Length     |  Value ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-


    Vendor-Specific-Attribute format:
    0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |  Length       |            Vendor-Id
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         Vendor-Id (cont)           | Vendor type   | Vendor length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Attribute-Specific...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    """

    _PACK_STR = '!BBH16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = {
        'ascii': [
            'radius_code', 'identifier', 'length', 'authenticator'
        ]
    }

    def __init__(self, radius_code=RADIUS_CODE_ACCESS_REQUEST, identifier=0, authenticator=get_random_str(),
                 secret="testing123", attributes=None):
        super(radius, self).__init__()
        self.radius_code = radius_code
        self.identifier = identifier
        self.length = 20
        self.authenticator = authenticator
        self.secret = secret
        self.attributes = attributes if attributes else \
            {RADIUS_ATTRIBUTE_USER_NAME: "testing", RADIUS_ATTRIBUTE_USER_PASSWORD: "password"}

    @classmethod
    def parser(cls, buf):
        # TODO: add extra parser with integrity check!
        assert len(buf) >= cls._MIN_LEN, \
            "the packet is too short (min_len={}, given={}, bytes)".format(cls._MIN_LEN, len(buf))
        (radius_code, identifier, length, authenticator) = struct.unpack(cls._PACK_STR, buf[:cls._MIN_LEN])
        assert len(buf) == length, \
            "the packet length ({}) does not match with the length field in the packet ({})".format(len(buf), length)
        pointer = cls._MIN_LEN
        attributes = {}
        while pointer < length:
            assert pointer+2 <= length, "not enough bytes left for the next attribute"
            t, l = struct.unpack("!BB", buf[pointer:pointer+2])
            assert pointer+l <= length, \
                "the attribute {} with length {} but only {} left for the data".format(t, l, length-pointer)
            pointer += 2
            l -= 2  # exclude type and length
            if t == RADIUS_ATTRIBUTE_VENDOR_SPECIFIC:
                if t not in attributes.keys():
                    attributes[t] = {}
                # vendor, vendor-attr, len, value
                vendor, vendor_attr, value_len = struct.unpack("!IBB", buf[pointer:pointer+6])
                value_len -= 2  # exclude type and length
                assert value_len == l-6, "VSA length {} does not match with the value length {}".format(value_len, l-6)
                if vendor not in attributes[t].keys():
                    attributes[t][vendor] = {}
                attributes[t][vendor][vendor_attr] = struct.unpack("!{}s".format(value_len), buf[pointer+6:pointer+l])[0]
            else:
                attributes[t] = struct.unpack("!{}s".format(l), buf[pointer:pointer+l])[0]
            pointer += l

        return cls(radius_code=radius_code, identifier=identifier, authenticator=authenticator, attributes=attributes)

    def serialize(self, payload, prev):
        # pack the attributes
        attr = bytes()
        for t, v in self.attributes.items():
            # special attributes
            if t == RADIUS_ATTRIBUTE_USER_PASSWORD:  # see https://tools.ietf.org/html/rfc2865 chapter 5.2 User-Password
                password = [bytearray(v[i:i+16]) for i in range(0, len(v), 16)]  # split password into 16bytes chunks
                if len(password[-1]) != 16:  # fits the last chunk?
                    password[-1] = password[-1].ljust(16, b'0')  # pad it with nulls
                b = bytearray(md5(self.secret + self.authenticator).digest())  # temporary hash
                v = bytearray()  # clear result
                for p in password:
                    for i in xrange(16):  # bitwise xor password chunk's p with temporary hash b
                        v += chr(p[i] ^ b[i])  # bytes((p[i] ^ b[i],)) in python3
                    b = md5(self.secret + v[-16:]).digest()  # new temporary hash
            # pack data
            if t == RADIUS_ATTRIBUTE_VENDOR_SPECIFIC and type(v) == dict:
                data = ''
                for vendor in v.keys():
                    for vendor_attr in v[vendor].keys():
                        vv = v[vendor][vendor_attr]
                        data += struct.pack("!IBB{}s".format(len(vv)), vendor, vendor_attr, len(vv)+2, vv)
            elif type(v) == int:
                data = struct.pack("!I", v)
            else:
                data = struct.pack("!{}s".format(len(v)), str(v))
            # combine attribute: type + length + data_value
            attr += struct.pack("!BB", t, len(data)+2) + data
        # if necessary, add Message-Authenticator attribute, filled with zeros as placeholder
        if RADIUS_ATTRIBUTE_EAP_MESSAGE in self.attributes.keys():
            attr += struct.pack("!BB", RADIUS_ATTRIBUTE_MESSAGE_AUTHENTICATOR, 18) + struct.pack("B", 0) * 16
        # pack head
        head = struct.pack(self._PACK_STR, self.radius_code, self.identifier, 20+len(attr), self.authenticator)
        # calculate the Message-Authenticator if necessary
        if RADIUS_ATTRIBUTE_EAP_MESSAGE in self.attributes.keys():
            # HMAC-MD5: shared secret as key + payload (Type, Identifier, Length, Request Authenticator, Attributes)
            data = hmac.new(self.secret, head+attr).digest()
            attr = attr[:-16] + struct.pack("!16s", data)  # replace the placeholder
        # TODO: calculate the response Authenticator for Access-Accept, Access-Reject, and Access-Challenge packets
        return head + attr
