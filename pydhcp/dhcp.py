import array
from binascii import hexlify, unhexlify
import socket
import struct
import os
import re
import time
from subprocess import Popen, PIPE


# DHCP constants
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8
DHCP_MAGIC_COOKIE = 0x63825363

DHCP_OPERATIONS = {
    1: 'discover',
    2: 'offer',
    3: 'request',
    4: 'decline',
    5: 'ack',
    6: 'nak',
    7: 'release',
    7: 'inform',
}

# Types
INT = '_int'
HEX = '_hex'
IP = '_ip'
MAC = '_mac'
STR = '_str'

DHCP_FIELDS = [
    {'id': 'op', 'name': 'message_type', 'length': 1, 'type': INT},
    {'id': 'htype', 'name': 'hardware_type', 'length': 1, 'type': INT},
    {'id': 'hlen', 'name': 'hardware_address_length', 'length': 1, 'type': INT},
    {'id': 'hops', 'name': 'hops', 'length': 1, 'type': INT},
    {'id': 'xid', 'name': 'transaction_id', 'length': 4, 'type': HEX},
    {'id': 'secs', 'name': 'seconds_elapsed', 'length': 2, 'type': INT},
    {'id': 'flags', 'name': 'boot_flags', 'length': 2, 'type': HEX},
    {'id': 'ciaddr', 'name': 'client_ip', 'length': 4, 'type': IP},
    {'id': 'yiaddr', 'name': 'your_ip', 'length': 4, 'type': IP},
    {'id': 'siaddr', 'name': 'next_server_ip', 'length': 4, 'type': IP},
    {'id': 'giaddr', 'name': 'relay_agent_ip', 'length': 4, 'type': IP},
    {'id': 'chaddr', 'name': 'client_mac', 'length': 16, 'type': MAC},
    {'id': 'sname', 'name': 'server_hostname', 'length': 64, 'type': STR},
    {'id': 'filename', 'name': 'boot_filename', 'length': 128, 'type': STR},
    {'id': 'magic', 'name': 'magic_cookie', 'length': 4, 'type': HEX},
]

DHCP_OPTIONS = [
    {'id': 00, 'name': 'padding', 'length': 1, 'type': HEX},
    {'id': 01, 'name': 'subnet_mask', 'length': 4, 'type': IP},
    {'id': 03, 'name': 'router', 'length': 4, 'type': IP},
    {'id': 06, 'name': 'dns', 'length': 4, 'type': IP},
    {'id': 12, 'name': 'hostname', 'length': 1, 'type': STR},
    {'id': 15, 'name': 'domain_name', 'length': 1, 'type': STR},
    {'id': 28, 'name': 'broadcast_address', 'length': 4, 'type': IP},
    {'id': 51, 'name': 'lease_time', 'length': 4, 'type': INT},
    {'id': 58, 'name': 'renewal_time', 'length': 4, 'type': INT},
    {'id': 59, 'name': 'rebinding_time', 'length': 4, 'type': INT},
    {'id': 53, 'name': 'operation', 'length': 1, 'type': INT},
    {'id': 54, 'name': 'server_id', 'length': 4, 'type': IP},
    {'id': 55, 'name': 'parameter_request', 'length': 0, 'type': HEX},
    {'id': 61, 'name': 'client_id', 'length': 6, 'type': MAC},
]


class DhcpOption(object):

    def __init__(self, value=None, decode=None, id=None, name=None):
        self._value = value
        self._decode = decode
        self.name = name
        self.id = id
        self.length = None
        self.type = None
        option = None

        if id:
            option = self.find_id(id)
        else:
            option = self.find_name(name)

        if option:
            for k, v in option.items():
                setattr(self, k, v)

    @property
    def value(self):
        f = getattr(self, self.type)
        return f()

    def _int(self):
        value = format(self._value, '0%sx' % (2 * self.length))
        return self._tlv_encode(self.id, self.length, value)

    def _ip(self):
        value = socket.inet_aton(self._value).encode('hex')
        return self._tlv_encode(self.id, self.length, value)

    def _mac(self):
        value = value.replace(':', '').lower()
        return self._tlv_encode(self.id, self.length, value)

    def _str(self):
        value = ''.join(x.encode('hex') for x in self._value)
        return self._tlv_encode(self.id, len(value) / 2, value)

    def _hex(self):
        return self._value

    def _tlv_encode(self, t, l, v):
        return format(t, '02x') + format(l, '02x') + v

    def find_id(self, id):
        for option in DHCP_OPTIONS:
            if id == option.get('id'):
                return option

    def find_name(self, name):
        for option in DHCP_OPTIONS:
            if name == option.get('name'):
                return option


class DhcpOptions(object):

    def __init__(self, options=None, **kwargs):

        if options:
            self._tlv_unpack(options)

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def data(self):
        return self._encode()

    def _encode(self):
        data = ''
        for option in DHCP_OPTIONS:
            value = getattr(self, option['name'], None)
            if value:
                data += DhcpOption(id=option['id'], value=value).value

        data += 'ff'

        return data

    def _tlv_unpack(self, tlv):
        options = {}

        while(tlv):
            [t] = struct.unpack('B', tlv[0])
            option = DhcpOption(id=t)
            name = option.name or 'padding'

            if name == 'end':
                break

            if name == 'padding':
                tlv = tlv[1:]
                continue

            [length] = struct.unpack('B', tlv[1])

            value = tlv[2:2 + length]
            tlv = tlv[2 + length:]

            if options.get(name, None):
                options[name].append(value)
            else:
                options[name] = [value]

        for k, v in options.items():
            setattr(self, k, v)


def exec_cmd(cmd_args):
    proc = Popen(cmd_args, stdout=PIPE, stderr=PIPE)
    (stdout, stderr) = proc.communicate()
    proc.wait()
    return (stdout, stderr, proc.returncode)


class Lease(object):

    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac


class DhcpPacket(object):

    def __init__(self, packet=None, **kwargs):
        options = None
        self._defaults()

        if packet:
            packet = hexlify(packet)
            fields = packet[0:480]
            options = packet[480:]
            self._decode_fields(fields)

        self.option = DhcpOptions(options=options)

    def _defaults(self):
        self.hardware_type = 1
        self.hardware_address_length = 6
        self.hops = 0
        self.seconds_elapsed = 0
        self.boot_flags = '8000'
        self.client_ip = '0.0.0.0'
        self.your_ip = '0.0.0.0'
        self.next_server_ip = '0.0.0.0'
        self.relay_agent_ip = '0.0.0.0'
        self.magic_cookie = DHCP_MAGIC_COOKIE

    def _decode_fields(self, data):
        for option in DHCP_FIELDS:
            l = option['length']
            f = getattr(self, '%s_decode' % (option['type']))
            value = f(data[:l * 2])
            data = data[l * 2:]
            setattr(self, option['name'], value)

    def _encode_fields(self):
        data = ''
        for option in DHCP_FIELDS:
            value = getattr(self, option['name'], None)
            l = option['length']
            f = getattr(self, '%s_encode' % (option['type']))
            encoded = f(value, option['length'])
            data += f(value, option['length'])

        return data

    def to_string(self):
        return self._encode_fields() + self.option.data

    def encode(self):
        packet = self._encode_fields() + self.option.data
        encoded = packet.decode('hex')

        return encoded

    def _int_encode(self, value, length):
        value = value or 0
        return format(int(value), '0%sx' % (2 * length))

    def _int_decode(self, value):
        return int(value, 16)

    def _ip_encode(self, value, length=8):
        value = value or '0.0.0.0'
        return socket.inet_aton(value).encode('hex')

    def _ip_decode(self, value):
        return socket.inet_ntoa(value.decode('hex'))

    def _mac_encode(self, value, length):
        value = value or '00:00:00:00:00:00'
        value = value.replace(':', '').lower()
        return value.ljust(2 * length, '0')

    def _mac_decode(self, value):
        value = value.lower()
        return ':'.join(a + b for a, b in zip(value[::2], value[1::2]))

    def _str_encode(self, value, length):
        value = value or ''
        value = ''.join(x.encode('hex') for x in value)
        return value.rjust(2 * length, '0')

    def _str_decode(self, value):
        return value.decode('hex')

    def _hex_encode(self, value, length):
        value = value or '0'
        return value

    def _hex_decode(self, value):
        return value


class DhcpAck(DhcpPacket):

    def __init__(self, packet=None, **kwargs):
        super(DhcpAck, self).__init__(packet=packet, kwargs=kwargs)
        offer.message_type = DHCP_OFFER


class DhcpServer(object):

    def __init__(self, ip=None, interface=None, **kwargs):
        self.port = 67
        self.interface = interface
        self.ip = ip or self.get_ip(interface)
        self.sock = None
        self.bind()

    def bind(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))

    def get_ip(self, interface=None):
        """
        Get the interface ip address
        """
        if not interface:
            interface = self.interface

        command = ['ifconfig', interface]
        stdout, stderr, rc = exec_cmd(command)

        if rc:
            print 'could not get interface information'

        m = re.search(r'inet\s+(?P<ip>\d+.\d+.\d+.\d+)', stdout, re.MULTILINE)
        if m:
            m = m.groupdict()
            return m['ip']

    def nak(self, dhcp):
        nak = dhcp
        nak.message_type = DHCP_ACK

    def offer(self, dhcp):
        offer = dhcp
        offer.message_type = DHCP_OFFER
        offer.hardware_type = 1
        offer.hardware_address_length = 6
        offer.hops = 0
        offer.seconds_elapsed = 0
        offer.boot_flags = '8000'
        offer.client_ip = '0.0.0.0'
        offer.your_ip = '172.16.1.72'
        offer.next_server_ip = '172.16.1.1'
        offer.relay_agent_ip = '172.16.1.99'

        # options
        offer.option.operation = DHCP_OFFER
        offer.option.lease_time = 86400
        offer.option.renewal_time = 43200
        offer.option.rebinding_time = 75600
        offer.option.subnet_mask = '255.255.255.0'
        offer.option.broadcast_address = '10.1.1.255'
        offer.option.dns = '10.1.1.1'
        offer.option.domain_name = 'localdomain'

        print offer.to_string()
        self.sock.sendto(offer.encode(), ('<broadcast>', 68))

    def start(self):
        print 'dhcp server started'
        while True:
            data = self.sock.recv(4096)
            dhcp = DhcpPacket(data)
            if dhcp.message_type == DHCP_DISCOVER:
                print 'sending offer'
                self.offer(dhcp)
            if dhcp.message_type == DHCP_REQUEST:
                print 'sending ack'
                self.ack(dhcp)


d = DhcpServer(interface='en0')
d.start()
