# -*- coding: utf-8 -*-

import pprint

from pyroute2.common import map_namespace, hexdump
from pyroute2.netlink import (
    genlmsg,
    nlmsg,
    nlmsgerr,
    nla,
    nla_base,
    nla_slot,
    NLMSG_ERROR,
    NLM_F_REQUEST,
    NLA_F_NESTED,
    NlaMapAdapter,
    NlaSpec,
    nlmsg_atoms
)
from pyroute2.netlink.generic import GenericNetlinkSocket
from pyroute2.netlink.nlsocket import Marshal
from pyroute2.netlink.exceptions import NetlinkError


JOOL_GENL_NAME = "Jool"
JOOL_HEADER_MAGIC = "jool"
JOOL_CLIENT_VERSION = (4, 1, 9, 0)
JOOL_PROTOCOL_VERSION = 1

# "Xlator" type
XT_TYPE_SIIT = 1
XT_TYPE_NAT64 = 2
# "Xlator" framework
XF_TYPE_NETFILTER = 4
XF_TYPE_IPTABLES = 8
(XF_TYPE_NAMES, XF_TYPE_VALUES) = map_namespace('XF_TYPE', globals())

L4PROTO_TCP = 0
L4PROTO_UDP = 1
L4PROTO_ICMP = 2
L4PROTO_OTHER = 3

ITERATIONS_SET = 1
ITERATIONS_AUTO = 2
ITERATIONS_INFINITE = 4

# Jool operations
JNLOP_INSTANCE_FOREACH = 0
JNLOP_INSTANCE_ADD = 1
JNLOP_INSTANCE_HELLO = 2
JNLOP_INSTANCE_RM = 3
JNLOP_INSTANCE_FLUSH = 4
JNLOP_ADDRESS_QUERY64 = 5
JNLOP_ADDRESS_QUERY46 = 6
JNLOP_STATS_FOREACH = 7
JNLOP_GLOBAL_FOREACH = 8
JNLOP_GLOBAL_UPDATE = 9
JNLOP_EAMT_FOREACH = 10
JNLOP_EAMT_ADD = 11
JNLOP_EAMT_RM = 12
JNLOP_EAMT_FLUSH = 13
JNLOP_BL4_FOREACH = 14
JNLOP_BL4_ADD = 15
JNLOP_BL4_RM = 16
JNLOP_BL4_FLUSH = 17
JNLOP_POOL4_FOREACH = 18
JNLOP_POOL4_ADD = 19
JNLOP_POOL4_RM = 20
JNLOP_POOL4_FLUSH = 21
JNLOP_BIB_FOREACH = 22
JNLOP_BIB_ADD = 23
JNLOP_BIB_RM = 24
JNLOP_SESSION_FOREACH = 25
JNLOP_FILE_HANDLE = 26
JNLOP_JOOLD_ADD = 27
JNLOP_JOOLD_ADVERTISE = 28
JNLOP_JOOLD_ACK = 29

# jool attribute root
JNLAR_ADDR_QUERY = 1
JNLAR_GLOBALS = 2
JNLAR_BL4_ENTRIES = 3
JNLAR_EAMT_ENTRIES = 4
JNLAR_POOL4_ENTRIES = 5
JNLAR_BIB_ENTRIES = 6
JNLAR_SESSION_ENTRIES = 7
JNLAR_OFFSET = 8
JNLAR_OFFSET_U8 = 9
JNLAR_OPERAND = 10
JNLAR_PROTO = 11
JNLAR_ATOMIC_INIT = 12
JNLAR_ATOMIC_END = 13

# jool attribute list
JNLAL_ENTRY = 1

# jool attribute prefix
JNLAP_ADDR = 1
JNLAP_LEN = 2

# jool attribute transport address
JNLAT_ADDR = 1
JNLAT_PORT = 2

# jool instance entry
JNLAIE_NS = 1
JNLAIE_XF = 2
JNLAIE_INAME = 3

# jool instance status
JNLAIS_STATUS = 1

# jool instance add
JNLAIA_XF = 1
JNLAIA_POOL6 = 2

# jool EAM
JNLAE_PREFIX6 = 1
JNLAE_PREFIX4 = 2

# jool pool4
JNLAP4_MARK = 1
JNLAP4_ITERATIONS = 2
JNLAP4_FLAGS = 3
JNLAP4_PROTO = 4
JNLAP4_PREFIX = 5
JNLAP4_PORT_MIN = 6
JNLAP4_PORT_MAX = 7

# jool BIB
JNLAB_SRC6 = 1
JNLAB_SRC4 = 2
JNLAB_PROTO = 3
JNLAB_STATIC = 4

# jool session
JNLASE_SRC6 = 1
JNLASE_DST6 = 2
JNLASE_SRC4 = 3
JNLASE_DST4 = 4
JNLASE_PROTO = 5
JNLASE_STATE = 6
JNLASE_TIMER = 7
JNLASE_EXPIRATION = 8

# jool address query
JNLAAQ_ADDR6 = 1
JNLAAQ_ADDR4 = 2
JNLAAQ_PREFIX6052 = 3
JNLAAQ_EAM = 4

# jool global attributes
# Common
JNLAG_ENABLED = 1
JNLAG_POOL6 = 2
JNLAG_LOWEST_IPV6_MTU = 3
JNLAG_DEBUG = 4
JNLAG_RESET_TC = 5
JNLAG_RESET_TOS = 6
JNLAG_TOS = 7
JNLAG_PLATEAUS = 8
# SIIT
JNLAG_COMPUTE_CSUM_ZERO = 9
JNLAG_HAIRPIN_MODE = 10
JNLAG_RANDOMIZE_ERROR_ADDR = 11
JNLAG_POOL6791V6 = 12
JNLAG_POOL6791V4 = 13
# NAT64
JNLAG_DROP_BY_ADDR = 14
JNLAG_DROP_EXTERNAL_TCP = 15
JNLAG_DROP_ICMP6_INFO = 16
JNLAG_SRC_ICMP6_BETTER = 17
JNLAG_F_ARGS = 18
JNLAG_HANDLE_RST = 19
JNLAG_TTL_TCP_EST = 20
JNLAG_TTL_TCP_TRANS = 21
JNLAG_TTL_UDP = 22
JNLAG_TTL_ICMP = 23
JNLAG_BIB_LOGGING = 24
JNLAG_SESSION_LOGGING = 25
JNLAG_MAX_STORED_PKTS = 26
# joold
JNLAG_JOOLD_ENABLED = 27
JNLAG_JOOLD_FLUSH_ASAP = 28
JNLAG_JOOLD_FLUSH_DEADLINE = 29
JNLAG_JOOLD_CAPACITY = 30
JNLAG_JOOLD_MAX_PAYLOAD = 31
(JNLAG_NAMES, JNLAG_VALUES) = map_namespace('JNLAG', globals())

# jool error
JNLAERR_CODE = 1
JNLAERR_MSG = 2

# joolhdr flags
JOOLNLHDR_FLAGS_ERROR = 1
JOOLNLHDR_FLAGS_FORCE = 2
JOOLNLHDR_FLAGS_QUICK = 4
JOOLNLHDR_FLAGS_M = 8

# jool statistics
JSTAT_RECEIVED6 = 1
JSTAT_RECEIVED4 = 2
JSTAT_SUCCESS = 3
JSTAT_BIB_ENTRIES = 4
JSTAT_SESSIONS = 5
JSTAT_ENOMEM = 6
JSTAT_XLATOR_DISABLED = 7
JSTAT_POOL6_UNSET = 8
JSTAT_SKB_SHARED = 9
JSTAT_L3HDR_OFFSET = 10
JSTAT_SKB_TRUNCATED = 11
JSTAT_HDR6 = 12
JSTAT_HDR4 = 13
JSTAT_UNKNOWN_L4_PROTO = 14
JSTAT_UNKNOWN_ICMP6_TYPE = 15
JSTAT_UNKNOWN_ICMP4_TYPE = 16
JSTAT_DOUBLE_ICMP6_ERROR = 17
JSTAT_DOUBLE_ICMP4_ERROR = 18
JSTAT_UNKNOWN_PROTO_INNER = 19
JSTAT_HAIRPIN_LOOP = 20
JSTAT_POOL6_MISMATCH = 21
JSTAT_POOL4_MISMATCH = 22
JSTAT_ICMP6_FILTER = 23
JSTAT_UNTRANSLATABLE_DST6 = 24
JSTAT_UNTRANSLATABLE_DST4 = 25
JSTAT_6056_F = 26
JSTAT_MASK_DOMAIN_NOT_FOUND = 27
JSTAT_BIB6_NOT_FOUND = 28
JSTAT_BIB4_NOT_FOUND = 29
JSTAT_SESSION_NOT_FOUND = 30
JSTAT_ADF = 31
JSTAT_V4_SYN = 32
JSTAT_SYN6_EXPECTED = 33
JSTAT_SYN4_EXPECTED = 34
JSTAT_TYPE1PKT = 35
JSTAT_TYPE2PKT = 36
JSTAT_SO_EXISTS = 37
JSTAT_SO_FULL = 38
JSTAT64_SRC = 39
JSTAT64_DST = 40
JSTAT64_PSKB_COPY = 41
JSTAT64_6791_ENOENT = 42
JSTAT64_ICMP_CSUM = 43
JSTAT64_UNTRANSLATABLE_PARAM_PROB_PTR = 44
JSTAT64_TTL = 45
JSTAT64_FRAGMENTED_ICMP = 46
JSTAT64_2XFRAG = 47
JSTAT64_FRAG_THEN_EXT = 48
JSTAT64_SEGMENTS_LEFT = 49
JSTAT46_SRC = 50
JSTAT46_DST = 51
JSTAT46_PSKB_COPY = 52
JSTAT46_6791_ENOENT = 53
JSTAT46_ICMP_CSUM = 54
JSTAT46_UNTRANSLATABLE_PARAM_PROBLEM_PTR = 55
JSTAT46_TTL = 56
JSTAT46_FRAGMENTED_ICMP = 57
JSTAT46_SRC_ROUTE = 58
JSTAT46_FRAGMENTED_ZERO_CSUM = 59
JSTAT46_BAD_MTU = 60
JSTAT_FAILED_ROUTES = 61
JSTAT_PKT_TOO_BIG = 62
JSTAT_DST_OUTPUT = 63
JSTAT_ICMP6ERR_SUCCESS = 64
JSTAT_ICMP6ERR_FAILURE = 65
JSTAT_ICMP4ERR_SUCCESS = 66
JSTAT_ICMP4ERR_FAILURE = 67
JSTAT_ICMPEXT_BIG = 68
JSTAT_UNKNOWN = 69
JSTAT_PADDING = 70
(JSTAT_NAMES, JSTAT_VALUES) = map_namespace('JSTAT', globals())

# jool custom NL message header
class jnlmsg(nlmsg):
    fields = (
        ('command', 'B'),
        ('version', 'B'),
        ('reserved', 'H'),
        ('magic', '4s'),
        ('joolver', '4B'),
        ('xt_type', 'B'),
        ('flags', 'B'),
        ('reserved1', 'B'),
        ('reserved2', 'B'),
        ('instance', '16s')
    )

# jool error message
class jnlmsgerr(jnlmsg):
    nla_map = (
        (JNLAERR_CODE, 'JNLAERR_CODE', 'uint16'),
        (JNLAERR_MSG, 'JNLAERR_MSG', 'asciiz')
    )

# layer4 proto
class l4proto(nlmsg_atoms.uint8):
    value_map = {
        L4PROTO_TCP: 'tcp',
        L4PROTO_UDP: 'udp',
        L4PROTO_ICMP: 'icmp',
        L4PROTO_OTHER: 'other'
    }

# IPv6 prefix (IP/mask)
class prefix6(nla):
    prefix = 'JNLAP_'

    nla_map = (
        (JNLAP_ADDR, 'JNLAP_ADDR', 'ip6addr'),
        (JNLAP_LEN, 'JNLAP_LEN', 'uint8')
    )

    def encode(self, *argv, **kwarg):
        if self.value is not None:
            if self.value.find('/') == -1:
                self.value = self.value + '/128'
            addr, mask = self.value.split('/')
            self['attrs'].append([self.name2nla('addr'), addr])
            self['attrs'].append([self.name2nla('len'), int(mask)])
            self.value = None
        nla.encode(self, *argv, **kwarg)

    def decode(self, *argv, **kwarg):
        nla.decode(self, *argv, **kwarg)
        addr = self.get_attr('JNLAP_ADDR')
        mask = self.get_attr('JNLAP_LEN')
        if addr is None or mask is None:
            return
        self.value = '{}/{}'.format(addr, mask)
        self['attrs'].clear()

# IPv4 prefix (IP/mask)
class prefix4(nla):
    prefix = 'JNLAP_'

    nla_map = (
        (JNLAP_ADDR, 'JNLAP_ADDR', 'ip4addr'),
        (JNLAP_LEN, 'JNLAP_LEN', 'uint8')
    )

    def encode(self, *argv, **kwarg):
        if self.value is not None:
            if self.value.find('/') == -1:
                self.value = self.value + '/32'
            addr, mask = self.value.split('/')
            self['attrs'].append([self.name2nla('addr'), addr])
            self['attrs'].append([self.name2nla('len'), int(mask)])
            self.value = None
        nla.encode(self, *argv, **kwarg)

    def decode(self, *argv, **kwarg):
        nla.decode(self, *argv, **kwarg)
        addr = self.get_attr('JNLAP_ADDR')
        mask = self.get_attr('JNLAP_LEN')
        if addr is None or mask is None:
            return
        self.value = '{}/{}'.format(addr, mask)
        self['attrs'].clear()

# Explicit Address Mapping record
class eamrecord(nla):
    prefix = 'JNLAE_'

    nla_map = (
        (JNLAE_PREFIX6, 'JNLAE_PREFIX6', 'prefix6'),
        (JNLAE_PREFIX4, 'JNLAE_PREFIX4', 'prefix4')
    )

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

    class prefix6(prefix6):
        nla_flags = NLA_F_NESTED

# IPv4 pool record
class pool4(nla):
    prefix = 'JNLAP4_'

    nla_map = (
        (JNLAP4_MARK, 'JNLAP4_MARK', 'uint32'),
        (JNLAP4_ITERATIONS, 'JNLAP4_ITERATIONS', 'uint32'),
        (JNLAP4_FLAGS, 'JNLAP4_FLAGS', 'pool4_flags'),
        (JNLAP4_PROTO, 'JNLAP4_PROTO', 'l4proto'),
        (JNLAP4_PREFIX, 'JNLAP4_PREFIX', 'prefix4'),
        (JNLAP4_PORT_MIN, 'JNLAP4_PORT_MIN', 'uint16'),
        (JNLAP4_PORT_MAX, 'JNLAP4_PORT_MAX', 'uint16')
    )

    class pool4_flags(nlmsg_atoms.uint8):
        value_map = {
            ITERATIONS_SET: 'set',
            ITERATIONS_AUTO: 'auto',
            ITERATIONS_INFINITE: 'infinite'
        }

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# IPv6 transport address (~socket)
class ip6taddr(nla):
    prefix = 'JNLAT_'

    nla_map = (
        (JNLAT_ADDR, 'JNLAT_ADDR', 'ip6addr'),
        (JNLAT_PORT, 'JNLAT_PORT', 'uint16')
    )

    # supports the following formats
    # - IP#port (jool format)
    # - [IP]:port (common format)
    def encode(self, *argv, **kwarg):
        if self.value is not None and type(self.value) is str:
            ip, port = (None, None)
            if self.value.find('#') != -1:
                ip, port = self.value.split('#')
                port = int(port)
            elif self.value.find(']:') != -1:
                ip, port = self.value.split(']:')
                ip = ip[1:]
                port = int(port)
            else:
                raise ValueError('Invalid transport address: {}'.format(self.value))
            self['attrs'].append([self.name2nla('addr'), ip])
            self['attrs'].append([self.name2nla('port'), port])
            self.value = None
        nla.encode(self, *argv, **kwarg)

    def decode(self, *argv, **kwarg):
        nla.decode(self, *argv, **kwarg)

# IPv4 transport address (~socket)
class ip4taddr(nla):
    prefix = 'JNLAT_'

    nla_map = (
        (JNLAT_ADDR, 'JNLAT_ADDR', 'ip4addr'),
        (JNLAT_PORT, 'JNLAT_PORT', 'uint16')
    )

    # supports the following formats:
    # - IP#port (jool format)
    # - IP:port (common format)
    def encode(self, *argv, **kwarg):
        if self.value is not None and type(self.value) is str:
            ip, port = (None, None)
            if self.value.find('#') != -1:
                ip, port = self.value.split('#')
                port = int(port)
            elif self.value.find(':') != -1:
                ip, port = self.value.split(':')
                port = int(port)
            else:
                raise ValueError('Invalid transport address: {}'.format(self.value))
            self['attrs'].append([self.name2nla('addr'), ip])
            self['attrs'].append([self.name2nla('port'), port])
        nla.encode(self, *argv, **kwarg)

    def decode(self, *argv, **kwarg):
        nla.decode(self, *argv, **kwarg)

# Binding Information Base record
class bibrecord(nla):
    prefix = 'JNLAB_'

    nla_map = (
        (JNLAB_SRC6, 'JNLAB_SRC6', 'ip6taddr'),
        (JNLAB_SRC4, 'JNLAB_SRC4', 'ip4taddr'),
        (JNLAB_PROTO, 'JNLAB_PROTO', 'l4proto'),
        (JNLAB_STATIC, 'JNLAB_STATIC', 'uint8')
    )

    class ip6taddr(ip6taddr):
        nla_flags = NLA_F_NESTED

    class ip4taddr(ip4taddr):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# NAT64 session
class session(nla):
    prefix = 'JNLASE_'

    nla_map = (
        (JNLASE_SRC6, 'JNLASE_SRC6', 'ip6taddr'),
        (JNLASE_DST6, 'JNLASE_DST6', 'ip6taddr'),
        (JNLASE_SRC4, 'JNLASE_SRC4', 'ip4taddr'),
        (JNLASE_DST4, 'JNLASE_DST4', 'ip4taddr'),
        (JNLASE_PROTO, 'JNLASE_PROTO', 'l4proto'),
        (JNLASE_STATE, 'JNLASE_STATE', 'uint8'),
        (JNLASE_TIMER, 'JNLASE_TIMER', 'uint8'),
        (JNLASE_EXPIRATION, 'JNLASE_EXPIRATION', 'uint32')
    )

    class ip6taddr(ip6taddr):
        nla_flags = NLA_F_NESTED

    class ip4taddr(ip4taddr):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# jool global settings
class jglobals(nla):
    prefix = 'JNLAG_'

    nla_map = (
        (JNLAG_ENABLED, 'JNLAG_ENABLED', 'uint8'),
        (JNLAG_POOL6, 'JNLAG_POOL6', 'prefix6'),
        (JNLAG_LOWEST_IPV6_MTU, 'JNLAG_LOWEST_IPV6_MTU', 'uint32'),
        (JNLAG_DEBUG, 'JNLAG_DEBUG', 'uint8'),
        (JNLAG_RESET_TC, 'JNLAG_RESET_TC', 'uint8'),
        (JNLAG_RESET_TOS, 'JNLAG_RESET_TOS', 'uint8'),
        (JNLAG_TOS, 'JNLAG_TOS', 'uint8'),
        (JNLAG_PLATEAUS, 'JNLAG_PLATEAUS', '*uint16'),
        (JNLAG_COMPUTE_CSUM_ZERO, 'JNLAG_COMPUTE_CSUM_ZERO', 'uint8'),
        (JNLAG_HAIRPIN_MODE, 'JNLAG_HAIRPIN_MODE', 'uint8'),
        (JNLAG_RANDOMIZE_ERROR_ADDR, 'JNLAG_RANDOMIZE_ERROR_ADDR', 'uint8'),
        (JNLAG_POOL6791V6, 'JNLAG_POOL6791V6', 'prefix6'),
        (JNLAG_POOL6791V4, 'JNLAG_POOL6791V4', 'prefix4'),
        (JNLAG_DROP_BY_ADDR, 'JNLAG_DROP_BY_ADDR', 'uint8'),
        (JNLAG_DROP_EXTERNAL_TCP, 'JNLAG_DROP_EXTERNAL_TCP', 'uint8'),
        (JNLAG_DROP_ICMP6_INFO, 'JNLAG_DROP_ICMP6_INFO', 'uint8'),
        (JNLAG_SRC_ICMP6_BETTER, 'JNLAG_SRC_ICMP6_BETTER', 'uint8'),
        (JNLAG_F_ARGS, 'JNLAG_F_ARGS', 'uint8'),
        (JNLAG_HANDLE_RST, 'JNLAG_HANDLE_RST', 'uint8'),
        (JNLAG_TTL_TCP_EST, 'JNLAG_TTL_TCP_EST', 'uint32'),
        (JNLAG_TTL_TCP_TRANS, 'JNLAG_TTL_TCP_TRANS', 'uint32'),
        (JNLAG_TTL_UDP, 'JNLAG_TTL_UDP', 'uint32'),
        (JNLAG_TTL_ICMP, 'JNLAG_TTL_ICMP', 'uint32'),
        (JNLAG_BIB_LOGGING, 'JNLAG_BIB_LOGGING', 'uint8'),
        (JNLAG_SESSION_LOGGING, 'JNLAG_SESSION_LOGGING', 'uint8'),
        (JNLAG_MAX_STORED_PKTS, 'JNLAG_MAX_STORED_PKTS', 'uint32'),
        (JNLAG_JOOLD_ENABLED, 'JNLAG_JOOLD_ENABLED', 'uint8'),
        (JNLAG_JOOLD_FLUSH_ASAP, 'JNLAG_JOOLD_FLUSH_ASAP', 'uint8'),
        (JNLAG_JOOLD_FLUSH_DEADLINE, 'JNLAG_JOOLD_FLUSH_DEADLINE', 'uint32'),
        (JNLAG_JOOLD_CAPACITY, 'JNLAG_JOOLD_CAPACITY', 'uint32'),
        (JNLAG_JOOLD_MAX_PAYLOAD, 'JNLAG_JOOLD_MAX_PAYLOAD', 'uint32')
    )

    class prefix6(prefix6):
        nla_flags = NLA_F_NESTED

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# jool instance record
class jinstance(nla):
    prefix = 'JNLAIE_'

    nla_map = (
        (JNLAIE_NS, 'JNLAIE_NS', 'uint32'),
        (JNLAIE_XF, 'JNLAIE_XF', 'uint8'),
        (JNLAIE_INAME, 'JNLAIE_INAME', 'asciiz')
    )

# instance list request
class jnlmsg_ilistq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'jinstance'),
    )

    class jinstance(jinstance):
        nla_flags = NLA_F_NESTED

# instance list response
class jnlmsg_ilistr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'jinstance'),
    )

    class jinstance(jinstance):
        nla_flags = NLA_F_NESTED

# instance add request
class jnlmsg_iadd(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OPERAND, 'JNLAR_OPERAND', 'operand'),
    )

    class operand(nla):
        nla_flags = NLA_F_NESTED
        prefix = 'JNLAIA_'

        nla_map = (
            (JNLAIA_XF, 'JNLAIA_XF', 'uint8'),
            (JNLAIA_POOL6, 'JNLAIA_POOL6', 'prefix6')
        )

        class prefix6(prefix6):
            nla_flags = NLA_F_NESTED

# instance "hello" (status) response
class jnlmsg_ihello(jnlmsg):
    prefix = 'JNLAIS_'

    nla_map = (
        (JNLAIS_STATUS, 'JNLAIS_STATUS', 'uint8'),
    )

# address query 6->4
class jnlmsg_addq64(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_ADDR_QUERY, 'JNLAR_ADDR_QUERY', 'ip6addr'),
    )

# address query 4->6
class jnlmsg_addq46(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_ADDR_QUERY, 'JNLAR_ADDR_QUERY', 'ip4addr'),
    )

# address query response
class jnlmsg_addqr(jnlmsg):
    prefix = 'JNLAAQ_'

    nla_map = (
        (JNLAAQ_ADDR6, 'JNLAAQ_ADDR6', 'ip6addr'),
        (JNLAAQ_ADDR4, 'JNLAAQ_ADDR4', 'ip4addr'),
        (JNLAAQ_PREFIX6052, 'JNLAAQ_PREFIX6052', 'prefix6'),
        (JNLAAQ_EAM, 'JNLAAQ_EAM', 'eamrecord')
    )

    class prefix6(prefix6):
        nla_flags = NLA_F_NESTED

    class eamrecord(eamrecord):
        nla_flags = NLA_F_NESTED

# stats response
class jnlmsg_stats(jnlmsg):
    def jstat_nla_spec(key):
        return NlaSpec(nlmsg_atoms.uint64, key, JSTAT_VALUES[key])

    nla_map = NlaMapAdapter(jstat_nla_spec)

# global settings response
class jnlmsg_glist(jnlmsg):
    prefix = jglobals.prefix
    nla_map = jglobals.nla_map

    class prefix6(prefix6):
        nla_flags = NLA_F_NESTED

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# global settings update
class jnlmsg_gupd(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_GLOBALS, 'JNLAR_GLOBALS', 'jglobals'),
    )

    class jglobals(jglobals):
        nla_flags = NLA_F_NESTED

# EAM table list query
class jnlmsg_eamtlistq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'prefix4'),
    )

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# EAM table list response
class jnlmsg_eamtlistr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'eamrecord'),
    )

    class eamrecord(eamrecord):
        nla_flags = NLA_F_NESTED

# EAM add and remove op
class jnlmsg_eamtop(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OPERAND, 'JNLAR_OPERAND', 'eamrecord'),
    )

    class eamrecord(eamrecord):
        nla_flags = NLA_F_NESTED

# blacklist4 list query
class jnlmsg_bl4listq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'prefix4'),
    )

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# blacklist4 list response
class jnlmsg_bl4listr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'prefix4'),
    )

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# blacklist4 add and remove op
class jnlmsg_bl4op(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OPERAND, 'JNLAR_OPERAND', 'prefix4'),
    )

    class prefix4(prefix4):
        nla_flags = NLA_F_NESTED

# pool4 query
class jnlmsg_p4listq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'pool4'),
        (JNLAR_PROTO, 'JNLAR_PROTO', 'l4proto')
    )

    class pool4(pool4):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# pool4 response
class jnlmsg_p4listr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'pool4'),
    )

    class pool4(pool4):
        nla_flags = NLA_F_NESTED

# pool4 add and remove op
class jnlmsg_p4op(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OPERAND, 'JNLAR_OPERAND', 'pool4'),
    )

    class pool4(pool4):
        nla_flags = NLA_F_NESTED

# BIB query
class jnlmsg_biblistq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'bibrecord'),
        (JNLAR_PROTO, 'JNLAR_PROTO', 'l4proto')
    )

    class bibrecord(bibrecord):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# BIB response
class jnlmsg_biblistr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'bibrecord'),
    )

    class bibrecord(bibrecord):
        nla_flags = NLA_F_NESTED

# BIB add and remove op
class jnlmsg_bibop(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OPERAND, 'JNLAR_OPERAND', 'bibrecord'),
    )

    class bibrecord(bibrecord):
        nla_flags = NLA_F_NESTED

# session list request
class jnlmsg_sesslq(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_OFFSET, 'JNLAR_OFFSET', 'session'),
        (JNLAR_PROTO, 'JNLAR_PROTO', 'l4proto')
    )

    class session(session):
        nla_flags = NLA_F_NESTED

    class l4proto(l4proto):
        pass

# session list response
class jnlmsg_sesslr(jnlmsg):
    prefix = 'JNLAL_'

    nla_map = (
        (JNLAL_ENTRY, 'JNLAL_ENTRY', 'session'),
    )

    class session(session):
        nla_flags = NLA_F_NESTED

# atomic configuration request
class jnlmsg_atomcfg(jnlmsg):
    prefix = 'JNLAR_'

    nla_map = (
        (JNLAR_ATOMIC_INIT, 'JNLAR_ATOMIC_INIT', 'flag'),
        (JNLAR_GLOBALS, 'JNLAR_GLOBALS', 'jglobals'),
        (JNLAR_BL4_ENTRIES, 'JNLAR_BL4_ENTRIES', 'prefix4_entry'),
        (JNLAR_EAMT_ENTRIES, 'JNLAR_EAMT_ENTRIES', 'eam_entry'),
        (JNLAR_POOL4_ENTRIES, 'JNLAR_POOL4_ENTRIES', 'pool4_entry'),
        (JNLAR_BIB_ENTRIES, 'JNLAR_BIB_ENTRIES', 'bib_entry'),
        (JNLAR_ATOMIC_END, 'JNLAR_ATOMIC_END', 'flag')
    )

    class jglobals(jglobals):
        nla_flags = NLA_F_NESTED

    class prefix4_entry(nla):
        prefix = 'JNLAL_'

        nla_map = (
            (JNLAL_ENTRY, 'JNLAL_ENTRY', 'prefix4'),
        )

        class prefix4(prefix4):
            nla_flags = NLA_F_NESTED

    class eam_entry(nla):
        prefix = 'JNLAL_'

        nla_map = (
            (JNLAL_ENTRY, 'JNLAL_ENTRY', 'eamrecord'),
        )

        class eamrecord(eamrecord):
            nla_flags = NLA_F_NESTED

    class pool4_entry(nla):
        prefix = 'JNLAL_'

        nla_map = (
            (JNLAL_ENTRY, 'JNLAL_ENTRY', 'pool4'),
        )

        class pool4(pool4):
            nla_flags = NLA_F_NESTED

    class bib_entry(nla):
        prefix = 'JNLAL_'

        nla_map = (
            (JNLAL_ENTRY, 'JNLAL_ENTRY', 'bibrecord'),
        )

        class bibrecord(bibrecord):
            nla_flags = NLA_F_NESTED

class MarshalJool(Marshal):
    # jool does not send any kind of data that might be used to
    # distinguish between message types, only sequence number can be used
    default_message_class = jnlmsg

    jool_response_map = {
        JNLOP_INSTANCE_FOREACH: jnlmsg_ilistr,
        JNLOP_INSTANCE_ADD: jnlmsg, # returns only ACK
        JNLOP_INSTANCE_HELLO: jnlmsg_ihello,
        JNLOP_INSTANCE_RM: jnlmsg, # returns only ACK
        JNLOP_INSTANCE_FLUSH: jnlmsg, # returns only ACK
        JNLOP_ADDRESS_QUERY64: jnlmsg_addqr,
        JNLOP_ADDRESS_QUERY46: jnlmsg_addqr,
        JNLOP_STATS_FOREACH: jnlmsg_stats,
        JNLOP_GLOBAL_FOREACH: jnlmsg_glist,
        JNLOP_GLOBAL_UPDATE: jnlmsg, # returns only ACK
        JNLOP_EAMT_FOREACH: jnlmsg_eamtlistr,
        JNLOP_EAMT_ADD: jnlmsg, # returns only ACK
        JNLOP_EAMT_RM: jnlmsg, # returns only ACK
        JNLOP_EAMT_FLUSH: jnlmsg, # returns only ACK
        JNLOP_BL4_FOREACH: jnlmsg_bl4listr,
        JNLOP_BL4_ADD: jnlmsg, # returns only ACK
        JNLOP_BL4_RM: jnlmsg, # returns only ACK
        JNLOP_BL4_FLUSH: jnlmsg, # returns only ACK
        JNLOP_POOL4_FOREACH: jnlmsg_p4listr,
        JNLOP_POOL4_ADD: jnlmsg, # returns only ACK
        JNLOP_POOL4_RM: jnlmsg, # returns only ACK
        JNLOP_POOL4_FLUSH: jnlmsg, # returns only ACK
        JNLOP_BIB_FOREACH: jnlmsg_biblistr,
        JNLOP_BIB_ADD: jnlmsg, # returns only ACK
        JNLOP_BIB_RM: jnlmsg, # returns only ACK
        JNLOP_SESSION_FOREACH: jnlmsg_sesslr,
        JNLOP_FILE_HANDLE: jnlmsg, # returns only ACK
        #JNLOP_JOOLD_ADD:
        #JNLOP_JOOLD_ADVERTISE:
        #JNLOP_JOOLD_ACK:
    }

    def fix_message(self, msg):
        error = None
        # standard netlink error
        if msg['header']['type'] == NLMSG_ERROR:
            errmsg = nlmsgerr(msg.data)
            errmsg.decode()
            error = NetlinkError(
                abs(errmsg['error']), errmsg.get_attr('NLMSGERR_ATTR_MSG')
            )
        # extract custom error from jool netlink message
        elif msg['flags'] & JOOLNLHDR_FLAGS_ERROR:
            errmsg = jnlmsgerr(msg.data)
            errmsg.decode()
            error = NetlinkError(
                abs(errmsg.get_attr('JNLAERR_CODE')), errmsg.get_attr('JNLAERR_MSG')
            )
        msg['header']['error'] = error

class JoolSocket(GenericNetlinkSocket):
    def __init__(self):
        GenericNetlinkSocket.__init__(self)

    def bind(self, groups=0, **kwarg):
        GenericNetlinkSocket.bind(
            self, JOOL_GENL_NAME, jnlmsg, groups, None, **kwarg
        )
        # we have to override marshal after bind because bind uses
        # the default marshal class for protocol discovery
        self.marshal = MarshalJool()

    def get_joolparser(self, command):
        def jnlparser(data, offset, length):
            parser = self.marshal.jool_response_map.get(command, self.marshal.default_message_class)
            msg = parser(data, offset, length)
            msg.decode()
            msg['command'] = command
            return msg
        return jnlparser

    def nlm_request(self, *argv, **kwarg):
        msg = None
        if len(argv) > 0:
            msg = argv[0]
        elif 'msg' in kwarg:
            msg = kwarg['msg']
        if 'command' in msg:
            # response command is always 0
            # we have to fix it for Marshalling to work
            command = msg['command']
            kwarg['parser'] = self.get_joolparser(command)
        return tuple(super().nlm_request(*argv, **kwarg))

# common class
class JoolBase(JoolSocket):
    def __init__(self):
        JoolSocket.__init__(self)
        JoolSocket.bind(self)

    # handle MORE flag here
    def _nlm_request(self, *argv, **kwarg):
        result = ()
        while True:
            ret = self.nlm_request(*argv, **kwarg)
            result += ret
            # MORE flag set
            # we need to issue a new request for the remaining results
            # TODO: support JNLAR_OFFSET_U8 (stats request)
            # currently it is not needed because answer fits into one response
            # TODO: support EAMT offset
            # EAMT offset is not based on returned object
            if ret[0]['flags'] & JOOLNLHDR_FLAGS_M:
                last = ret[0]['attrs'][-1]
                offset = nla_slot('JNLAR_OFFSET', last.cell[1])
                argv[0]['attrs'] = [offset]
            else:
                return result

    def _make_message(self, command, command_map, instance):
        msg = command_map[command][0]()
        msg['command'] = command_map[command][1]
        msg['version'] = JOOL_PROTOCOL_VERSION
        msg['magic'] = JOOL_HEADER_MAGIC
        msg['joolver'] = JOOL_CLIENT_VERSION
        msg['xt_type'] = self._xt_type
        msg['instance'] = instance
        return msg

    def instance(self, command, instance='default', pool6='64:ff9b::/96', framework='netfilter'):
        command_map = {
            'list': (jnlmsg_ilistq, JNLOP_INSTANCE_FOREACH),
            'add': (jnlmsg_iadd, JNLOP_INSTANCE_ADD),
            'hello': (jnlmsg, JNLOP_INSTANCE_HELLO),
            'remove': (jnlmsg, JNLOP_INSTANCE_RM),
            'flush': (jnlmsg, JNLOP_INSTANCE_FLUSH)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'add':
            xf_type = XF_TYPE_NAMES['XF_TYPE_{}'.format(framework.upper())]
            op = jnlmsg_iadd.operand()
            op['attrs'].append([jnlmsg_iadd.operand.name2nla('xf'), xf_type])
            if pool6 is not None:
                op['attrs'].append([jnlmsg_iadd.operand.name2nla('pool6'), pool6])
            msg['attrs'].append([jnlmsg_iadd.name2nla('operand'), op])
        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def stats(self, command, instance='default'):
        command_map = {
            'list': (jnlmsg, JNLOP_STATS_FOREACH)
        }

        msg = self._make_message(command, command_map, instance)
        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    # global is a built-in keyword
    def options(self, command, instance='default', options={}):
        command_map = {
            'list': (jnlmsg, JNLOP_GLOBAL_FOREACH),
            'update': (jnlmsg_gupd, JNLOP_GLOBAL_UPDATE)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'update':
            glattr = jglobals()
            for option, value in options.items():
                glattr['attrs'].append([glattr.name2nla(option), value])
            msg['attrs'].append([msg.name2nla('globals'), glattr])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    # this requires a lot of restructuring so
    # TODO: support atomic operations
    def atomic(self, command, instance='default'):
        raise NotImplemented()

# NAT64
class Jool(JoolBase):
    def __init__(self):
        super().__init__()
        self._xt_type = XT_TYPE_NAT64

    def pool4(self, command, instance='default', proto='tcp', pool={}):
        command_map = {
            'list': (jnlmsg_p4listq, JNLOP_POOL4_FOREACH),
            'add': (jnlmsg_p4op, JNLOP_POOL4_ADD),
            'remove': (jnlmsg_p4op, JNLOP_POOL4_RM),
            'flush': (jnlmsg, JNLOP_POOL4_FLUSH)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'list':
            msg['attrs'].append([msg.name2nla('proto'), proto])

        if command == 'add' or command == 'remove':
            p4 = pool4()
            for option, value in pool.items():
                p4['attrs'].append([p4.name2nla(option), value])
            msg['attrs'].append([msg.name2nla('operand'), p4])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def bib(self, command, instance='default', proto='tcp', bib={}):
        command_map = {
            'list': (jnlmsg_biblistq, JNLOP_BIB_FOREACH),
            'add': (jnlmsg_bibop, JNLOP_BIB_ADD),
            'remove': (jnlmsg_bibop, JNLOP_BIB_RM)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'list':
            msg['attrs'].append([msg.name2nla('proto'), proto])

        if command == 'add' or command == 'remove':
            bibr = bibrecord()
            for option, value in bib.items():
                bibr['attrs'].append([bibr.name2nla(option), value])
            msg['attrs'].append([msg.name2nla('operand'), bibr])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def session(self, command, instance='default', proto='tcp'):
        command_map = {
            'list': (jnlmsg_sesslq, JNLOP_SESSION_FOREACH)
        }

        msg = self._make_message(command, command_map, instance)
        msg['attrs'].append([msg.name2nla('proto'), proto])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

# SIIT
class Jool_SIIT(JoolBase):
    def __init__(self):
        super().__init__()
        self._xt_type = XT_TYPE_SIIT

    def instance(self, *argv, **kwarg):
        # in SIIT pool6 is not mandatory
        if 'pool6' not in kwarg:
            kwarg['pool6'] = None
        return JoolBase.instance(self, *argv, **kwarg)

    def address(self, command, instance='default', address=None):
        command_map = {
            'query46': (jnlmsg_addq46, JNLOP_ADDRESS_QUERY46),
            'query64': (jnlmsg_addq64, JNLOP_ADDRESS_QUERY64)
        }
        if command == 'query':
            if address.find(':') != -1:
                command_map['query'] = command_map['query64']
            else:
                command_map['query'] = command_map['query46']

        msg = self._make_message(command, command_map, instance)
        msg['attrs'].append([msg.name2nla('addr_query'), address])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def eamt(self, command, instance='default', eam={}):
        command_map = {
            'list': (jnlmsg_eamtlistq, JNLOP_EAMT_FOREACH),
            'add': (jnlmsg_eamtop, JNLOP_EAMT_ADD),
            'remove': (jnlmsg_eamtop, JNLOP_EAMT_RM),
            'flush': (jnlmsg, JNLOP_EAMT_FLUSH)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'add' or command == 'remove':
            eamr = eamrecord()
            for option, value in eam.items():
                eamr['attrs'].append([eamr.name2nla(option), value])
            msg['attrs'].append([msg.name2nla('operand'), eamr])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def blacklist4(self, command, instance='default', prefix=None):
        command_map = {
            'list': (jnlmsg_bl4listq, JNLOP_BL4_FOREACH),
            'add': (jnlmsg_bl4op, JNLOP_BL4_ADD),
            'remove': (jnlmsg_bl4op, JNLOP_BL4_RM),
            'flush': (jnlmsg, JNLOP_BL4_FLUSH)
        }

        msg = self._make_message(command, command_map, instance)

        if command == 'add' or command == 'remove':
            msg['attrs'].append([msg.name2nla('operand'), prefix])

        return self._nlm_request(msg, self.prid, NLM_F_REQUEST)

    def denylist4(self, *argv, **kwarg):
        self.blacklist4(*argv, **kwarg)
