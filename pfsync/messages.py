from .mixins import UnpackableMixin


class PFStateKey(UnpackableMixin):
    """
    A class corresponding to the following C struct:
    See FreeBSD sources sys/net/pfvar.h

    struct pfsync_state_key {
        struct pf_addr	 addr[2];
        u_int16_t	 port[2];
    };


    """
    unpack_format = '!16s16s 2H'

    @staticmethod
    def format_addr(addr):
        """
        Format the IP address as a string
        Does not works with IPV6 addresses

        """
        import socket

        return socket.inet_ntoa(addr[:4])

    def __init__(self,
                 addr1, addr2,
                 port1, port2):
        self.addr = (
            self.format_addr(addr1),
            self.format_addr(addr2))
        self.port = (port1, port2)


class MessageState(UnpackableMixin):
    """
    A class corresponding to the following C struct:
    struct pfsync_state_1301 {
        u_int64_t	 id;
        char		 ifname[IFNAMSIZ];
        struct pfsync_state_key	key[2];
        struct pfsync_state_peer src;
        struct pfsync_state_peer dst;
        struct pf_addr	 rt_addr;
        u_int32_t	 rule;
        u_int32_t	 anchor;
        u_int32_t	 nat_rule;
        u_int32_t	 creation;
        u_int32_t	 expire;
        u_int32_t	 packets[2][2];
        u_int32_t	 bytes[2][2];
        u_int32_t	 creatorid;
        sa_family_t	 af;
        u_int8_t	 proto;
        u_int8_t	 direction;
        u_int8_t	 __spare[2];
        u_int8_t	 log;
        u_int8_t	 state_flags;
        u_int8_t	 timeout;
        u_int8_t	 sync_flags;
        u_int8_t	 updates;
    } __packed;


    __str__ and is_nat methods are inspired of OpenBSD;s tcpdump
    See OpenBSD sources src/usr.sbin/tcpdump/print-pfsync.c
    /*
     * INS, UPD, DEL
     */

    /* these use struct pfsync_state

    """

    @classmethod
    def get_unpack_format(cls):
        """
        Brace yourselves, long dirty string is coming.

        Unpacking of structs is done as a string with the size of the
        struct and will be unpacked again in __init__

        Tabs are replaced with their size * their type (ex: int a[2] ->
        'ii') and will be repacked in tuples in __init__
        This does not stand for ifname

        The pf_addr struct (which is in fact an union containing the
        128bits ip address) is extracted as 4 32 bits unsigned int which
        will be our preferred form

        """
        from struct import calcsize

        unpack_format = '!Q 16s'
        unpack_format += '%(state_key_size)ds%(state_key_size)ds' % {'state_key_size': PFStateKey.get_cstruct_size(), }
        unpack_format += '%(state_peer_size)ds%(state_peer_size)ds' % {
            'state_peer_size': calcsize('%dsIIIHHBB6B' % calcsize('HBBI')),  # to fix
        }
        unpack_format += '4I IIIII 4I 4I I B BB 2B BBBBB'
        return unpack_format

    def __init__(self, *args):
        _id, ifname, \
            key1, key2, \
            _, _, \
            _, _, _, _, \
            rule, _, _, \
            creation, expire, \
            packets1, packets2, packets3, packets4, \
            bytes1, bytes2, bytes3, bytes4, \
            creator_id, \
            _, \
            protocol, \
            direction, \
            _, _, \
            log, \
            _, \
            timeout, _, _ = args
        self.id = _id
        self.creator = creator_id
        self.interface = ifname.split(b'\0')[0]  # Berk
        self.key = (PFStateKey.from_data(key1)[0],
                    PFStateKey.from_data(key2)[0])
        self.packets = ((packets1, packets2), (packets3, packets4))
        self.bytes = ((bytes1, bytes2), (bytes3, bytes4))
        self.protocol = protocol
        self.direction = direction
        self.timeout = timeout
        self.expire = expire
        self.creation = creation
        self.rule = rule
        self.log = log

    def __str__(self):
        msg = f"{hex(self.id)} (created by {hex(self.creator)}) - {self.interface} {self.get_protocol_name()} "
        if self.is_nat():
            msg += "%(pub_source)s:%(pub_port)d (%(priv_source)s:%(priv_port)d) -> %(dest)s:%(dest_port)d" % {
                'pub_source': self.key[0].addr[1],
                'pub_port': self.key[0].port[1],
                'priv_source': self.key[1].addr[1],
                'priv_port': self.key[1].port[1],
                'dest': self.key[0].addr[0],
                'dest_port': self.key[0].port[0]
            }
        else:
            msg += f"%(pub_source)s:%(pub_port)d  {'<-' if self.direction ==0 else '->'} %(dest)s:%(dest_port)d" % {
                'pub_source': self.key[0].addr[1],
                'pub_port': self.key[0].port[1],
                'dest': self.key[0].addr[0],
                'dest_port': self.key[0].port[0]
            }
        return msg

    def is_nat(self):
        """
        This method determines if the source was NATted
        """
        return self.key[1].addr[1] != self.key[0].addr[1]

    def get_protocol_name(self):
        """
        Returns the protocol name based on the protocol id
        Should use a stdlib method instead of this dirty quick solution

        """
        if self.protocol == 1:
            return "ICMP"
        elif self.protocol == 6:
            return "TCP"
        elif self.protocol == 17:
            return "UDP"
        elif self.protocol == 112:
            return "VRRP"
        else:
            return str(self.protocol)


class MessageDeleteCompressed(UnpackableMixin):
    """
    This class handle pfsync_del_c messages.
    It follows the same structure as the following C struct:
    struct pfsync_del_c {
    u_int64_t                       id;
    u_int32_t                       creatorid;
    } __packed;

    See OpenBSD sources sys/net/if_pfsync.h

    """
    unpack_format = '!QI'

    def __init__(self, id, creator_id):
        self.id = id
        self.creator = creator_id

    def __str__(self):
        return "%d (created by %d)" % (self.id, self.creator)


class MessageClear(UnpackableMixin):
    """
    This class handle psync_clr messages.
    It corresponds to the following C struct:
    struct pfsync_clr {
        char				ifname[IFNAMSIZ];
        u_int32_t			creatorid;
    } __packed;


    See OpenBSD sources sys/net/if_pfsync.h

    """
    unpack_format = "!16s I"

    def __init__(self, iface, creator_id):
        self.interface = iface
        self.creator = creator_id

    def __str__(self):
        return "Deleted all states on %s (created by %d)" % (self.interface, self.creator)


class MessageInsertAck(UnpackableMixin):
    """
    This class handle pfsync_ins_ack messages.
    It corresponds to the following C struct:
    struct pfsync_ins_ack {
        u_int64_t			id;
        u_int32_t			creatorid;
    } __packed;



    See OpenBSD sources sys/net/if_pfsync.h

    """
    unpack_format = "!Q I"

    def __init__(self, id, creator_id):
        self.id = id
        self.creator = creator_id

    def __str__(self):
        return "Ack of inserted state on %s (created by %d)" % (self.id, self.creator)


class MessageUpdateReq(UnpackableMixin):
    """
    This class handle pfsync_upd_req messages.
    It corresponds to the following C struct:
    struct pfsync_upd_req {
        u_int64_t			id;
        u_int32_t			creatorid;
    } __packed;

    See OpenBSD sources sys/net/if_pfsync.h

    """
    unpack_format = "!Q I"

    def __init__(self, id, creator_id):
        self.id = id
        self.creator = creator_id

    def __str__(self):
        return "Update state on %s (created by %d)" % (self.id, self.creator)


class MessageUpdateCompressed(UnpackableMixin):
    """
    This class handle pfsync_upd_c messages.
    It corresponds to the following C struct:
    struct pfsync_upd_c {
        u_int64_t			id;
        struct pfsync_state_peer	src;
        struct pfsync_state_peer	dst;
        u_int32_t			creatorid;
        u_int32_t			expire;
        u_int8_t			timeout;
        u_int8_t			_pad[3];
    } __packed;

    See FreeBSD sources sys/net/if_pfsync.h

    """
    unpack_format = "!Q "

    @classmethod
    def get_unpack_format(cls):
        """
        Brace yourselves, long dirty string is coming.

        Unpacking of structs is done as a string with the size of the
        struct and will be unpacked again in __init__

        Tabs are replaced with their size * their type (ex: int a[2] ->
        'ii') and will be repacked in tuples in __init__
        This does not stand for ifname

        The pf_addr struct (which is in fact an union containing the
        128bits ip address) is extracted as 4 32 bits unsigned int which
        will be our preferred form

        """
        from struct import calcsize

        unpack_format = '!Q'
        unpack_format += '%(state_peer_size)ds%(state_peer_size)ds' % {
            'state_peer_size': calcsize('%dsIIIHHBB6B' % calcsize('HBBI')),  # to fix
        }
        unpack_format += 'IIB 3B'
        return unpack_format

    def __init__(self, id, src, dst, creator_id, expire, timeout, pad1, pad2, pad3):
        self.id = id
        self.creator = creator_id
        self.dst = dst
        self.src = src
        self.expire = expire
        self.timeout = timeout

    def __str__(self):
        return "Compressed update state on %s (created by %d)" % (self.id, self.creator)
