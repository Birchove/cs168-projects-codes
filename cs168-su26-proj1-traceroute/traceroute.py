import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 40

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

ICMP_TIME_EXCEEDED = (11, 0)
ICMP_PORT_UNREACHABLE = (3, 3)
TRACEROUTE_PAYLOAD = b"Potato"

# 避免达到65536端口, 采用取模运算
PROBE_PORT_RANGE = 65536 - TRACEROUTE_PORT_NUMBER


class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes | memoryview):
        # 本课程中统一采用大端序进行encode-decode
        # 大端序: 高位字节在前, 低位字节在后; 小端序反之
        # 字节序只会影响跨字节的 编码解析, 不会影响单字节解码

        view = memoryview(buffer)       # 避免切片拷贝

        if len(view) < 20:
            raise ValueError("IPv4 header must be at least 20 bytes")

        first_byte = view[0]      # First Byte: Version & IHL
        self.version = first_byte >> 4 # higher 4 bits
        ihl = first_byte & 0x0F     # Internet Header Length, 报头长度, 以 4 byte为一个单位
        self.header_len = 4 * ihl   # 转为 byte 单位

        if self.version != 4:
            raise ValueError("Invalid IPv4 version")

        if self.header_len < 20 or len(view) < self.header_len:
            raise ValueError("Invalid IHL or truncated IPv4 header")

        second_byte = view[1]     # Second Byte: DSCP & ECN
        _dscp = second_byte >> 2     # higher 6 bits, DSCP（Differentiated Services Code Point，差分服务代码点）
        _ecn = second_byte & 0x03    # ECN（Explicit Congestion Notification，显式拥塞通知）
        self.tos = second_byte    # 此 Class 中没有分开定义两者, 为了匹配 Class, 所以再将二者拼起来

        total_length_bytes = view[2:4]  # 整个 IP 包理论字节数
        self.length = int.from_bytes(total_length_bytes, 'big')      # 将字节表示转为具体的int数字

        if self.length < self.header_len:
            raise ValueError("Invalid IPv4 total length")

        id_bytes = view[4:6]        # 分片重组标识
        self.id = int.from_bytes(id_bytes, 'big')

        flags_frag = int.from_bytes(view[6:8], 'big')
        self.flags = flags_frag >> 13       # 高3位, 控制数据包是否允许分片，以及标识当前分片是否为最后一个分片
        self.frag_offset = flags_frag & 0x1FFF      # 后13位, 指明当前分片所携带的数据（有效载荷）
        # 实际字节偏移量: offset * 8

        self.ttl = view[8]        # TTL

        self.proto = view[9]      # Protocol

        self.cksum = int.from_bytes(view[10:12], 'big') # header checksum

        self.src = '.'.join(map(str, view[12:16]))  # source

        self.dst = '.'.join(map(str, view[16:20]))    # destination



    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"offset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes | memoryview):
        view = memoryview(buffer)

        if len(view) < 8:
            raise ValueError("ICMP header must be at least 8 bytes")
        
        self.type = view[0]   # 消息类型, 如11为TTL结束, 3为unreachable
        self.code = view[1]   # 具体子原因；如 Type=11 且 Code=0 表示传输途中 TTL 超时，Type=3 且 Code=3 表示目的端口不可达

        self.cksum = int.from_bytes(view[2:4], 'big')  # 覆盖整个 ICMP 报文（含头部与载荷）的 16 位反码和校验

        _rest_of_header = int.from_bytes(view[4:8], 'big') # Rest of Header / Unused


    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes | memoryview):
        view = memoryview(buffer)

        if len(view) < 8:
            raise ValueError("UDP header must be at least 8 bytes")

        self.src_port = int.from_bytes(view[:2], 'big')     # 发送端端口
        self.dst_port = int.from_bytes(view[2:4], 'big')    # 接收端端口
        self.len = int.from_bytes(view[4:6], 'big')         # UDP 首部 + 数据的总字节数
        self.cksum = int.from_bytes(view[6:8], 'big')        # checksum

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

# Helper1: 通用的 IPv4 解析函数
def parse_ipv4_header(buffer: bytes | memoryview, offset: int, protocol: int | None = None) -> IPv4 | None:
    view = memoryview(buffer)

    # 数据本身的合法性
    if offset < 0 or offset >= len(view):
        return None

    ################## IPv4 Header 结构合法性 ###################

    # 利用构造函数排除不符合要求的情况, 是结构性的解析失败:
    # 1. 长度不够20; 2. header-length >= 20 , header-length >= len(view)
    # 3. version; 4. total length
    try:
        packet = IPv4(view[offset:])
    except ValueError:
        return None

    # 补充特异场景下的需求
    # 1. check the protocol
    if protocol is not None and protocol != packet.proto:
        return None

    return packet
    

def parse_icmp(buffer: bytes | memoryview, offset: int) -> ICMP | None:
    view = memoryview(buffer)
    if offset < 0 or offset >= len(view):
        return None
    try:
        packet = ICMP(view[offset:])
    except ValueError:
        return None
    
    return packet

def parse_udp(buffer: bytes | memoryview, offset: int) -> UDP | None:
    view = memoryview(buffer)
    if offset < 0 or offset >= len(view):
        return None
    try:
        packet = UDP(view[offset:])
    except ValueError:
        return None
    return packet

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    result = []
    reached = False
    probe_id = 0        # 具体到每次探测, 每次probe使用独立端口
    payload = TRACEROUTE_PAYLOAD

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        # 去除重复探测
        routers_this_ttl = set()

        # 多次尝试
        sendsock.set_ttl(ttl)
        for _ in range(PROBE_ATTEMPT_COUNT):
            #   send
            probe_port = TRACEROUTE_PORT_NUMBER + probe_id % PROBE_PORT_RANGE   # 取模防止端口用尽
            sendsock.sendto(payload, (ip, probe_port))
            probe_id += 1

            while recvsock.recv_select():
                buf, _ = recvsock.recvfrom()
                # outer ipv4
                outer_ip = parse_ipv4_header(buf, 0, 1)
                if not outer_ip:
                    continue

                # icmp
                icmp_offset = outer_ip.header_len
                icmp = parse_icmp(buf, icmp_offset)
                if not icmp:
                    continue

                # inner ipv4
                inner_ip_offset = icmp_offset + 8
                inner_ip = parse_ipv4_header(buf, inner_ip_offset, 17)
                if not inner_ip:
                    continue

                # inner udp
                inner_udp_offset = inner_ip_offset + inner_ip.header_len
                inner_udp = parse_udp(buf, inner_udp_offset)
                if not inner_udp:
                    continue

                # 不属于当前目的地, 或者不是本次probe返回的结果:
                if inner_ip.dst != ip or inner_udp.dst_port != probe_port:
                    continue

                status = (icmp.type, icmp.code)
                if status == ICMP_TIME_EXCEEDED:
                    routers_this_ttl.add(outer_ip.src)
                    break
                elif status == ICMP_PORT_UNREACHABLE:
                    # 非目标的3, 3: 不加入路由表
                    if outer_ip.src == ip:
                        routers_this_ttl.add(ip)
                        reached = True
                    # 无论是否目标，都结束本次探测等待
                    break
                # 其他 ICMP 类型：continue 继续等待，不 break

            # 避免无意义等待
            if reached:
                break

        routers_this_ttl = list(routers_this_ttl)

        # 如果到达目标主机, 将其移到最后一次响应
        routers_this_ttl = [r for r in routers_this_ttl if r != ip]
        if reached:
            routers_this_ttl.append(ip)

        util.print_result(routers_this_ttl, ttl)
        result.append(routers_this_ttl)

        if reached:
            break

    return result




if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
