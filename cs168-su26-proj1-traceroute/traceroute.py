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

    def __init__(self, buffer: bytes):
        # 本课程中统一采用大端序进行encode-decode
        # 大端序: 高位字节在前, 低位字节在后; 小端序反之
        # 字节序只会影响跨字节的 编码解析, 不会影响单字节解码

        view = memoryview(buffer)       # 避免切片拷贝

        if len(view) < 20:
            raise ValueError("IPv4 header must be at least 20 bytes")

        first_byte = buffer[0]      # First Byte: Version & IHL
        self.version = first_byte >> 4 # higher 4 bits
        ihl = first_byte & 0x0F     # Internet Header Length, 报头长度, 以 4 byte为一个单位
        self.header_len = 4 * ihl   # 转为 byte 单位

        if self.header_len < 20 or len(view) < self.header_len:
            raise ValueError("Invalid IHL or truncated IPv4 header")

        second_byte = buffer[1]     # Second Byte: DSCP & ECN
        dscp = second_byte >> 2     # higher 6 bits, DSCP（Differentiated Services Code Point，差分服务代码点）
        ecn = second_byte & 0x03    # ECN（Explicit Congestion Notification，显式拥塞通知）
        self.tos = (dscp << 2) | ecn    # 此 Class 中没有分开定义两者, 为了匹配 Class, 所以再将二者拼起来

        total_length_bytes = view[2:4]  # 整个 IP 包理论字节数
        self.length = int.from_bytes(total_length_bytes, 'big')      # 将字节表示转为具体的int数字

        id_bytes = view[4:6]        # 分片重组标识
        self.id = int.from_bytes(id_bytes, 'big')

        flags_frag = int.from_bytes(view[6:8], 'big')
        self.flags = flags_frag >> 13       # 高3位, 控制数据包是否允许分片，以及标识当前分片是否为最后一个分片
        self.frag_offset = flags_frag & 0x1FFF      # 后13位, 指明当前分片所携带的数据（有效载荷）
        # 实际字节偏移量: offset * 8

        self.ttl = buffer[8]        # TTL

        self.proto = buffer[9]      # Protocol

        self.cksum = int.from_bytes(view[10:12], 'big') # header checksum

        self.src = '.'.join(map(str, view[12:16]))  # source

        self.dst = '.'.join(map(str, view[16:20]))    # destination



    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
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

    def __init__(self, buffer: bytes):
        self.type = buffer[0]   # 消息类型, 如11为TTL结束, 3为unreachable
        self.code = buffer[1]   # 具体子原因；如 Type=11 且 Code=0 表示传输途中 TTL 超时，Type=3 且 Code=3 表示目的端口不可达

        view = memoryview(buffer)
        self.cksum = int.from_bytes(view[2:4], 'big')  # 覆盖整个 ICMP 报文（含头部与载荷）的 16 位反码和校验

        rest_of_header = int.from_bytes(view[4:8], 'big') # Rest of Header / Unused


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

    def __init__(self, buffer: bytes):
        view = memoryview(buffer)

        self.src_port = int.from_bytes(view[:2], 'big')     # 发送端端口
        self.dst_port = int.from_bytes(view[2:4], 'big')    # 接收端端口
        self.len = int.from_bytes(view[4:6], 'big')         # UDP 首部 + 数据的总字节数
        self.cksum = int.from_bytes(view[6:8], 'big')        # checksum

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

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
    payload = b"Potato"

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        routers_this_ttl = []

        # 多次尝试
        sendsock.set_ttl(ttl)
        for _ in range(PROBE_ATTEMPT_COUNT):
            #   send
            probe_port = TRACEROUTE_PORT_NUMBER + probe_id
            sendsock.sendto(payload, (ip, probe_port))
            probe_id += 1

            # 判断有无返回信号
            if not recvsock.recv_select():
                continue

            # 得到对应返回的字节串
            buf, _ = recvsock.recvfrom()

            # 长度不足IPv4首部最短长度, 可能是截断包或异常短包，直接 IPv4(buf) 会越界报错，直接丢弃并继续下一轮尝试。
            if len(buf) < 20:
                continue

            # 得到外部 IPv4 字段
            outer_ip = IPv4(buf)

            # 校验 IPv4 载荷合法性: fragment offset 若不为0, 则代表本块不是首片分片, 不可能包含完整ip信息
            if (outer_ip.version != 4 or
                outer_ip.header_len < 20 or
                outer_ip.header_len > len(buf) or
                outer_ip.frag_offset > 0
                ):      continue

            icmp_offset = outer_ip.header_len       # icmp 偏移量, 对应于IPv4header长度

            # 外层 IPv4 的上层协议不是 ICMP（协议号不为 1），
            # 或者剩余字节数不足以容纳一个完整的 8 字节 ICMP 首部 + 20 字节 内部IPv4 协议
            if outer_ip.proto != 1 or len(buf) < icmp_offset + 8 + 20:
                continue

            icmp = ICMP(buf[icmp_offset:])

            inner_ip_offset = icmp_offset + 8       # 固定长度, icmp偏移量 + 8

            # 检查内层ip合法性
            if len(buf) < inner_ip_offset + 20:
                continue
            inner_ip = IPv4(buf[inner_ip_offset:])  

            # 内层 ipv4 合法性
            if (
                    inner_ip.version != 4
                    or inner_ip.header_len < 20
                    or inner_ip.frag_offset > 0
                ):
                    continue

            inner_udp_offset = inner_ip_offset + inner_ip.header_len

            # 检查协议, 以及字节串长度, 协议为 17 代表内嵌协议为UDP
            if inner_ip.proto != 17 or len(buf) < inner_udp_offset + 8:
                continue

            inner_udp = UDP(buf[inner_udp_offset:])

            # 确认这条 ICMP 报错是由我们发往目标 IP / 探测端口的 UDP 包触发的
            if inner_ip.dst != ip or inner_udp.dst_port != probe_port:
                continue

            # Type 11 (Time Exceeded) 超时, code == 0, 传输中超时；
            # Type 3, Code 3 (Port Unreachable) 表示到达目标主机
            # 这是 UDP 常用的判定组合, 其余type不是 traceroute 探测期待的响应
            if icmp.type == 11 and icmp.code == 0:
                if outer_ip.src not in routers_this_ttl:
                    routers_this_ttl.append(outer_ip.src)
            elif icmp.type == 3 and icmp.code == 3:
                if outer_ip.src not in routers_this_ttl:
                    routers_this_ttl.append(outer_ip.src)

                # 确定这个 不可达(type3 + code3) 的字段来自目标ip
                if outer_ip.src == ip:
                    reached = True

        if reached:
            # 如果到达目标地址, 就应只包含目标地址ip
            routers_this_ttl = [ip]

        util.print_result(routers_this_ttl, ttl)
        result.append(routers_this_ttl)
        print(
            f"[DEBUG] TTL={ttl}, "
            f"expected_port={probe_port}, "
            f"router={outer_ip.src}, "
            f"ICMP={icmp.type}/{icmp.code}, "
            f"inner_dst={inner_ip.dst}, "
            f"received_port={inner_udp.dst_port}"
        )

        if reached:
            break

    return result




if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
