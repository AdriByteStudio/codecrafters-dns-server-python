import socket
import struct
import sys


def encode_domain_name(domain):
    parts = domain.split(".")
    encoded = b"".join(
        struct.pack("B", len(part)) + part.encode() for part in parts
    )
    return encoded + b"\x00"


def decode_domain_name(buf, offset):
    labels = []
    while True:
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", buf[offset:offset + 2])[0] & 0x3FFF
            part, _ = decode_domain_name(buf, pointer)
            labels.append(part)
            offset += 2
            return ".".join(labels), offset
        offset += 1
        if length == 0:
            break
        labels.append(buf[offset:offset + length].decode())
        offset += length
    return ".".join(labels), offset


def parse_question(buf, offset):
    domain, offset = decode_domain_name(buf, offset)
    qtype, qclass = struct.unpack(">HH", buf[offset:offset + 4])
    offset += 4
    return domain, qtype, qclass, offset


def build_question(domain, qtype=1, qclass=1):
    return encode_domain_name(domain) + struct.pack(">HH", qtype, qclass)


def build_answer(domain, ip, qtype=1, qclass=1, ttl=60):
    rdata = socket.inet_aton(ip)
    return (
        encode_domain_name(domain)
        + struct.pack(">HHIH", qtype, qclass, ttl, len(rdata))
        + rdata
    )


def parse_answer(buf, offset):
    domain, offset = decode_domain_name(buf, offset)
    qtype, qclass, ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
    offset += 10
    rdata = buf[offset:offset + rdlength]
    offset += rdlength
    return domain, qtype, qclass, ttl, rdata, offset


def build_query_packet(query_id, domain, qtype=1, qclass=1):
    header = struct.pack(">HHHHHH", query_id, 0, 1, 0, 0, 0)
    return header + build_question(domain, qtype, qclass)


def resolve_answer(resolver_addr, query_id, domain, qtype, qclass):
    query = build_query_packet(query_id, domain, qtype, qclass)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query, resolver_addr)
        data, _ = sock.recvfrom(512)
    finally:
        sock.close()

    _, _, _, offset = parse_question(data, 12)
    _, _, _, ttl, rdata, _ = parse_answer(data, offset)
    ip = socket.inet_ntoa(rdata)
    return build_answer(domain, ip, qtype, qclass, ttl)


def parse_header(buf):
    packet_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", buf[:12]
    )
    opcode = (flags >> 11) & 0x0F
    rd = (flags >> 8) & 0x01
    return {
        "id": packet_id,
        "opcode": opcode,
        "rd": rd,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


def build_header(request, qdcount=0, ancount=0, nscount=0, arcount=0):
    packet_id = request["id"]
    qr = 1
    opcode = request["opcode"]
    aa = 0
    tc = 0
    rd = request["rd"]
    ra = 0
    z = 0
    rcode = 0 if opcode == 0 else 4

    flags = (
        (qr << 15)
        | (opcode << 11)
        | (aa << 10)
        | (tc << 9)
        | (rd << 8)
        | (ra << 7)
        | (z << 4)
        | rcode
    )

    return struct.pack(
        ">HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount
    )


def build_response(buf, resolver_addr=None):
    request = parse_header(buf)
    offset = 12
    questions = []
    for _ in range(request["qdcount"]):
        domain, qtype, qclass, offset = parse_question(buf, offset)
        questions.append((domain, qtype, qclass))

    question_bytes = b"".join(
        build_question(domain, qtype, qclass) for domain, qtype, qclass in questions
    )
    if resolver_addr:
        answer_bytes = b"".join(
            resolve_answer(resolver_addr, request["id"], domain, qtype, qclass)
            for domain, qtype, qclass in questions
        )
    else:
        answer_bytes = b"".join(
            build_answer(domain, "8.8.8.8", qtype, qclass)
            for domain, qtype, qclass in questions
        )
    header = build_header(
        request, qdcount=len(questions), ancount=len(questions)
    )
    return header + question_bytes + answer_bytes


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    resolver_addr = None
    if "--resolver" in sys.argv:
        address = sys.argv[sys.argv.index("--resolver") + 1]
        ip, port = address.rsplit(":", 1)
        resolver_addr = (ip, int(port))

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
         try:
             buf, source = udp_socket.recvfrom(512)

             response = build_response(buf, resolver_addr)

             udp_socket.sendto(response, source)
         except Exception as e:
             print(f"Error receiving data: {e}")
             break


if __name__ == "__main__":
    main()
