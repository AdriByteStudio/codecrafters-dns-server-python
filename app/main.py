import socket
import struct


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


def build_response(buf):
    request = parse_header(buf)
    offset = 12
    domains = []
    for _ in range(request["qdcount"]):
        domain, _, _, offset = parse_question(buf, offset)
        domains.append(domain)

    questions = b"".join(build_question(domain) for domain in domains)
    answers = b"".join(build_answer(domain, "8.8.8.8") for domain in domains)
    header = build_header(
        request, qdcount=len(domains), ancount=len(domains)
    )
    return header + questions + answers


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
         try:
             buf, source = udp_socket.recvfrom(512)

             response = build_response(buf)

             udp_socket.sendto(response, source)
         except Exception as e:
             print(f"Error receiving data: {e}")
             break


if __name__ == "__main__":
    main()
