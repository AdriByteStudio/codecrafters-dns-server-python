import socket
import struct


def encode_domain_name(domain):
    parts = domain.split(".")
    encoded = b"".join(
        struct.pack("B", len(part)) + part.encode() for part in parts
    )
    return encoded + b"\x00"


def build_question(domain, qtype=1, qclass=1):
    return encode_domain_name(domain) + struct.pack(">HH", qtype, qclass)


def build_answer(domain, ip, qtype=1, qclass=1, ttl=60):
    rdata = socket.inet_aton(ip)
    return (
        encode_domain_name(domain)
        + struct.pack(">HHIH", qtype, qclass, ttl, len(rdata))
        + rdata
    )


def build_header(qdcount=0, ancount=0, nscount=0, arcount=0):
    packet_id = 1234
    qr = 1
    opcode = 0
    aa = 0
    tc = 0
    rd = 0
    ra = 0
    z = 0
    rcode = 0

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


def build_response():
    question = build_question("codecrafters.io")
    answer = build_answer("codecrafters.io", "8.8.8.8")
    header = build_header(qdcount=1, ancount=1)
    return header + question + answer


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
         try:
             buf, source = udp_socket.recvfrom(512)

             response = build_response()

             udp_socket.sendto(response, source)
         except Exception as e:
             print(f"Error receiving data: {e}")
             break


if __name__ == "__main__":
    main()
