from query import build_query, DNSQuestion, DNSHeader
from dns_consts import *
from dataclasses import dataclass
from io import BytesIO
from typing import List
import struct

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def parse_header(reader):
    # essentially a mirror of header_to_byte
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def decode_name_simple(reader):
    """
    Doesn't really work in real life because of DNS compression
     RFC 1035, section 4.1.4
    """
    parts = []
    while(length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def parse_question(reader):
    name = decode_name_simple(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)

def parse_record(reader):
    name = decode_name(reader)
    # the type, class, TTL, and data length together are 10 bytes 
    # ( 2 + 2 + 4 + 2)
    data = reader.read(10)
    #HHIH means 2-byte int, 2-byte int, 4-byte int, 2-byte int
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data =reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)

    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]
    
    return DNSPacket(header, questions, answers, authorities, additionals)


def ip_to_string(ip):
    """ Translates bytes to string for ips
    """
    return ".".join([str(x) for x in ip])


import socket
def main():
    query = build_query("www.example.com", 1)
    
    # create a UDP socket
    # `socket.AF_INET` means that we're connecting to the internet
    #                  (as opposed to a Unix domain socket `AF_UNIX` for example)
    # `socket.SOCK_DGRAM` means "UDP"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # send query to 8.8.8.8, port 54 -> default DNS port
    sock.sendto(query, ("8.8.8.8", 53))
    
    response, _ = sock.recvfrom(1024)
    
    packet = parse_dns_packet(response)
    print(ip_to_string(packet.answers[0].data))


if __name__ == "__main__":
    main()
