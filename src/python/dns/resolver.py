from query import header_to_bytes, question_to_bytes, encode_dns_name, build_query
from response import DNSHeader, DNSQuestion, DNSRecord, DNSPacket
from response import decode_name, parse_header, parse_question, parse_dns_packet
from response import ip_to_string
from dns_consts import *
import socket



def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type, flags=0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))
    
    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)


def get_answer(packet):
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data

def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data

def get_nameserver(packet):
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')

def resolve(domain_name, record_type):
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver , domain_name, record_type)
        
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("Something went wrong..")


def main():
    resolve("twitter.com", TYPE_A)


if __name__ == "__main__":
    main()