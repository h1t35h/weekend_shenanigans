from dataclasses import dataclass
from dns_consts import *
import dataclasses
import struct


@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


def header_to_bytes(header: DNSHeader):
    fields = dataclasses.astuple(header)
    # each H for a field in DNSHeader. The '!' at the start is for big-endian
    # byte order. H signifies 2byte integer.
    return struct.pack("!HHHHHH", *fields)


def question_to_bytes(question: DNSQuestion):
    return question.name + struct.pack("!HH", question.type_ , question.class_)


def encode_dns_name(domain_name: str):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


import random
random.seed(1)

def build_query(domain_name, record_type, flags=1):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    if flags:
        RECURSION_DESIRED = 1 << 8
    else:
        RECURSION_DESIRED = 0
    
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    
    return header_to_bytes(header) + question_to_bytes(question)



