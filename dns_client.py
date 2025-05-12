#!/usr/bin/env python3

import sys
import socket
import struct
import random

DNS_PORT = 53

# Extended type codes with AAAA (28)
TYPE_CODES = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'PTR': 12,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,  # Added for IPv6
}

def get_type_code(name: str) -> int:
    """Return the numeric type code for a textual DNS record type (default to A=1 if unknown)."""
    return TYPE_CODES.get(name.upper(), 1)

def encode_dns_name(name: str) -> bytes:
    """
    Encode a domain name (e.g., 'www.example.com') into the label format required by RFC 1035:
       3www7example3com0
    """
    parts = name.strip('.').split('.')
    output = b''
    for p in parts:
        if len(p) > 63:
            raise ValueError("Label too long (max 63 bytes).")
        output += struct.pack('!B', len(p)) + p.encode('ascii', errors='replace')
    return output + b'\x00'

def build_dns_query(qname: str, qtype: int) -> bytes:
    """
    Build a minimal DNS query packet (header + one question).
    RFC 1035: The header is 12 bytes, question follows.
    """
    # Transaction ID: random 16-bit
    tx_id = random.getrandbits(16)

    # Flags:
    #   QR=0 (query), Opcode=0 (standard), AA=0, TC=0, RD=1 (recursion desired),
    #   RA=0 (set by server), Z=0, RCODE=0 => 0x0100
    flags = 0x0100

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(
        "!HHHHHH",
        tx_id,       # ID
        flags,       # Flags
        qdcount,     # QDCOUNT
        ancount,     # ANCOUNT
        nscount,     # NSCOUNT
        arcount      # ARCOUNT
    )
    # Question Section: QNAME + QTYPE + QCLASS(IN=1)
    question = encode_dns_name(qname)
    qtype_bytes = struct.pack("!H", qtype)
    qclass_bytes = struct.pack("!H", 1)  # IN class

    return header + question + qtype_bytes + qclass_bytes

def parse_dns_response(data: bytes, expected_id: int):
    """
    Parse the DNS response per RFC 1035. Return a dict with:
      {
        'header': { ... },
        'questions': [ { qname, qtype, qclass } ],
        'answers': [ { name, type, class, ttl, rdata } ],
        'authority': [ ... ],
        'additional': [ ... ],
        'truncated': bool
      }
    Raises ValueError if the response is malformed or doesn't match expected_id.
    """
    if len(data) < 12:
        raise ValueError("DNS response too short.")

    # Unpack header
    (rx_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])

    if rx_id != expected_id:
        raise ValueError("Response ID does not match query ID.")

    qr = (flags >> 15) & 0x1  # Must be 1 in a response
    tc = (flags >> 9) & 0x1   # Truncated bit
    rcode = flags & 0xF       # Lower 4 bits

    if qr != 1:
        raise ValueError("Not a response (QR=0).")

    offset = 12
    questions = []
    for _ in range(qdcount):
        offset, qname = decode_dns_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
        offset += 4
        questions.append({
            'qname': qname,
            'qtype': qtype,
            'qclass': qclass
        })

    answers = []
    for _ in range(ancount):
        offset, rr = parse_resource_record(data, offset)
        answers.append(rr)

    authority = []
    for _ in range(nscount):
        offset, rr = parse_resource_record(data, offset)
        authority.append(rr)

    additional = []
    for _ in range(arcount):
        offset, rr = parse_resource_record(data, offset)
        additional.append(rr)

    header_info = {
        'id': rx_id,
        'flags': flags,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'rcode': rcode,
        'tc': tc
    }

    return {
        'header': header_info,
        'questions': questions,
        'answers': answers,
        'authority': authority,
        'additional': additional,
        'truncated': (tc == 1)
    }

def parse_resource_record(data: bytes, offset: int):
    """
    Parse a single Resource Record: NAME + (TYPE, CLASS, TTL, RDLENGTH, RDATA).
    Returns (new_offset, rr_dict).
    """
    offset, name = decode_dns_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata = data[offset:offset+rdlength]
    offset += rdlength

    rr = {
        'name': name,
        'type': rtype,
        'class': rclass,
        'ttl': ttl,
        'rdata': rdata
    }
    return offset, rr

def decode_dns_name(data: bytes, offset: int):
    """
    Decode a domain name at the given offset in `data`, handling compression.
    Returns (new_offset, name_string).
    """
    labels = []
    jumped = False
    jump_offset = 0

    while True:
        if offset >= len(data):
            raise ValueError("Offset beyond data length when decoding name.")

        length = data[offset]
        offset += 1
        if length == 0:
            # End of this name
            break

        # Check for pointer (two high bits = 11)
        if (length & 0xC0) == 0xC0:
            # Next byte + lower 6 bits of length form the pointer
            b2 = data[offset]
            offset += 1
            pointer = ((length & 0x3F) << 8) | b2
            if pointer >= len(data):
                raise ValueError("Invalid pointer offset.")
            if not jumped:
                jump_offset = offset
            jumped = True
            offset = pointer
        else:
            # A normal label
            label = data[offset:offset+length]
            offset += length
            labels.append(label.decode('ascii', errors='replace'))

    name = ".".join(labels)
    if jumped:
        return (jump_offset, name)
    else:
        return (offset, name)

def query_via_udp(qname: str, qtype: int, server_ip: str, timeout=2):

    packet = build_dns_query(qname, qtype)
    tx_id = struct.unpack("!H", packet[:2])[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (server_ip, DNS_PORT))

    data, _ = sock.recvfrom(512)  # 512 bytes max (RFC 1035)
    sock.close()

    return parse_dns_response(data, tx_id)

def query_via_tcp(qname: str, qtype: int, server_ip: str, timeout=5):

    packet = build_dns_query(qname, qtype)
    tx_id = struct.unpack("!H", packet[:2])[0]

    # Prepend length to the packet
    tcp_query = struct.pack("!H", len(packet)) + packet

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((server_ip, DNS_PORT))
    s.sendall(tcp_query)

    length_data = s.recv(2)
    if len(length_data) < 2:
        s.close()
        raise ValueError("No length data from TCP response.")
    msg_len = struct.unpack("!H", length_data)[0]

    response_data = b''
    while len(response_data) < msg_len:
        chunk = s.recv(msg_len - len(response_data))
        if not chunk:
            break
        response_data += chunk

    s.close()
    if len(response_data) != msg_len:
        raise ValueError("Incomplete TCP DNS response.")

    return parse_dns_response(response_data, tx_id)

def resolve(qname: str, rtype_str='A', server_ip='8.8.8.8'):

    qtype = get_type_code(rtype_str)


    resp = query_via_udp(qname, qtype, server_ip)
    if resp['truncated']:

        resp = query_via_tcp(qname, qtype, server_ip)


    rcode = resp['header']['rcode']
    if rcode != 0:
        raise RuntimeError(f"DNS error, RCODE={rcode}")

    return resp

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [rtype=A] [dns_server=8.8.8.8]")
        sys.exit(1)

    domain = sys.argv[1]
    rtype = sys.argv[2] if len(sys.argv) > 2 else 'A'
    dns_server = sys.argv[3] if len(sys.argv) > 3 else '8.8.8.8'

    try:
        response = resolve(domain, rtype, dns_server)
    except Exception as e:
        print(f"Resolution failed: {e}")
        sys.exit(1)

    header = response['header']
    answers = response['answers']

    print(f"--- Response from {dns_server} ---")
    print(f"TX_ID={header['id']}, RCODE={header['rcode']}, Truncated={header['tc']}")
    print(f"Questions={header['qdcount']}, Answers={header['ancount']}, Auth={header['nscount']}, Addl={header['arcount']}\n")


    for rr in answers:
        name_ = rr['name']
        rtype_ = rr['type']
        ttl_ = rr['ttl']
        rdata_ = rr['rdata']

        if rtype_ == 1:  # A
            ip = socket.inet_ntoa(rdata_)
            print(f"{name_} A {ip} TTL={ttl_}")
        elif rtype_ == 28:  # AAAA
            # IPv6 address
            ip6 = socket.inet_ntop(socket.AF_INET6, rdata_)
            print(f"{name_} AAAA {ip6} TTL={ttl_}")
        elif rtype_ == 2:  # NS
            _, nsname = decode_dns_name(b'\x00' + rdata_, 1)
            print(f"{name_} NS {nsname} TTL={ttl_}")
        elif rtype_ == 5:  # CNAME
            _, cname = decode_dns_name(b'\x00' + rdata_, 1)
            print(f"{name_} CNAME {cname} TTL={ttl_}")
        elif rtype_ == 12:  # PTR
            _, ptr = decode_dns_name(b'\x00' + rdata_, 1)
            print(f"{name_} PTR {ptr} TTL={ttl_}")
        elif rtype_ == 15:  # MX
            pref = struct.unpack("!H", rdata_[:2])[0]
            _, exch = decode_dns_name(b'\x00' + rdata_[2:], 1)
            print(f"{name_} MX {exch} pref={pref} TTL={ttl_}")
        elif rtype_ == 16:  # TXT
            txts = []
            i = 0
            while i < len(rdata_):
                ln = rdata_[i]
                i += 1
                txts.append(rdata_[i:i + ln].decode(errors='replace'))
                i += ln
            print(f"{name_} TXT {' '.join(txts)} TTL={ttl_}")
        elif rtype_ == 6:  # SOA (minimal)
            off, mname = decode_dns_name(b'\x00' + rdata_, 1)
            off, rname = decode_dns_name(b'\x00' + rdata_, off)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", rdata_[off:off + 20])
            print(f"{name_} SOA {mname} {rname} serial={serial} TTL={ttl_}")
        else:
            print(f"{name_} TYPE={rtype_} [len={len(rdata_)}] TTL={ttl_}")


if __name__ == "__main__":
    main()
