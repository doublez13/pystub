#!/usr/bin/python3
#Python implementation of RFC 1035 just for fun
#https://tools.ietf.org/html/rfc1035
#
#Status: Work in Progress

import socket
import random
import sys

qtypes = {'A'    :  1,
          'NS'   :  2,
          'MD'   :  3,
          'MF'   :  4,
          'CNAME':  5,
          'SOA'  :  6,
          'MB'   :  7,
          'MG'   :  8,
          'MR'   :  9,
          'NULL' : 10,
          'WKS'  : 11,
          'PTR'  : 12,
          'HINFO': 13,
          'MINFO': 14,
          'MX'   : 15,
          'TXT'  : 16,
          'AAAA' : 28}

qclasses = {'IN': 1}

def gen_packet(header, query):
    return header + query

def gen_header(trans_id, flags, QDCount, ANCount, NSCount, ARCount):
    QDCount = QDCount.to_bytes(2, byteorder='big')
    ANCount = ANCount.to_bytes(2, byteorder='big')
    NSCount = NSCount.to_bytes(2, byteorder='big')
    ARCount = ARCount.to_bytes(2, byteorder='big')
    return trans_id + flags + QDCount + ANCount + NSCount + ARCount

def gen_header_std_query():
    return gen_header(gen_trans_id(), gen_flags_std_query(), 1, 0, 0, 0)

def gen_flags(QR, OpCode, AA, TC, RD, RA, Z, RCode):
    flags = QR*(2**15) | OpCode*(2**11) | AA*(2**10)| TC*(2**9) | RD*(2**8) | RA*(2**7) | Z*(2**4) | RCode
    return flags.to_bytes(2, byteorder='big')

def gen_flags_std_query():
    return gen_flags(0, 0, 0, 0, 1, 0, 0, 0)

def parse_flags(flags):
    QR      = (flags >> 15) & 2**1-1
    OpCode  = (flags >> 11) & 2**4-1
    AA      = (flags >> 10) & 2**1-1
    TC      = (flags >>  9) & 2**1-1
    RD      = (flags >>  8) & 2**1-1
    RA      = (flags >>  7) & 2**1-1
    Z       = (flags >>  3) & 2**3-1
    RCode   = (flags >>  0) & 2**4-1
    return (QR, OpCode, AA, TC, RD, RA, Z, RCode)

def gen_name(qname):
    if len(qname) > 253:
        return null
    dns_name = str.encode('')
    parts = qname.split('.')
    for part in parts:
        if len(part) > 63:
            return null
        dns_name += str.encode(chr(len(part))+part)
    dns_name += str.encode(chr(0))
    return dns_name

def gen_ptr(qname):
    parts = qname.split('.')
    ptr = parts[3]+'.'+parts[2]+'.'+parts[1]+'.'+parts[0]+".in-addr.arpa"
    return gen_name(ptr)

def parse_name(start, packet):
    name_str = ''
    i = start
    while packet[i] > 0:
        if(packet[i] >= 0xc0):
            if debug: print("Compressed name received. Following reference")
            offset = int.from_bytes(packet[i:i+2], 'big') & 2**14-1
            name_str += parse_name(offset, packet)
            return name_str
        count = packet[i]
        name_str += packet[i+1:i+count+1].decode("ascii")
        name_str += '.'
        i+=count+1
    name_str = name_str[:-1]
    return name_str

def skip_name(start, data):
    while data[start] > 0:
        if data[start] == 0xc0:
            start += 1
            break
        start += 1
    return start + 1

def gen_question(qname, qtype, qclass):
    if qtype == 'PTR':
        query = gen_ptr(qname)
    elif qtype in qtypes.keys():
        query = gen_name(qname)
    else:
        print("Support not implmented for record type: " + qtype)
        sys.exit(1)
    query += qtypes[qtype].to_bytes(2, byteorder='big')
    query += qclasses[qclass].to_bytes(2, byteorder='big')
    return query

def parse_question(question):
    qname  = parse_name(0, question)
    qtype  = int.from_bytes(question[-4:-2], 'big')
    qclass = int.from_bytes(question[-2:0], 'big')
    return (qname, qtype, qclass)

def gen_trans_id():
    return random.randrange(2**16-1).to_bytes(2, byteorder='big')

def parse_rdata(qtype, start, data):
    rdata = {}
    if qtype == qtypes['A']:
        if debug: print("Parsing A record")
        rdata['ADDRESS'] = str(data[start])+'.'+str(data[start+1])+'.'+str(data[start+2])+'.'+str(data[start+3])
    elif qtype == qtypes['NS']:
        if debug: print("Parsing NS record")
        rdata['NSDNAME'] = parse_name(start, data)
    elif qtype == qtypes['CNAME']:
        if debug: print("Parsing CNAME record")
        rdata['CNAME'] =  parse_name(start, data)
    elif qtype == qtypes['SOA']:
        if debug: print("Parsing SOA record")
        rdata['MNAME']  = parse_name(start, data)
        start = skip_name(start, data)
        rdata['RNAME']  = parse_name(start, data)
        start = skip_name(start, data)
        rdata['SERIAL']  = int.from_bytes(data[start:start+4], 'big')
        rdata['REFRESH'] = int.from_bytes(data[start+4:start+8], 'big')
        rdata['RETRY']   = int.from_bytes(data[start+8:start+12], 'big')
        rdata['EXPIRE']  = int.from_bytes(data[start+12:start+16], 'big')
        rdata['MINIMUM'] = int.from_bytes(data[start+20:start+24], 'big')
    elif qtype == qtypes['PTR']:
        if debug: print("Parsing PTR record");
        rdata['PTRDNAME'] = parse_name(start, data)
    elif qtype == qtypes['MX']:
        if debug: print("Parsing MX record");
        rdata['PREFERENCE'] = int.from_bytes(data[start:start+2], 'big')
        rdata['EXCHANGE']   = parse_name(start+2, data)
    elif qtype == qtypes['TXT']:
        if debug: print("Parsing TXT record");
        length = int.from_bytes(data[start-2:start], 'big')
        curr_size = 0
        rdata['TXT-DATA'] = []
        while curr_size < length and data[start+curr_size]:
            size = data[start+curr_size]
            rdata['TXT-DATA'].append(data[start+curr_size+1:start+curr_size+1+size].decode("ascii"))
            curr_size += (1+size)
    elif qtype == qtypes['AAAA']:
        if debug: print("Parsing AAAA record");
        AAAA = ''
        for i in range(8): AAAA += (str(data[start+2*i:start+2*i+2].hex())+':')
        rdata['AAAA_ADDRESS'] = AAAA[:-1]
    else:
        if debug: print("Parsing not implmented for record type: " + str(qtype))
        rdata['ERROR'] = "Parsing not implmented for record type: " + str(qtype)
    return rdata

def parse_packet(packet):
    if(tcp):
        length = int.from_bytes(packet[:2], 'big')
        packet = packet[2:]
    header = packet[:12]
    
    #parse header
    trans_id = int.from_bytes(header[:2], 'big')
    flags    = int.from_bytes(header[2:4], 'big')
    QDCount  = int.from_bytes(header[4:6], 'big')   #Number of questions
    ANCount  = int.from_bytes(header[6:8], 'big')   #Number of answers
    NSCount  = int.from_bytes(header[8:10], 'big')  #Number of NS RRs
    ARCount  = int.from_bytes(header[10:12], 'big') #Number of add RRS

    flags = parse_flags(flags)
    if(flags[0] == 0): #QR
        print("QR code indicates a question, not a response. Aborting...")
        sys.exit(1);

    pos = 12
    if(QDCount):
        if debug: print("Response contains query section. Parsing...")
        question_end = pos
        while packet[question_end] > 0:
          question_end += 1
        question_end += 5
        quest        = packet[pos:question_end]
        quest_parsed = parse_question(quest)
        pos          = question_end
        if debug: print()
    for section in ('Answers', 'Auth NS', "Additional"):
        if section == 'Answers':
            count = ANCount
        elif section == "Auth NS":
            count = NSCount
        elif section == "Additional":
            count = ARCount
        if count and debug: print("Response contains " + section + " section. Parsing...")
        for i in range(count):
            end      = pos
            end      = skip_name(end, packet)
            qname    = parse_name(pos, packet)
            qtype    = int.from_bytes(packet[end:end+2], 'big')
            qclass   = int.from_bytes(packet[end+2:end+4], 'big')
            ttl      = int.from_bytes(packet[end+4:end+8], 'big')
            RDlength = int.from_bytes(packet[end+8:end+10], 'big')
            end += 10
            RData = parse_rdata(qtype, end, packet)
            RData['QNAME']  = qname
            RData['QTYPE']  = qtype
            RData['QCLASS'] = qclass
            RData['TTL']    = ttl
            print(RData)
            end += RDlength
            pos = end
        if count and debug: print()

######QUERY SETTINGS######
#FLAGS
QR        = 0 #Query: 0, Response: 1
OpCode    = 0 #Standard Query: 0000, Inverse Query: 0100
AA        = 0 #Authoritative Answer
TC        = 0 #Is Message truncated
RD        = 1 #Do query recursively
RA        = 0 #Is recursive support available in the NS
Z         = 0 #Reserved
RCode     = 0 #Response Code

#COUNTS
QDCount   = 1 
ANCount   = 0
NSCount   = 0
ARCount   = 0

#QUERY
qname     = 'www.google.com'
qtype     = 'AAAA'
qclass    = 'IN'

#MISC
server    = '155.98.110.17'
port      = 53
tcp       = 0
debug     = 0
##########################

sock_type = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
conn = socket.socket(socket.AF_INET, sock_type)
conn.connect((server, port))

trans_id = gen_trans_id()
flags    = gen_flags(QR, OpCode, AA, TC, RD, RA, Z, RCode)
header   = gen_header(trans_id, flags, QDCount, ANCount, NSCount, ARCount)
#header    = gen_header_std_query()
query    = gen_question(qname, qtype, qclass)
packet   = gen_packet(header, query)
if not tcp and len(packet) > 512:
    print("Packet length too large for UDP, Sending as TCP...")
    tcp = 1
if tcp:
    packet_len = len(packet).to_bytes(2, byteorder='big')
    packet = packet_len + packet

conn.sendall(packet)
packet= conn.recv(4096)
parse_packet(packet)
