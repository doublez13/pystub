#!/usr/local/bin/python3.6
#Python implementation of RFC 1035 just for fun
#https://tools.ietf.org/html/rfc1035
#
#Status: Work in Progress

import socket
import random
import sys
import json

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
          'AAAA' : 28,
          'SRV'  : 33}

qclasses = {'IN': 1}

rcodes= {0: "No Error",
         1: "Format Error",
         2: "Server Failure",
         3: "Non-Existent Domain",
         4: "Not Implemented",
         5: "Query Refused"}

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
    Z       = (flags >>  6) & 2**1-1
    AD      = (flags >>  5) & 2**1-1 #RFC 4035
    CD      = (flags >>  4) & 2**1-1 #RFC 4035
    RCode   = (flags >>  0) & 2**4-1
    return {"QR":QR, "OpCode":OpCode, "AA":AA, "TC":TC, "RD":RD, "RA":RA, "Z":Z, "AD":AD, "CD":CD, "RCode":RCode}

#Find key by value in qtypes and qclasses
def qtype_int_to_name(qint):
  return {v: k for k, v in qtypes.items()}[qint]

def qclass_int_to_name(qint):
  return {v: k for k, v in qclasses.items()}[qint]

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
        if data[start] >= 0xc0:
            return start +2
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

def parse_question(start, data):
    qname  = parse_name(start, data)
    pos    = skip_name(start, data)
    qtype  = int.from_bytes(data[pos:pos+2], 'big')
    qtype  = qtype_int_to_name(qtype)
    qclass = int.from_bytes(data[pos+2:pos+4], 'big')
    qclass = qclass_int_to_name(qclass)
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
        if debug: print("Parsing PTR record")
        rdata['PTRDNAME'] = parse_name(start, data)
    elif qtype == qtypes['MX']:
        if debug: print("Parsing MX record")
        rdata['PREFERENCE'] = int.from_bytes(data[start:start+2], 'big')
        rdata['EXCHANGE']   = parse_name(start+2, data)
    elif qtype == qtypes['TXT']:
        if debug: print("Parsing TXT record")
        length = int.from_bytes(data[start-2:start], 'big')
        curr_size = 0
        rdata['TXT-DATA'] = []
        while curr_size < length and data[start+curr_size]:
            size = data[start+curr_size]
            rdata['TXT-DATA'].append(data[start+curr_size+1:start+curr_size+1+size].decode("ascii"))
            curr_size += (1+size)
    elif qtype == qtypes['AAAA']:
        if debug: print("Parsing AAAA record")
        AAAA = ''
        for i in range(8): AAAA += (str(data[start+2*i:start+2*i+2].hex())+':')
        rdata['AAAA_ADDRESS'] = AAAA[:-1]
    elif qtype == qtypes['SRV']: #RFC 2782
        if debug: print("Parsing SRV record")
        rdata['PRIORITY'] = int.from_bytes(data[start:start+2], 'big')
        rdata['WEIGHT']   = int.from_bytes(data[start+2:start+4], 'big')
        rdata['PORT']     = int.from_bytes(data[start+4:start+6], 'big')
        rdata['TARGET']   = parse_name(start+6, data)
    else:
        print("Parsing not implmented for record type: " + str(qtype))
        rdata['ERROR'] = "Parsing not implmented for record type: " + str(qtype)
    return rdata

def gen_rdata(data):
    rdata = b''
    qtype = data['QTYPE'];
    if qtype == 'A':
        if debug: print("Building A record")
        size   = 4
        add    = data['ADDRESS'].split('.')
        rdata += size.to_bytes(2, byteorder='big')
        for i in range(4):
          rdata += int(add[i]).to_bytes(1, 'big')
    elif qtype == 'NS':
        if debug: print("Building NS record")
        nsdname = data['NSDNAME']
        size    = len(nsdname)
        rdata  += size.to_bytes(2, byteorder='big')
        rdata  += gen_name(nsdname)
    elif qtype == 'CNAME':
        if debug: print("Building CNAME record")
        cname   = data['CNAME']
        size    = len(cname)
        rdata  += size.to_bytes(2, byteorder='big')
        rdata  += gen_name(cname)
    elif qtype == 'SOA':
        if debug: print("Building SOA record")
        size    = len(data['MNAME']) + len(data['RNAME']) + 4*5
        mname   = gen_name(data['MNAME'])
        rname   = gen_name(data['RNAME'])
        serial  = data['SERIAL'].to_bytes(4, byteorder='big')
        refresh = data['REFRESH'].to_bytes(4, byteorder='big')
        retry   = data['RETRY'].to_bytes(4, byteorder='big')
        expire  = data['EXPIRE'].to_bytes(4, byteorder='big')
        minimum = data['MINIMUM'].to_bytes(4, byteorder='big')
        rdata  += size.to_bytes(2, byteorder='big')
        rdata  += mname + rname + serial + refresh + retry + expire + minimum
    elif qtype == 'MX':
        if debug: print("Building MX record")
        size = len(data['EXCHANGE']) + 2
        pref = data['PREFERENCE'].to_bytes(2, byteorder='big')
        exch = gen_name(data['EXCHANGE'])
        rdata  += size.to_bytes(2, byteorder='big')
        rdata  += pref + exch
    else:
        print("Parsing not implmented for record type: " + str(qtype))
        print(data)
    return rdata

def gen_RRs(data):
    response = ''
    if data['QDCount']:
      qname  = data['Question'][0]['QNAME']
      qtype  = data['Question'][0]['QTYPE']
      qclass = data['Question'][0]['QCLASS']
      response = gen_name(qname)
      response += qtypes[qtype].to_bytes(2, byteorder='big')
      response += qclasses[qclass].to_bytes(2, byteorder='big')
    for section in ['Answer', 'Authority', 'Additional']:
        count = 0
        if section == 'Answer' and data['ANCount']:
            count = data['ANCount']
        elif section == 'Authority' and data['NSCount']:
            count = data['NSCount']
        elif section == 'Additional' and data['ARCount']:
            count = data['ARCount']
        for i in range(count):
            qname  = data[section][i]['QNAME']
            qtype  = data[section][i]['QTYPE']
            qclass = data[section][i]['QCLASS']
            ttl    = data[section][i]['TTL']

            tmp_res  = gen_name(qname)
            tmp_res += qtypes[qtype].to_bytes(2, byteorder='big')
            tmp_res += qclasses[qclass].to_bytes(2, byteorder='big')
            tmp_res += ttl.to_bytes(4, byteorder='big')
            rdata    = gen_rdata(data[section][i])
            if len(rdata) > 0 : #Type implemented
                tmp_res  += rdata
                response += tmp_res
    return response

def parse_packet(packet):
    ret = {}
    pkt_len = len(packet) #Length of the packet received 
    if(tcp):
        enc_len = int.from_bytes(packet[:2], 'big') #Encoded packet length
        pkt_len = pkt_len - 2
        packet = packet[2:]
        if pkt_len != enc_len:
            print("Packet length mismatch. Aborting...")
            sys.exit(1)
    
    #parse header
    if len(packet) < 12:
        print("Packet length too short. Aborting...")
        sys.exit(1)
    header = packet[:12]
    trans_id = int.from_bytes(header[:2], 'big')
    flags    = int.from_bytes(header[2:4], 'big')
    QDCount  = int.from_bytes(header[4:6], 'big')   #Number of questions
    ANCount  = int.from_bytes(header[6:8], 'big')   #Number of answers
    NSCount  = int.from_bytes(header[8:10], 'big')  #Number of NS RRs
    ARCount  = int.from_bytes(header[10:12], 'big') #Number of add RRS

    flags = parse_flags(flags)

    RCode = flags["RCode"]
    if RCode not in rcodes:
        print("RCode not implemented. Aborting...")
        sys.exit(1)

    ret['RCODE']   = rcodes[RCode]
    ret['TXID']    = trans_id
    ret['QDCount'] = QDCount
    ret['ANCount'] = ANCount
    ret['NSCount'] = NSCount
    ret['ARCount'] = ARCount

    pos = 12
    if(QDCount):
        if debug: print("Packet query section. Parsing...")
        if QDCount > 1:
            print("QDCount > 1 not supported. Aborting...")
            sys.exit(1)
        qdata = parse_question(pos, packet)
        pos   = skip_name(pos, packet)+4
        #Probably not going to support multiple queries, but storing in list anyway
        ret['Question'] = []
        ret['Question'].append({'QNAME':qdata[0], "QTYPE":qdata[1], 'QCLASS':qdata[2]})
    for section in ('Answer', 'Authority', "Additional"):
        if section == 'Answer':
            count = ANCount
        elif section == "Authority":
            count = NSCount
        elif section == "Additional":
            count = ARCount
        if count and debug: print("Response contains " + section + " section. Parsing...")
        ret[section] = []
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
            RData['QTYPE']  = qtype_int_to_name(qtype)
            RData['QCLASS'] = qclass_int_to_name(qclass)
            RData['TTL']    = ttl
            ret[section].append(RData)
            end += RDlength
            pos = end
    return ret

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
qtype     = 'A'
qclass    = 'IN'

#MISC
server    = '8.8.8.8'
port      = 53
tcp       = 0
debug     = 0
##########################

#Connection to upstream dns server
sock_type = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
upstr = socket.socket(socket.AF_INET, sock_type)
upstr.connect((server, port))

#Listen for a query here
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 53))
print("Server listening\n")
while True:
    #Receive and parse client query
    request, cladd = s.recvfrom(4096)
    if debug: print("Received client query")
    parsed  = parse_packet(request)
    cltxid  = parsed['TXID']
    qname   = parsed['Question'][0]['QNAME']
    qtype   = parsed['Question'][0]['QTYPE']
    qclass  = parsed['Question'][0]['QCLASS']
    if debug: print("Client query parsed\n")

    #Build and send query upstream
    if debug: print("Generating upstream query")
    header  = gen_header_std_query()
    query   = gen_question(qname, qtype, qclass)
    packet  = gen_packet(header, query)
    upstr.sendall(packet)
    if debug: print("Sent upstream query\n")

    #Receive and parse upstream response
    packet = upstr.recv(4096)
    if debug: print("Received upstream response")
    parsed = parse_packet(packet)
    QDCount = parsed['QDCount']
    ANCount = parsed['ANCount']
    NSCount = parsed['NSCount']
    ARCount = parsed['ARCount']
    if debug: print("Upstream response parsed\n")

    #Build and send client response
    if debug: print("Generating client response")
    flags    = gen_flags(1, 0, 0, TC, 1, 1, 0, 0)
    cltxid   = cltxid.to_bytes(2, 'big')#Make the gen_header function do this
    header   = gen_header(cltxid, flags, 1, ANCount, NSCount, ARCount)
    response = gen_RRs(parsed)
    packet   = gen_packet(header, response)
    s.sendto(packet, cladd)
    if debug: print("Sent client response\n\n")
