#!/usr/bin/env python
#coding: utf8

# *****************************************************
# CAUTION: you have to install tshark tool
# *****************************************************

import os
import time, datetime
import struct

import sys,os  

tshark_path = "/usr/bin/tshark"

if not os.path.exists(tshark_path):
    print "Sorry: tshark not found in path: %s" % tshark_path
    print "Maybe you did not install tshark. Or you should change this source file at LINE 11 to tell me the right installed path."
    sys.exit(-1)

if len(sys.argv) < 2:
    print "Usage: python generate_metadata_from_pcap.py <pcap file> <metadata_dir>"  
    sys.exit(-1)


in_path = sys.argv[1] 

if not os.path.exists(in_path):
    print "Usage: python generate_metadata_from_pcap.py <pcap file> <metadata_dir>"  
    print "Error: not found file %s" % in_path
    sys.exit(-1)

out_dir = sys.argv[2]
if not os.path.exists(in_path):
    print "Usage: python generate_metadata_from_pcap.py <pcap file> <metadata_dir>"  
    print "Error: not found dir %s" % out_dir
    sys.exit(-1)
   

tmp_dir = "/tmp"
out_path = os.path.join(out_dir, os.path.basename(in_path)+".txt")


os.system(tshark_path + " -T fields -E separator=\"^\" "
"-e data ""-e data "
          "-e ip.src "            #  3=sourceIP
          "-e ip.dst "            #  4=destIP
          "-e udp.srcport "       #  5=sourcePort
          "-e udp.dstport "       #  6=destPort
          "-e ip.proto "          #  7=protocol
"-e data ""-e data ""-e data ""-e data " # 8-11
          "-e frame.time_epoch "  #  flowStartSeconds
                                  #  带插入
"-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data "
          "-e dns.flags.rcode "   #  54 = DNSReplyCode
          "-e dns.qry.name "      #  55 = DNSQueryName
          "-e dns.qry.type "      #  56 = DNSRequestRRType
          "-e dns.qry.class "     #  57 = DNSRRClass
          "-e dns.time "          #  58 = DNSDelay   #每个请求包和响应包的时间间隔，换算 
          "-e dns.resp.ttl "      #  59 = DNSReplyTTL
          "-e ip.addr "           #  60 = DNSReplyIPv4
          "-e ipv6.addr "         #  61 = DNSReplyIPv6
          "-e dns.resp.type "     #  62 = DNSReplyRRType
"-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data "
          "-e dns.resp.name "     #  77 = DNSReplyName
"-e data ""-e data ""-e data "
                                  #  待插payload
          "-e data ""-e data ""-e data ""-e data ""-e data ""-e data "
          "-e dns.length "        #  88 = DNSRequestLength
          "-e data "              #  89=DNSRequestErrLength
          "-e dns.resp.len "      #  90 = DNSReplyLength
          "-e data "              #  91=DNSReplyErrLength
"-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data ""-e data "
          "-Y dns -r %s  >%s/tsharkResult.txt" % (in_path, tmp_dir))


#读取pcap文件，解析相应的信息，为了在记事本中显示的方便。
payloadResultwithBlank = "%s/payloadResultwithBlank.txt" % tmp_dir
fpcap = open(in_path, 'rb')
ftxt = open(payloadResultwithBlank,'w')
string_data = fpcap.read()
#pcap文件包头解析
pcap_header = {}
pcap_header['magic_number'] = string_data[0:4]
pcap_header['version_major'] = string_data[4:6]
pcap_header['version_minor'] = string_data[6:8]
pcap_header['thiszone'] = string_data[8:12]
pcap_header['sigfigs'] = string_data[12:16]
pcap_header['snaplen'] = string_data[16:20]
pcap_header['linktype'] = string_data[20:24]
step = 0
packet_num = 0
packet_data = []
pcap_packet_header = {}
i =24
while(i<len(string_data)):
    # 数据包头各个字段
    pcap_packet_header['GMTtime'] = string_data[i:i+4]
    pcap_packet_header['MicroTime'] = string_data[i+4:i+8]
    pcap_packet_header['caplen'] = string_data[i+8:i+12]
    pcap_packet_header['len'] = string_data[i+12:i+16]
    #求出此包的包长len
    packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
    #写入此包数据
    packet_data.append(string_data[i+58:i+16+packet_len])
    i = i+ packet_len+16
    packet_num+=1
# 把pacp文件里的数据包信息写入result.txt
for i in range(packet_num):
    ftxt.write(''.join(x.encode('hex') for x in packet_data[i]) + '\n')
ftxt.close()
fpcap.close()
infp = open(payloadResultwithBlank, "r")

payloadResultOver = "%s/payloadResultOver.txt" % tmp_dir
outfp = open(payloadResultOver, "w")
lines = infp.readlines()
for li in lines:
    if li.split():
        outfp.writelines(li)
infp.close()
outfp.close()

def copyTimeMetadata(string):
    string = string.split('^')
    string.insert(11,string[11])
    return string

payloadFile = open("%s/payloadResultOver.txt" % tmp_dir)
tsharkFile = open("%s/tsharkResult.txt" % tmp_dir)
tsharkData = []
payload = []
meteData = []

for line in tsharkFile:
    line = line.replace("\n", "")
    line = copyTimeMetadata(line)
    tsharkData.append(line)
for line in payloadFile:
    line = line.replace("\n","")
    payload.append(line)
count1 = len(payload)
for i in range(0,count1):
    tsharkData[i].insert(80,payload[i])
    if (tsharkData[i][76]=="<Root>"):
        tsharkData[i][76]=tsharkData[i][54]

meteDataWithPayload = open("%s/meteDataWithPayload.txt" % tmp_dir,'w')
for line in tsharkData:
    meteDataWithPayload.write("^".join(line)+"\n")

finallyMetedata = []
dataListFromQuery = []
dataListFromRespon = []
QueriesName_map = {}
DNSQueryName = 55 -1
destPort = 6 -1
DNSDelay = 0


with open("%s/meteDataWithPayload.txt" % tmp_dir) as f:
    lines = f.readlines()
    for index,line in enumerate(lines):
        line = line.replace("\n","")
        dataFromQuery = line.split("^")
        if 89 < len(dataFromQuery) and dataFromQuery[destPort] == "53":             # 此时是请求报文，合并到请求报文中
            dataListFromQuery.append(dataFromQuery)     #dataListFromQuery列表保存的全是请求字段
            QueriesName = dataFromQuery[DNSQueryName]
            QueriesName_map[QueriesName] = index
    count = len(QueriesName_map)                        #计算总共多少条请求报文
    for line in lines:
        dataFromRespon = line.split("^")
        if 89 < len(dataFromRespon) and dataFromRespon[destPort] != "53":
            NAME = dataFromRespon[DNSQueryName]         #响应报文中的域名
            if (NAME in QueriesName_map):
                for i in range(0, count):
                    if dataListFromQuery[i][DNSQueryName] == NAME:
                        dataListFromQuery[i][12] = dataFromRespon[12]
                        dataListFromQuery[i][53] = dataFromRespon[53]
                        dataListFromQuery[i][57] = dataFromRespon[57]
                        dataListFromQuery[i][58] = dataFromRespon[58]
                        dataListFromQuery[i][89] = dataFromRespon[89]
                        DNSDelay = (float(dataListFromQuery[i][12])-float(dataListFromQuery[i][11]))*1000000
                        dataListFromQuery[i][57] = str(DNSDelay)
            else:
                print "warning: The response message could not find the requested message", line
                pass


meteDataFile = open(out_path,'w')
for line in dataListFromQuery:
    if line[53]!="":
        line[59] = line[59].replace(",",";")
        meteDataFile.write("^".join(line) + "\n")
meteDataFile.close()

print "%s generated from pcap file %s OK." % (out_path, in_path)
