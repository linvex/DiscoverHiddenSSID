#!/usr/bin/python
#-*-coding:utf-8 -*-

import sys, os, binascii
from scapy.all import *

aps = []
aps2 = []

def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.addr2 == '38:bc:1a:8e:3d:34':
			try:
#				print pkt.info
				if binascii.hexlify(ssid)[:2] != '00':
					if pkt.addr2 not in aps2:
						aps2.append(pkt.addr2)
						print '隐藏无线热点名称是：'+pkt.info
			except:
				pass				
					

sniff(iface = 'mon0', prn = PacketHandler)