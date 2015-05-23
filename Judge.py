#!/usr/bin/python
#-*-coding: utf-8 -*-
## author:linvex
## 本脚本可辅助揪出周围隐藏无线名称，并给出是否加密和加密类型信息。仅供学习，勿做他用。

import sys, os, binascii
from scapy.all import *

aps = []
aps2 = []
Jug = 0

def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.subtype == 5:
			if pkt.addr2 not in aps:
				aps.append(pkt.addr2)
				print pkt.info+'\t\t\t'+pkt.addr2
				'''
				if binascii.hexlify(pkt.info)[:2]== '00':
					print '发现隐藏无线热点！ BSSID是 %s' %pkt.addr2
					print pkt.info
					addr2 = pkt.addr2
				'''

sniff(iface = 'mon0', prn = PacketHandler)