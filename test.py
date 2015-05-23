#!/usr/bin/python
#-*-coding:utf-8 -*-

import urllib, base64, binascii, time, re
from scapy.all import *

aps = []
def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in aps:
				aps.append(pkt.addr2)
				cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
				if re.search('privacy', cap):
					a = '加密状态：Yes\t热点BSSID为%s\tSSID为%s'%(pkt.addr2, pkt.info)
					#with open('test.txt', 'a+') as t:
					#	t.write(a+'\n')
					print a
				else:
					b = '加密状态：No\t热点BSSID为%s\tSSID为%s'%(pkt.addr2, pkt.info)
					#with open('test.txt', 'a+') as t:
					#	t.write(b+'\n')
					print b
				

sniff(iface = 'mon0', prn = PacketHandler)