#!/usr/bin/python
#-*-coding: utf-8 -*-
## author:linvex
## 本脚本可辅助揪出周围隐藏无线名称，仅供学习，勿做他用。

import sys, os, binascii, time, re
from scapy.all import *

Jug = 0
con0 = 0
con1 = 0
con2 = 0
aps = []
aps2 = []

#判断是否开启监听模式
try:
	ifa = os.popen('ifconfig  | grep mon0 | cut -d " " -f 1')
	ifb = ifa.read()
	if ifb != 'mon0\n':
		print '正在开启监听模式……\n'
		#os.system('airmon-ng start wlan0')
		f = os.popen('airmon-ng start wlan0')
		f.read()
		f.close
	if ifb == 'mon0\n':
		pass
	ifa.close()
except:
	pass

#定义sniff的prn函数
def PacketHandler(pkt):

	#定义全局变量
	global Jug#控制sniff流程
	global con0#控制第一种状态的print函数
	global con1#控制第二种状态的print函数
	global con2#控制第三种状态的print函数
	global addr#BSSID赋值

	#发现无线热点
	if Jug == 0:
		if con0 == 0:
			print '正在搜索周围是否存在隐藏热点……\n'
			con0 =+ 1
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype == 8:#进一步精细化sniff包
				if pkt.addr2 not in aps:
					aps.append(pkt.addr2)
					if binascii.hexlify(pkt.info)[:2] == '00':#判断名称是否为空
									       #这里简单解释一下：隐藏SSID并非代表SSID值为空，而是以\x00填充，\x00的数量与隐藏SSID的字符数一致
						print '发现隐藏无线热点！ BSSID是 %s\n' %pkt.addr2
						addr = pkt.addr2
						#Jug = 1
						Jug = 2

	#启动攻击模式，命令为 aireplay-ng --deauth 0 -a addr mon0 --ignore-negative-one，除长时间无法获取无线热点名称，一般不使用
	if Jug == 1:
		#os.system('aireplay-ng --deauth 0 -a '+addr+' mon0 --ignore-negative-one')
		#Jug = 2
		pass

	#寻找无线热点名称
	if Jug == 2:
		if con2 == 0:
			print '正在破解无线热点名称……'
			print '若长时间未能破解得出结果，请修改源代码或手动执行以下命令：\nsudo aireplay-ng --deauth 0 -a '+addr+' mon0 --ignore-negative-one\n'
			con2 =+ 1
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype == 5:
				if pkt.addr2 == addr:
					try:
						#print pkt.info#该行为调试行
						if pkt.addr2 not in aps2:
							aps2.append(pkt.addr2)
							cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
							print '隐藏无线热点名称是：'+pkt.info
							if re.search('privacy', cap):
								print '加密状态： 已加密\n'
							else:
								print '加密状态： 未加密\n'
							print '正在关闭监听模式……\n'
							time.sleep(1)
							t = os.popen('airmon-ng stop mon0')
							t.read()
							t.close
					except:
						pass

try:
	sniff(iface = 'mon0', prn = PacketHandler)
except:
	print '任务完成，程序即将停止，谢谢使用！\n'
	time.sleep(1)
	sys.exit()