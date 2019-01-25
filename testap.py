#!/usr/bin/python
# -*- coding:utf-8 -*-

import asyncore
import fcntl
import logging
import os
import signal
import socket
import struct
import sys
import time
import threading

from argparse import ArgumentParser
from netaddr import *
from netaddr.core import NotRegisteredError
from platform import system
from subprocess import call, Popen, PIPE

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib("wpa_eapol")


################################################################################
# define variables
W = '\033[0m'
R = '\033[31m'
G = '\033[32m'
O = '\033[33m'
B = '\033[34m'
P = '\033[35m'
C = '\033[36m'
#G = '\033[37m'
T = '\033[93m'

wintfparent = ''	# wireless
intfparent = ''		# wired
verbose = 0
hopList = []
channelList = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10, 12, 13]
channel = 1
apMACAddress = ''
apIPAddress = '10.0.2.100'
apIPAddress_sub = '10.0.2.100/24'
# routerAddress_sub = '10.0.2.2/24'
clientList = {}
DN = open(os.devnull, 'w')


################################################################################
class BeaconThread(threading.Thread):
	iface = None
	packet = None
	sc = 0

	def __init__(self, iface):
		threading.Thread.__init__(self)
		self.stop_event = threading.Event()
		self.iface = iface
		self.setDaemon(True)

	def run(self):
		if self.packet != None:
			while not self.stop_event.is_set():
				self.packet.SC = self.nextSC()
				sendp(self.packet, iface=self.iface, verbose=0)
				time.sleep(0.5)

	def stop(self):
		print "----- stop thread sending beacon -----"
		self.stop_event.set()
		print ""

	def nextSC(self):
		self.sc = (self.sc + 1) % 4096
		temp = self.sc
		return temp * 16

	def makeBeaconPacket(self, apMACAddress, baseBeaconPacket, sc):
		packet = None
		self.sc = sc
		pktradiotap = None
		pktdot11fcs = None
		pktdot11beacon = None
		pktdot11elt = None
		pktdot11elt_ssid = None
		pktdot11elt_rates = None
		pktdot11elt_dsset = None
		pktdot11elt_tim = None
		pktdot11elt_country = None
		pktdot11elt_erpinfo_erpid = None
		pktdot11elt_erpinfo_nonerpid = None
		pktdot11elt_esrates = None
		pktdot11elt_htcapabilities = None
		pktdot11elt_htinformation = None


		if baseBeaconPacket.haslayer(RadioTap):
			pktradiotap = baseBeaconPacket.getlayer(RadioTap)
			f1=lambda x: 128 if x < 5000 else 256
			l1=[-30, -50, -52, -55, -56, -57, -58, -59, -60, -61, -62, -63, -64, -65, -66, -67, -70, -73, -76, -80]
			packet = RadioTap(
								version=pktradiotap.version,
								pad=pktradiotap.pad,
	#							len=pktradiotap.len,
								present=46,	# <Flag 46 (Flags+Rate+Channel+dBm_AntSignal)>, <Flag 536870958 (Flags+Rate+Channel+dBm_AntSignal+RadiotapNS)>
								Flags=16,	# <Flag 16 (FCS)>
								Rate=pktradiotap.Rate,
								Channel=pktradiotap.Channel,
								ChannelFlags=f1(pktradiotap.Channel),	# <Flag 128 (2GHz)>, <Flag 256 (5GHz)>
								dBm_AntSignal=random.choice(l1)
	#							notdecoded=pktradiotap.notdecoded
								)

			if baseBeaconPacket.haslayer(Dot11FCS):
				pktdot11fcs = baseBeaconPacket.getlayer(Dot11FCS)
				packet /= Dot11FCS(
									subtype=pktdot11fcs.subtype,
									type=pktdot11fcs.type,
									proto=pktdot11fcs.proto,
	#								FCField=pktdot11fcs.FCField,
									ID=pktdot11fcs.ID,
									addr1=pktdot11fcs.addr1,
									addr2=apMACAddress,		# testap mac address
									addr3=apMACAddress,		# testap mac address
									addr4=pktdot11fcs.addr4,
									SC=sc	# sc
									)

				if baseBeaconPacket.haslayer(Dot11Beacon):
					pktdot11beacon = baseBeaconPacket.getlayer(Dot11Beacon)
					packet /= Dot11Beacon(
											timestamp = pktdot11beacon.timestamp,
											cap=260,	# <Flag 260 (short-slot+ESS)>
											beacon_interval=pktdot11beacon.beacon_interval
											)
					if baseBeaconPacket.haslayer(Dot11Elt):
						pktdot11elt = baseBeaconPacket.getlayer(Dot11Elt)
						temp = pktdot11elt.copy()
						elt = None
						eltcount = 1

						while elt != temp.lastlayer(Dot11Elt):
							elt = pktdot11elt.getlayer(Dot11Elt, nb=eltcount)
							eltcount += 1
							if hasattr(elt, 'ID'):
								if elt.ID == 0: # SSID
									packet /= Dot11Elt(
														info=elt.info,
														ID=0,
														len=elt.len
														)
								elif elt.ID == 1: # Rates
									packet /= Dot11EltRates(
														rates=elt.rates,
														ID=1,
														len=elt.len
														)
								elif elt.ID == 3: # DSset
									packet /= Dot11Elt(
														info=elt.info,
														ID=3,
														len=elt.len
														)
								elif elt.ID == 5: # TIM
									packet /= Dot11Elt(
														info=elt.info,
														ID=5,
														len=elt.len
														)
								elif elt.ID == 7: # Country
									packet /= Dot11Elt(
														info=elt.info,
														ID=7,
														len=elt.len
														)
								elif elt.ID == 42: # ERPinfo erpid
									packet /= Dot11Elt(
														info=elt.info,
														ID=42,
														len=elt.len
														)
								elif elt.ID == 47: # ERPinfo non erpid
									packet /= Dot11Elt(
														info=elt.info,
														ID=47,
														len=elt.len
														)
								elif elt.ID == 50: # ESRates
									packet /= Dot11Elt(
														info=elt.info,
														ID=50,
														len=elt.len
														)
								elif elt.ID == 45: # HTCapabilities
									packet /= Dot11Elt(
														info=elt.info,
														ID=45,
														len=elt.len
														)
								elif elt.ID == 61: # HTInformation
									packet /= Dot11Elt(
														info=elt.info,
														ID=61,
														len=elt.len
														)
								# elif elt.ID == 221: # Vendor Specific
								# 	packet /= Dot11EltVendorSpecific(
								# 						info=elt.info,
								# 						oui=elt.oui,
								# 						ID=221,
								# 						len=elt.len
								# 						)
					else:
						print R+"There are no Dot11Elt layers. Could not create beacon packet."+W
						return False
				else:
					print R+"There is no Dot11Beacon layer. Could not create beacon packet."+W
					return False
			else:
				print R+"There is no Dot11FCS layer. Could not create beacon packet."+W
				return False
		else:
			print R+"There is no RadioTap layer. Could not create beacon packet."+W
			return False

#		print ls(packet)
#		print ""

		self.packet = packet
		return packet


class WiredInterfaceThread(threading.Thread):
	clientList = None
	wiface = None
	iface = None
	apMACAddress = None
	beaconPacket = None
	eltPacket = None

	def __init__(self, wiface, iface, clientList, apMACAddress, beaconPacket, eltPacket):
		threading.Thread.__init__(self)
		self.stop_event = threading.Event()
		self.wiface = wiface
		self.iface = iface
		self.clientList = clientList
		self.apMACAddress = apMACAddress
		self.beaconPacket = beaconPacket
		self.eltPacket = eltPacket
		self.setDaemon(True)

	def run(self):
		cap = sniff(iface = self.iface, prn = self.packetHandler, stop_filter = lambda p: self.stop_event.is_set())

	def stop(self):
		print "----- stop thread wired interface -----"
		self.stop_event.set()
		print ""

	def packetHandler(self, pkt):
		client = None
		if pkt.haslayer(Ether):
			client = self.clientList.get(pkt[Ether].dst)
			if client == None and pkt[Ether].dst != "ff:ff:ff:ff:ff:ff":
				return
			if pkt.haslayer(ARP):
#				temp = pkt.getlayer(ARP)
				packet = self.makeRadioTapPacket(self.beaconPacket)
				if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
					packet /= Dot11FCS(
										type=2,	# Data Frame
										subtype=0,	# Data
										proto=0,
										FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
										ID=0,	# duration
										addr1=pkt[Ether].dst,	# dst
										addr2=self.apMACAddress,	# AP
										addr3=pkt[Ether].src,	# src
										SC=0,
#										addr4=None,
										)
					packet /= LLC()
					packet /= SNAP()
					packet /= ARP(
									hwtype=pkt[ARP].hwtype,
									ptype=pkt[ARP].ptype,
									hwlen=pkt[ARP].hwlen,
									plen=pkt[ARP].plen,
									op=pkt[ARP].op,
									hwsrc=pkt[ARP].hwsrc,
									psrc=pkt[ARP].psrc,
									hwdst=pkt[ARP].hwdst,
									pdst=pkt[ARP].pdst
									)
					sendp(packet, iface=self.wiface, verbose=0)
				else:
					packet /= Dot11FCS(
										type=2,	# Data Frame
										subtype=0,	# Data
										proto=0,
										FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
										ID=0,	# duration
										addr1=pkt[Ether].dst,	# dst
										addr2=self.apMACAddress,	# AP
										addr3=pkt[Ether].src,	# src
										SC=client.nextApSC(),
#										addr4=None,
										)
					packet /= LLC()
					packet /= SNAP()
					packet /= ARP(
									hwtype=pkt[ARP].hwtype,
									ptype=pkt[ARP].ptype,
									hwlen=pkt[ARP].hwlen,
									plen=pkt[ARP].plen,
									op=pkt[ARP].op,
									hwsrc=pkt[ARP].hwsrc,
									psrc=pkt[ARP].psrc,
									hwdst=pkt[ARP].hwdst,
									pdst=pkt[ARP].pdst
									)
					sendp(packet, iface=self.wiface, verbose=0)
			elif pkt.haslayer(DHCP):
				if pkt[DHCP].options[0][1] == 2 or pkt[DHCP].options[0][1] == 5:	# DHCP Offer or DHCP ACK
					if pkt[DHCP].options[0][1] == 5:	# DHCP ACK
						client.setIpAddress(pkt[BOOTP].yiaddr)
					temp = pkt.getlayer(IP)
					packet = self.makeRadioTapPacket(self.beaconPacket)
					if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" or pkt[IP].dst == "255.255.255.255":
						packet /= Dot11FCS(
											type=2,	# Data Frame
											subtype=0,	# Data
											proto=0,
											FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
											ID=0,	# duration
											addr1=pkt[Ether].dst,	# dst
											addr2=self.apMACAddress,	# AP
											addr3=pkt[Ether].src,	# src
											SC=0,
#											addr4=None,
											)
						packet /= LLC()
						packet /= SNAP()
						packet /= temp
						sendp(packet, iface=self.wiface, verbose=0)
					else:
						packet /= Dot11FCS(
											type=2,	# Data Frame
											subtype=0,	# Data
											proto=0,
											FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
											ID=0,	# duration
											addr1=pkt[Ether].dst,	# dst
											addr2=self.apMACAddress,	# AP
											addr3=pkt[Ether].src,	# src
											SC=client.nextApSC(),
#											addr4=None,
											)
						packet /= LLC()
						packet /= SNAP()
						packet /= temp
						sendp(packet, iface=self.wiface, verbose=0)
				else:
					return
			elif pkt.haslayer(IP):
				packet = self.makeRadioTapPacket(self.beaconPacket)
				if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" or pkt[IP].dst == "255.255.255.255":
					packet /= Dot11FCS(
										type=2,	# Data Frame
										subtype=0,	# Data
										proto=0,
										FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
										ID=0,	# duration
										addr1=pkt[Ether].dst,	# dst
										addr2=self.apMACAddress,	# AP
										addr3=pkt[Ether].src,	# src
										SC=0,
#										addr4=None,
										)
					packet /= LLC()
					packet /= SNAP()
					temp = IP(
								version=pkt[IP].version,
								ihl=pkt[IP].ihl,
								tos=pkt[IP].tos,
								len=pkt[IP].len,
								id=pkt[IP].id,
								flags=pkt[IP].flags,
								frag=pkt[IP].frag,
								ttl=pkt[IP].ttl,
								proto=pkt[IP].proto,
								chksum=pkt[IP].chksum,
								src=pkt[IP].src,
								dst=pkt[IP].dst,
								options=pkt[IP].options
								)
					if pkt.haslayer(TCP):
						temp /= TCP(
										sport=pkt[TCP].sport,
										dport=pkt[TCP].dport,
										seq=pkt[TCP].seq,
										ack=pkt[TCP].ack,
										dataofs=pkt[TCP].dataofs,
										reserved=pkt[TCP].reserved,
										flags=pkt[TCP].flags,
										window=pkt[TCP].window,
										chksum=pkt[TCP].chksum,
										urgptr=pkt[TCP].urgptr,
										options=pkt[TCP].options
									)
						if hasattr(pkt[TCP], 'load'):
							temp /= pkt[TCP].load
						if temp[IP].len > 1460:
							frags = fragment(temp, fragsize=1400)
							c = 0
							for f in frags:
								p = packet.copy()
								p /= f
								p[IP].len = len(p[IP])
								if c > 0:
									p[Dot11FCS].SC = c * 16
								c += 1
								sendp(p, iface=self.wiface, verbose=0)
						else:
							packet /= temp
							sendp(packet, iface=self.wiface, verbose=0)

					elif pkt.haslayer(UDP):
						temp /= pkt.getlayer(UDP)
						packet /= temp
						sendp(packet, iface=self.wiface, verbose=0)
					else:
						return
				elif pkt[IP].dst == client.getIpAddress():
					packet /= Dot11FCS(
										type=2,	# Data Frame
										subtype=0,	# Data
										proto=0,
										FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
										ID=0,	# duration
										addr1=pkt[Ether].dst,	# dst
										addr2=self.apMACAddress,	# AP
										addr3=pkt[Ether].src,	# src
										SC=client.nextApSC(),
#										addr4=None,
										)
					packet /= LLC()
					packet /= SNAP()
					temp = IP(
								version=pkt[IP].version,
								ihl=pkt[IP].ihl,
								tos=pkt[IP].tos,
								len=pkt[IP].len,
								id=pkt[IP].id,
								flags=pkt[IP].flags,
								frag=pkt[IP].frag,
								ttl=pkt[IP].ttl,
								proto=pkt[IP].proto,
								chksum=pkt[IP].chksum,
								src=pkt[IP].src,
								dst=pkt[IP].dst,
								options=pkt[IP].options
								)
					if pkt.haslayer(TCP):
						temp /= TCP(
										sport=pkt[TCP].sport,
										dport=pkt[TCP].dport,
										seq=pkt[TCP].seq,
										ack=pkt[TCP].ack,
										dataofs=pkt[TCP].dataofs,
										reserved=pkt[TCP].reserved,
										flags=pkt[TCP].flags,
										window=pkt[TCP].window,
										chksum=pkt[TCP].chksum,
										urgptr=pkt[TCP].urgptr,
										options=pkt[TCP].options
									)
						if hasattr(pkt[TCP], 'load'):
							temp /= pkt[TCP].load
#						print "temp[IP].len = %d" % temp[IP].len
						if temp[IP].len > 1460:
							frags = fragment(temp, fragsize=1400)
							c = 0
							for f in frags:
								p = packet.copy()
								p /= f
								p[IP].len = len(p[IP])
								if c > 0:
									p[Dot11FCS].SC = client.nextApSC()
								c += 1
#								print p.command()
#								print "len(p[IP].load) = %d" % len(p[IP].load)
#								print "len(p[IP]) = %d" % len(p[IP])
								sendp(p, iface=self.wiface, verbose=0)
						else:
							packet /= temp
							sendp(packet, iface=self.wiface, verbose=0)
					elif pkt.haslayer(UDP):
						temp /= pkt.getlayer(UDP)
						packet /= temp
						sendp(packet, iface=self.wiface, verbose=0)
					elif pkt.haslayer(ICMP):
						temp /= pkt.getlayer(ICMP)
						packet /= temp
						sendp(packet, iface=self.wiface, verbose=0)
					else:
						return

	def makeRadioTapPacket(self, basePacket):
		packet = None
		pktradiotap = None
		if basePacket.haslayer(RadioTap):
			pktradiotap = basePacket.getlayer(RadioTap)
			f1=lambda x: 128 if x < 5000 else 256
			l1=[-30, -50, -52, -55, -56, -57, -58, -59, -60, -61, -62, -63, -64, -65, -66, -67, -70, -73, -76, -80]
			packet = RadioTap(
								version=pktradiotap.version,
								pad=pktradiotap.pad,
	#							len=pktradiotap.len,
								present=46,	# <Flag 46 (Flags+Rate+Channel+dBm_AntSignal)>, <Flag 536870958 (Flags+Rate+Channel+dBm_AntSignal+RadiotapNS)>
								Flags=16,	# <Flag 16 (FCS)>
								Rate=pktradiotap.Rate,
								Channel=pktradiotap.Channel,
								ChannelFlags=f1(pktradiotap.Channel),	# <Flag 128 (2GHz)>, <Flag 256 (5GHz)>
								dBm_AntSignal=random.choice(l1)
	#							notdecoded=pktradiotap.notdecoded
								)
			return packet
		else:
			print R+"There is no RadioTap layer. Could not create beacon packet."+W
			return False


class TestAPThread(threading.Thread):
	bpffilter = "not (wlan type mgt subtype beacon)"
	th1 = None
	clientList = None
	wiface = None
	iface = None
	apMACAddress = None
	apIPAddress = None
	beaconPacket = None
	eltPacket = None
	ipPacket = None
	tcpPacket = None
	udpPacket = None
	dhcpPacket = None

	def __init__(self, wiface, iface, clientList, apMACAddress, apIPAddress, beaconPacket, eltPacket, th1):
		threading.Thread.__init__(self)
		self.stop_event = threading.Event()
		self.wiface = wiface
		self.iface = iface
		self.clientList = clientList
		self.apMACAddress = apMACAddress
		self.apIPAddress = apIPAddress
		self.beaconPacket = beaconPacket
		self.eltPacket = eltPacket
		self.th1 = th1
		self.setDaemon(True)

	def run(self):
#		cap = sniff(iface = self.iface, prn = self.PacketHandler, lfilter=lambda x:x.haslayer(Dot11Beacon), stop_filter = lambda p: self.stop_event.is_set())
		cap = sniff(iface = self.wiface, prn = self.packetHandler, filter=self.bpffilter, stop_filter = lambda p: self.stop_event.is_set())
#		print "Stopped after %i packets" % len(cap)

	def stop(self):
		print "----- stop thread testap -----"
		self.stop_event.set()
		print ""

	def packetHandler(self, pkt):
		client = None
		pktradiotap = None
		pktdot11fcs = None
		pktdot11elt = None

		if pkt.haslayer(Dot11ProbeReq) and pkt.info == self.beaconPacket.info:
			client = self.clientList.get(pkt.addr2)
			if client != None and client.getFlagDot11AssoResp():
				return
			client = Client(pkt.addr2)
			self.clientList[pkt.addr2] = client
			client.setFlagDot11ProbeReq(True)
			packet = self.makeRadioTapPacket(self.beaconPacket)
			packet /= Dot11FCS(
								type=0,
								subtype=5,
								proto=0,
								FCfield=0,
								ID=0,	# duration
								addr1=client.getMacAddress(),
								addr2=self.apMACAddress,
								addr3=self.apMACAddress,
								SC=client.nextApSC(),
#								addr4=None,
								)
			packet /= Dot11ProbeResp(
									timestamp=int(time.time()),
									cap=260,	# <Flag 260 (short-slot+ESS)>
									beacon_interval=self.beaconPacket.beacon_interval
									)
#			packet /= self.makeDot11EltPacket(self.beaconPacket)
			packet /= self.eltPacket
#			print ls(packet)
			sendp(packet, iface=self.wiface, verbose=0)
			client.setFlagDot11ProbeResp(True)
		elif pkt.haslayer(Dot11Auth):
			client = self.clientList.get(pkt.addr2)
			if client == None:
				return
			if client.getFlagDot11ProbeResp():
				temp = pkt.getlayer(Dot11Auth)
				if temp.status == 0 and temp.seqnum == 1:
					client.setFlagDot11AuthReq(True)
					packet = self.makeRadioTapPacket(self.beaconPacket)
					packet /= Dot11FCS(
										type=0,
										subtype=11,
										proto=0,
										FCfield=0,
										ID=pkt.ID,	# duration
										addr1=client.getMacAddress(),
										addr2=self.apMACAddress,
										addr3=self.apMACAddress,
										SC=client.nextApSC(),
#										addr4=None,
										)
					packet /= Dot11Auth(
										algo=0,
										seqnum=2,
										status=0
										)
					sendp(packet, iface=self.wiface, verbose=0)
					client.setFlagDot11AuthResp(True)
				else:
					return
			else:
				return
		elif pkt.haslayer(Dot11AssoReq):
			client = self.clientList.get(pkt.addr2)
			if client == None:
				return
			if client.getFlagDot11AuthResp():
				temp = pkt.getlayer(Dot11AssoReq)
				client.setFlagDot11AssoReq(True)
				client.setClientAID(random.randint(0, 65536))
				packet = self.makeRadioTapPacket(self.beaconPacket)
				packet /= Dot11FCS(
									type=0,
									subtype=1,
									proto=0,
									FCfield=0,
									ID=pkt.ID,	# duration
									addr1=client.getMacAddress(),
									addr2=self.apMACAddress,
									addr3=self.apMACAddress,
									SC=client.nextApSC()
#									addr4=None,
									)
				packet /= Dot11AssoResp(
										cap=260,	# <Flag 260 (short-slot+ESS)>
										status=0,
										AID=client.getClientAID()
										)
				temp2 = self.eltPacket.getlayer(Dot11EltRates)
				packet /= temp2
				sendp(packet, iface=self.wiface, verbose=0)
				client.setFlagDot11AssoResp(True)
				print "Connect Client: %s." % client.getMacAddress()
			else:
				return
		elif pkt.haslayer(Dot11Deauth):
			client = self.clientList.get(pkt.addr2)
			if client == None:
				return
			if client.getFlagDot11AssoResp():
				temp = pkt.getlayer(Dot11AssoReq)
				print self.clientList[pkt.addr2]
				del self.clientList[pkt.addr2]
				# if temp.reason == 1:	# unspec
				# 	del self.clientList[pkt.addr2]
				# elif temp.reason == 2:	# auth expired
				# 	del self.clientList[pkt.addr2]
				# elif temp.reason == 3:	# deauth ST leaving
				# 	del self.clientList[pkt.addr2]
				# elif temp.reason == 4:	# inactivity
				# 	del self.clientList[pkt.addr2]
				# elif temp.reason == 5:	# AP full
				# 	del self.clientList[pkt.addr2]
				# else:
				# 	del self.clientList[pkt.addr2]
		elif pkt.haslayer(Dot11FCS) and pkt.addr1 == self.apMACAddress and not pkt.addr3 == self.apMACAddress:
			client = self.clientList.get(pkt.addr2)
			if client == None:
				return
			if client.getFlagDot11AssoResp():
				if pkt.haslayer(ARP):
					if pkt[ARP].op == 1 and pkt[ARP].pdst == self.apIPAddress and pkt[ARP].hwsrc == client.getMacAddress() and pkt[ARP].psrc == client.getIpAddress(): # ARP request to AP
						packet = self.makeRadioTapPacket(self.beaconPacket)
						packet /= Dot11FCS(
											type=2,	# Data Frame
											subtype=0,	# Data
											proto=0,
											FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
											ID=0,	# duration
											addr1=client.getMacAddress(),	# dst
											addr2=self.apMACAddress,	# AP
											addr3=self.apMACAddress,	# src
											SC=client.nextApSC(),
#											addr4=None,
											)
						packet /= LLC()
						packet /= SNAP()
						packet /= ARP(
										hwtype=1,	# Ethernet
										ptype=2048,	# IPv4 (0x0800)
										hwlen=6,
										plen=4,
										op=2,	# reply
										hwsrc=self.apMACAddress,
										psrc=self.apIPAddress,
										hwdst=client.getMacAddress(),
										pdst=client.getIpAddress()
										)
						sendp(packet, iface=self.wiface, verbose=0)
					else:
						temp = pkt.getlayer(ARP)
						packet = Ether(
										dst=pkt.addr3,
										src=pkt.addr2,
#										type=
										)
						packet /= temp
						sendp(packet, iface=self.iface, verbose=0)
				elif pkt.haslayer(IP):
					packet = Ether(
									dst=pkt.addr3,
									src=pkt.addr2,
#									type=
									)
					temp = IP(
								version=pkt[IP].version,
								ihl=pkt[IP].ihl,
								tos=pkt[IP].tos,
								len=pkt[IP].len,
								id=pkt[IP].id,
								flags=pkt[IP].flags,
								frag=pkt[IP].frag,
								ttl=pkt[IP].ttl,
								proto=pkt[IP].proto,
								chksum=pkt[IP].chksum,
								src=pkt[IP].src,
								dst=pkt[IP].dst,
								options=pkt[IP].options
								)
					if pkt.haslayer(TCP):
						temp /= TCP(
										sport=pkt[TCP].sport,
										dport=pkt[TCP].dport,
										seq=pkt[TCP].seq,
										ack=pkt[TCP].ack,
										dataofs=pkt[TCP].dataofs,
										reserved=pkt[TCP].reserved,
										flags=pkt[TCP].flags,
										window=pkt[TCP].window,
										chksum=pkt[TCP].chksum,
										urgptr=pkt[TCP].urgptr,
										options=pkt[TCP].options
									)
						if hasattr(pkt[TCP], 'load'):
							temp /= pkt[TCP].load
						if temp[IP].len > 1460:
							frags = fragment(temp, fragsize=1400)
							for f in frags:
								p = packet.copy()
								p /= f
								p[IP].len = len(p[IP])
								sendp(p, iface=self.iface, verbose=0)
						else:
							packet /= temp
							sendp(packet, iface=self.iface, verbose=0)
					elif pkt.haslayer(UDP):
						temp /= pkt.getlayer(UDP)
						packet /= temp
						sendp(packet, iface=self.iface, verbose=0)
					elif pkt.haslayer(ICMP):
						temp /= pkt.getlayer(ICMP)
						packet /= temp
						sendp(packet, iface=self.iface, verbose=0)
					else:
						return
			else:
				return
		elif pkt.haslayer(Dot11FCS) and pkt.addr1 == self.apMACAddress and pkt.addr3 == self.apMACAddress:
			client = self.clientList.get(pkt.addr2)
			if client == None:
				return
			if client.getFlagDot11AssoResp():
				if pkt.haslayer(ICMP):
					if pkt[IP].src == client.getIpAddress() and pkt[IP].dst == self.apIPAddress and pkt[ICMP].type == 8 and pkt[ICMP].code == 0:
						packet = self.makeRadioTapPacket(self.beaconPacket)
						packet /= Dot11FCS(
											type=2,	# Data Frame
											subtype=0,	# Data
											proto=0,
											FCfield=2,	# <Flag 2 (from-DS)> or <Flag 10 (from-DS+retry)>
											ID=0,	# duration
											addr1=client.getMacAddress(),	# dst
											addr2=self.apMACAddress,	# AP
											addr3=self.apMACAddress,	# src
											SC=client.nextApSC(),
#											addr4=None,
											)
						packet /= LLC()
						packet /= SNAP()
						packet /= IP(
										version=4,
										ihl=5,	# header length 20byte
										# tos=,
										# len=,
										# id=,
										# flags=,
										# frag=,
										# ttl=,
										proto=pkt[IP].proto,
										# chksum=,
										src=self.apIPAddress,
										dst=client.getIpAddress(),
										# options=
										)
						packet /= ICMP(
										type=0,	# Echo reply
										code=0,
										# chksum=,
										# id=,
										# seq=,
										# ts_ori=,
										# ts_rx=,
										# ts_tx=,
										# gw=,
										# ptr=,
										# reserved=,
										# length=,
										# addr_mask=,
										# nextopmtu=,
										# unused=,
										# unused=
										)
		else:
			return

	def makeRadioTapPacket(self, basePacket):
		packet = None
		pktradiotap = None

		if basePacket.haslayer(RadioTap):
			pktradiotap = basePacket.getlayer(RadioTap)
			f1=lambda x: 128 if x < 5000 else 256
			l1=[-30, -50, -52, -55, -56, -57, -58, -59, -60, -61, -62, -63, -64, -65, -66, -67, -70, -73, -76, -80]
			packet = RadioTap(
								version=pktradiotap.version,
								pad=pktradiotap.pad,
	#							len=pktradiotap.len,
								present=46,	# <Flag 46 (Flags+Rate+Channel+dBm_AntSignal)>, <Flag 536870958 (Flags+Rate+Channel+dBm_AntSignal+RadiotapNS)>
								Flags=16,	# <Flag 16 (FCS)>
								Rate=pktradiotap.Rate,
								Channel=pktradiotap.Channel,
								ChannelFlags=f1(pktradiotap.Channel),	# <Flag 128 (2GHz)>, <Flag 256 (5GHz)>
								dBm_AntSignal=random.choice(l1)
	#							notdecoded=pktradiotap.notdecoded
								)
			return packet
		else:
			print R+"There is no RadioTap layer. Could not create beacon packet."+W
			return False


class Client():
	macAddress = ''
	ipAddress = ''
	apSC = 0
	clientAID = 0
	clientSC = 0

	# flags
	flagDot11ProbeReq = False
	flagDot11ProbeResp = False
	flagDot11AuthReq = False
	flagDot11AuthResp = False
	flagDot11AssoReq = False
	flagDot11AssoResp = False

	def __init__(self, macAddress):
		self.macAddress = macAddress
		self.apSC = random.randint(0, 4096)

	def nextApSC(self):
		self.apSC = (self.apSC + 1) % 4096
		temp = self.apSC
		return temp * 16

	def setMacAddress(self, macAddress):
		self.macAddress = macAddress

	def getMacAddress(self):
		return self.macAddress

	def setIpAddress(self, ipAddress):
		self.ipAddress = ipAddress

	def getIpAddress(self):
		return self.ipAddress

	def setApSC(self, apSC):
		self.apSC = apSC

	def getApSC(self):
		return apSC

	def setClientSC(self, clientSC):
		self.clientSC = clientSC

	def getClientSC(self):
		return self.clientSC

	def setClientAID(self, clientAID):
		self.clientAID = clientAID

	def getClientAID(self):
		return self.clientAID

	def setFlagDot11ProbeReq(self, flagDot11ProbeReq):
		self.flagDot11ProbeReq = flagDot11ProbeReq

	def getFlagDot11ProbeReq(self):
		return self.flagDot11ProbeReq

	def setFlagDot11ProbeResp(self, flagDot11ProbeResp):
		self.flagDot11ProbeResp = flagDot11ProbeResp

	def getFlagDot11ProbeResp(self):
		return self.flagDot11ProbeResp

	def setFlagDot11AuthReq(self, flagDot11AuthReq):
		self.flagDot11AuthReq = flagDot11AuthReq

	def getFlagDot11AuthReq(self):
		return self.flagDot11AuthReq

	def setFlagDot11AuthResp(self, flagDot11AuthResp):
		self.flagDot11AuthResp = flagDot11AuthResp

	def getFlagDot11AuthResp(self):
		return self.flagDot11AuthResp

	def setFlagDot11AssoReq(self, flagDot11AssoReq):
		self.flagDot11AssoReq = flagDot11AssoReq

	def getFlagDot11AssoReq(self):
		return self.flagDot11AssoReq

	def setFlagDot11AssoResp(self, flagDot11AssoResp):
		self.flagDot11AssoResp = flagDot11AssoResp

	def getFlagDot11AssoResp(self):
		return self.flagDot11AssoResp


################################################################################
def osCheck():
	osversion = system()
	print "Operating System: %s"%osversion
	print ""

	if osversion != 'Linux':
		print R+"This script only works on Linux OS! Exiting!"+W
		exit(1)


def rootCheck():
	if os.geteuid() != 0:
		exit(R+"You need to be root to run this script!"+W)
	else:
		print "You are running this script as root!"
		print ""


def argumentCheck():
	result = parser()
	if result == False:
		sys.exit(1)
	print ''


def parser():
	global wintfparent, intfparent
	usage = O+'Usage: sudo python %s winterface interface [--help]'%os.path.basename(__file__)+W

	argparser = ArgumentParser(usage=usage)
	argparser.add_argument('winterface', type=str, help='wireless interface name')
	argparser.add_argument('interface', type=str, help=' wired interface name')
	args = argparser.parse_args()

	if args.winterface:
		if checkInterface(args.winterface):
			wintfparent = args.winterface
		else:
			return False
	if args.interface:
		if checkInterface(args.interface):
			intfparent = args.interface
		else:
			return False

	return True


def checkInterface(iface):
	if not os.path.isdir("/sys/class/net/" + iface):
		print R+"Interface %s does not exist! Cannot countinue!"%(iface)+W
		print ""
		return False
	else:
		print "Interface %s exist!"%(iface)
		print ""
		return True


def initWirelessInterface(iface):
	if checkInterface(iface):
		try:
			# WiFi interface down
			print G+"----- WiFi interface down -----"+W
			os.system("ip link set %s down" % iface)
			time.sleep(0.5)
			print ""

			# rfkill unblock all
			print G+"----- rfkill unblock all -----"+W
			os.system("rfkill unblock all")
			os.system("rfkill list")
			print ""

			# iw reg set JP
			print G+"----- iw reg set JP -----"+W
			os.system("iw reg set JP")
			os.system("iw reg get")
			print ""

			# airmon-ng check kill
			print G+"----- airmon-ng check kill -----"+W
			os.system("airmon-ng check")
			os.system("airmon-ng check kill")
			time.sleep(10.0)
			os.system("airmon-ng check")
			print ""

			# WiFi interface mode change: monitor
			print G+"----- WiFi interface mode change: monitor -----"+W
			os.system("iw dev %s set type monitor" % iface)
#			os.system("iwconfig %s" % iface)
			print ""

			# WiFi interface set txpower
			print G+"----- WiFi interface set txpower -----"+W
			os.system("iwconfig %s txpower 5" % iface)
			os.system("iwconfig %s" % iface)
			print ""

			# MAC Address change
			print G+"----- MAC address change -----"+W
			os.system("macchanger -A %s" % iface)
			print ""

			# IP Address set
			print G+"----- IP address set -----"+W
			os.system("ip addr add %s dev %s" % (apIPAddress_sub, iface))
			print ""

			# Default Gateway set
			# print G+"----- Default Gateway set -----"+W
			# os.system("ip route add default via %s", routeAddress)

			# WiFi interface up
			print G+"----- WiFi interface up -----"+W
			os.system("ip link set %s up" % iface)
			os.system("ip addr show dev %s" % iface)
			print ""

			# Virtual interface (tun) create


			# Forward enable
			# print G+"----- Forward enable -----"+W
			# os.system("sysctl -w net.ipv4.ip_forward=1")
			# print ""

		except OSError as e:
			print R+"Could not create monitor %s"%iface+W
			os.kill(os.getpid(), SIGINT)
			sys.exit(1)
	else:
		print R+"WiFi interface %s does not exist! Cannot countinue!"%(iface)+W



def getMAC(iface):
	if checkInterface(iface):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
		macaddr = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
		manuf = getMACOUI(macaddr)
		print "Actual %s MAC Address: %s (%s)" % (iface, macaddr.upper(), manuf)
		print ""
		return macaddr
	else:
		return None


def getMACOUI(mac):
	maco = EUI(mac)
	try:
		manuf = maco.oui.registration().org
	except NotRegisteredError:
		manuf = "Not avaiable"
	return manuf


def changeMAC(iface):
	if checkInterface(iface):
		try:
			# WiFi interface down
			print "----- WiFi interface down -----"
			os.system("ip link set %s down" % iface)
			time.sleep(0.5)
			print ""

			# MAC Address change
			print "----- MAC Address change -----"
			os.system("macchanger -A %s" % iface)
			print ""

			# WiFi interface up
			print "----- WiFi interface up -----"
			os.system("ip link set %s up" % iface)
			time.sleep(0.5)
			os.system("ip addr show dev %s" % iface)
			print ""

		except OSError as e:
			print R+"Could not create monitor %s"%iface+W
			os.kill(os.getpid(), SIGINT)
			sys.exit(1)


def scanBeacon(iface):
	global hopList
	hopList = [] # hopList clear

	if checkInterface(iface):
		hopList=checkChannels(iface)

		while 1:
			channel_str = raw_input(T+"input scan channel number: "+W)
			if int(channel_str) in hopList:
				setChannel(iface, channel_str)

				print "----- scan beacon packet -----"
#				cap=sniff(iface=iface, lfilter=lambda x:x.haslayer(Dot11Beacon), prn=lambda p:(p.info, p.addr1, p.addr2, p.addr3), count=10)
				capture = sniff(iface=iface, lfilter=lambda x:x.haslayer(Dot11Beacon), count=10)
				i = 0
				for cap in capture:
					print "[%d] ssid:%s, len:%d, addr1:%s, addr2:%s, addr3:%s, addr4:%s"%(i, cap.info, cap[Dot11Elt].len, cap.addr1, cap.addr2, cap.addr3, cap.addr4)
					i += 1
				print ""

				packetnumber_str = raw_input(T+"select beacon packet number: "+W)
				print ""

				try:
					if int(packetnumber_str) < 10 and int(packetnumber_str) >= 0:
						packetnumber = int(packetnumber_str)

						# stealth ssid
						if '\x00' in capture[packetnumber].info:
							ssid_str = raw_input(T+"input ssid: "+W)
							if len(ssid_str) > capture[packetnumber][Dot11Elt].len:
								ssid_str = ssid_str[:capture[packetnumber][Dot11Elt].len]
								capture[packetnumber][Dot11Elt].info = ssid_str
							else:
								capture[packetnumber][Dot11Elt].info = ssid_str
								capture[packetnumber][Dot11Elt].len = len(ssid_str)
							print "Set ssid:%s, len:%d."%(capture[packetnumber][Dot11Elt].info, capture[packetnumber][Dot11Elt].len)
						return capture[packetnumber], channel_str
					else:
						continue
				except ValueError:
					continue
	else:
		return False, False


def checkChannels(iface):
	hopList = [] # hopList clear

	print G+"----- check channels -----"+W
	for ch in channelList:
		check = True
		try:
			proc = Popen(['iw', 'dev', iface, 'set', 'channel', str(ch)], stdout=DN, stderr=PIPE)
		except:
			os.kill(os.getpid(),SIGINT)
			check = False
		for line in proc.communicate()[1].split('\n'):
			if len(line) > 2: # iw dev shouldnt display output unless there's an error
				check = False
			if check == True:
				hopList.append(ch)
	print 'Channel List: ' + str(hopList)

	return hopList


def setChannel(iface, channel):
	try:
		# Set Channel
		print G+"----- WiFi interface channel setting -----"+W
		print "channel = " + channel
		os.system("iw dev %s set channel %s" % (iface, channel))
		os.system("iwconfig %s" % iface)
		print ""
	except OSError as e:
		print "Could not create monitor %s" % iface
		os.kill(os.getpid(), SIGINT)
		sys.exit(1)



def runTestAP(wiface, iface):
	global apMACAddress, apIPAddress, clientList

	clientList = {}	# clear

	# Scan Beacon
	result = scanBeacon(wiface)
	if result[0]==False or result[1]==False:
#		print R+""+W
		return False

	baseBeaconPacket = result[0]
	channel = result[1]


	# start thread
	print "----- start thread sending beacon -----"
	print ""
	th1 = BeaconThread(wiface)
	beaconPacket = th1.makeBeaconPacket(apMACAddress, baseBeaconPacket, 0)
	if beaconPacket == False:
		return False
	th1.start()

	# start wired interface
	print "----- start thread wired interface -----"
	print ""
	eltPacket = beaconPacket.getlayer(Dot11Elt)
	th2 = WiredInterfaceThread(wiface, iface, clientList, apMACAddress, beaconPacket, eltPacket)
	th2.start()

	# start testap
	print "----- start thread testap -----"
	print ""
#	eltPacket = beaconPacket.getlayer(Dot11Elt)
	th3 = TestAPThread(wiface, iface, clientList, apMACAddress, apIPAddress, beaconPacket, eltPacket, th1)
	th3.start()

	raw_input(T+"Use anykey to exit."+"\n"+W)
	print ""

	# stop thread
	th3.stop()
	th2.stop()
	th1.stop()


def quit(wiface, status):
	if not os.path.isdir("/sys/class/net/" + wiface):
		print R+"WiFi interface %s does not exist! Cannot countinue!"%(wiface)+W
		exit(1)
	else:
		try:
			if status == 0:
				# WiFi interface down
				print G+"----- WiFi interface down -----"+W
				os.system("ip link set %s down" % wiface)
				print ""

				print G+"----- IP address del -----"+W
				os.system("ip addr del %s dev %s" % (apIPAddress_sub, wiface))
				print ""
			else:
				# WiFi interface up
				print G+"----- WiFi interface up -----"+W
				os.system("ip link set %s up" % wiface)
				print ""
			time.sleep(0.5)
			os.system("ip addr show dev %s" % wiface)
			print ""
		except OSError as e:
			print R+"Could not create monitor %s"%wiface+W
			os.kill(os.getpid(), signal.SIGINT)
			sys.exit(1)


def main():
	global apMACAddress, hopList

	# Check if OS is linux:
	print O+"##### OS Check #####"+W
	osCheck()

	# Check for root privileges
	print O+"##### Root Check #####"+W
	rootCheck()

	# Check argument
	print O+"##### Argument parser #####"+W
	argumentCheck()

	while True:
		print ''
		print C+'##########################################################################################'+W
		print C+'Init Interface           :'+W+'init'+W
		print C+'Get MAC Address          :'+W+'getmac'+W
		print C+'Change MAC Address       :'+W+'changemac'+W
		print C+'Check Channel            :'+W+'checkchannels'+W
		print C+'Set Channel              :'+W+'setchannel <channel number>'+W
		print C+'Run TestAP (OpenSystem)  :'+W+'runtestap'+W
		print ''
		print C+'Quit                     :'+W+'quit <interface down:0, up:1>'+W
		print C+'##########################################################################################'+W
		print ''

		command = raw_input(T+"Command > "+W).split()

		if 'init' in command:
			# Check if monitor device exits and mode change
			print O+"##### Init Wireless Interface #####"+W
			initWirelessInterface(wintfparent)

			# Get Wifi interface actual MAC address
			apMACAddress = getMAC(wintfparent)
			print ''

		elif 'getmac' in command:
			print O+"##### Get MAC Address #####"+W
			apMACAddress = getMAC(wintfparent)
			print ''

		elif 'changemac' in command:
			print O+"##### Change MAC Address #####"+W
			changeMAC(wintfparent)
			apMACAddress = getMAC(wintfparent)
			print ''

		elif 'checkchannels' in command:
			print O+'##### Check Channels #####'+W
			hopList = checkChannels(wintfparent)
			print ''

		elif 'setchannel' in command:
			if len(command) == 2:
				print O+'##### Set Channel #####'+W
				setChannel(wintfparent, command[1])
			else:
				print R+'Command error: setchannel <channel number>'+W
			print ''

		elif 'runtestap' in command:
			print O+'##### Run TestAP(OpenSystem) #####'+W
			if apMACAddress == '':
				changeMAC(wintfparent)
				apMACAddress = getMAC(wintfparent)
			runTestAP(wintfparent, intfparent)
			print ''

		# elif '' in command:
		# 	print O+'#####  #####'+W

		elif 'quit' in command:
			if len(command) == 2:
				print O+'##### Quit #####'+W
				quit(wintfparent, int(command[1]))
				sys.exit(0)
			else:
				print R+'Command error: quit <interface down:0, up:1>'+W
			print ''
		else:
			print R+'Command error: command mistake'+W
			print ''
			continue


################################################################################
main()
