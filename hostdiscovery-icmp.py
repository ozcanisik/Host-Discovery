from scapy.layers.inet import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Uyarı mesajını kapatmak için
ip_packet = IP()  # IP paketi oluşturduk
icmp_packet = ICMP()  # ICMP paketi oluşturduk

ping_packet = ip_packet/icmp_packet  # Burada da ikisini birleştirip ping paketi oluşturduk

address = input("Tarama yapılacak subneti giriniz (örn: (10.10.10.): ") # Tarama yapılacak subneti kullanıcıdan istedik

ipList = []

for i in range(11):  # Burada da tek tek ip adreslerine ping attık ve eğer cevap dönerse bunu listeye kaydettik
	ping_packet[IP].dst = address + str(i)
	response = sr1(ping_packet, timeout=0.5, verbose = False)
	if(response):
		ipList.append(ping_packet[IP].dst)
	else:
		pass

print(ipList)
