from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import ipaddress
import socket

def get_user_input():
    while True:
        target_ip = input("Taramak istediğiniz IP adresini veya IP aralığını girin (örn: 192.168.1.1 veya 192.168.1.1/24): ")

        try:
            ip_network = ipaddress.ip_network(target_ip, strict=False)
            break
        except ValueError:
            print("Geçersiz bir IP adresi veya IP aralığı girdiniz. Lütfen doğru bir formatta girin.")

    return str(ip_network)


def get_device_name(ip_address):
    try:
        host_name = socket.gethostbyaddr(ip_address) # IP adresinden DNS sorguları yaparak cihaz adını tespit etmeye çalışıyoruz
        return host_name
    except (socket.herror, socket.gaierror, socket.timeout): # Tespit edilemediği durumlarda bilinmiyor olarak return ediyoruz
        return "Bilinmiyor"


def arp_scan(target_ip):
    eth = Ether()  # Ethernet paketi
    arp = ARP()  # ARP paketi

    eth.dst = "ff:ff:ff:ff:ff:ff"  # ethernet destination mac adresi(broadcast)
    arp.pdst = target_ip  # arp destination için subnet
    broadcast_packet = eth / arp  # eth ve arp paketleri birleştirip bir broadcast paketi oluşturduk

    try:
        answered, unanswered = srp(broadcast_packet, timeout=2)  # paketleri srp(send and receive packet) metodu ile yolladık. Cevaplananlar ve cevaplanmayanları aldık

        print("ARP - Tarama Sonuçları:")
        for send, receive in answered:
            ip_address = receive.psrc
            mac_address = receive.src
            device_name = get_device_name(ip_address)
            print("IP: {}  MAC: {}  Device Name: {}".format(ip_address, mac_address, device_name)) # Çıktıları yazdırdık

    except Exception as e:
        print("Hata oluştu: {}".format(str(e)))

if __name__ == "__main__":
    try:
        target_ip = get_user_input()
        arp_scan(target_ip)
    except KeyboardInterrupt:
        print("Kullanıcı tarafından iptal edildi.")
