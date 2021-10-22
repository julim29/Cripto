#!/usr/bin/env python
import scapy.all as scapy
import argparse
import sys
#--------------------------------NETWORK_SCANNER.PY-------------------------------------------
# Funcionamiento : Funciona como un nmap, escanea los dispositivos conectados a nuestra red.
# Run : python network_scanner.py -t <IP o rango de IP>
# Ejemplo para escanear todos los dispositivos : python network_scanner.py -t 10.0.2.1/24
# A ver si se puede mejorar poniendo los tipos de dispositivo o algo pero no estoy seguro
#---------------------------------------------------------------------------------------------

#Recibe los argumentos
def get_argmuent():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip or ip range")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    return options

# ARP-ping. Return una lista <IP,MAC>
def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dic)

    return client_list

# Para print la lista en el terminal
def print_result(scan_list):
    print("IP\t\t\tMAC\n-----------------------------------------")
    if not scan_list:
        print("(No device found)")
    else:
        for client in scan_list:
            print(client["ip"] + "\t\t" + client["mac"])

options = get_argmuent()
result_list = scan(options.target)
print_result(result_list)
