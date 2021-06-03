import scapy.all as scapy
from scapy.contrib.lacp import SlowProtocol, LACP
from scapy.layers.inet import Ether, Dot3
from scapy.all import *

def scan(ip):

    pkt= Ether() / SlowProtocol() / LACP()
    unansw,answ=scapy.srp(pkt,timeout=1)
    запрашивает  в консоли
    print(unansw.summary())# пакеты без ответа

    print(answ.summary())# пакеты с ответом

    scapy.ls(scapy.LACP())

scan("10.0.2.1/24")

