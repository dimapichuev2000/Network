from scapy.all import *
import re

def traffic_monitor_callback(pkt):
    global tmp, str_inf
    print("==============================Полученный пакет==============================")
    pkt.show()
    print("============================================================================")
    sniff_list=list(pkt)
    srt =str(sniff_list[0])
    inf=srt.split('\\')
    n=len(inf)
    print(inf)
    for i in range(n):
        if re.search(r'\b\w\w\wGet info//\b',inf[i]):
            print(inf[i])
            tmp=inf[i].split("//")
            str_inf=tmp[1]
    z=len(tmp[1])
    str_list=str_inf[:z-1]
    for elem in sniff_list:
        dst=elem[0].dst
        src = elem[0].src
        type = elem[0].type
    return str_list,dst,src,type













sniff(iface="Ethernet", stop_filter=traffic_monitor_callback, store=0, timeout=1000, filter="ether proto 0x8809")