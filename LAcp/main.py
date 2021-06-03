import time

import scapy.all as scapy
from scapy.layers.inet import Ether, Dot3
import pandas as pd
from scapy.contrib.lacp import SlowProtocol, LACP
from scapy.layers.l2 import LLC, SNAP, STP

k=0


# Генерация пакета
#dst- дистанейшен адрес

# pkt = Dot3(dst="01:00:0c:cc:cc:cd", src="08:17:35:51:29:2e") \
#     / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) \
#     / SNAP(OUI=0x0c, code=0x010b) \
#     / STP(rootid=8406, portid=0x802e, pathcost=19, rootmac="2c:33:11:53:85:80",bridgeid=32982, bridgemac="08:17:35:51:29:00", bpdutype=128) \
#     / data
#pkt = Ether(dst="01:00:0c:cc:cc:cd", src="08:17:35:51:29:2e") / SlowProtocol(subtype=1) / LACP(partner_state= 1)/data

#unansw,answ=scapy.srp(pkt,timeout=1)
#запрашивает  в консоли
#print(unansw.summary())# пакеты без ответа

#print(answ.summary())# пакеты с ответом


#
def scan(mac,data):
    """
          <Отправка пакетов LACP>
          :param mac: <MAC адрес>
          :param data: <Данные>
          :return tab_list <лист с нужными значениями >
          """
    pkt = Ether(dst=mac, src="08:17:35:51:29:2e") / SlowProtocol(subtype=1) / LACP( actor_state=61,partner_system_priority=1,partner_system=1)/data
    # actor_state = 61
    #scapy.srp(pkt) # отправка пакета LACP
    answ_list=scapy.srp(pkt,timeout=1,verbose=False)[0] # отправка и получение пакета LACP возвращает два значения в виде списка
    tab_list=[]
    #pkt.show()
    for elem in answ_list:
        tab_disc = {'dst': elem[0].dst, 'src':elem[0].src, 'subtype':elem[0].subtype, 'type':elem[0].type, 'data':elem[0].load}
        tab_list.append(tab_disc)
    return tab_list


def print_list(res_list):
    if(k==1):
        print("dst\t\t\t\t\tsrc\t\t\t\t\tsubtype\t\t\ttype\t\tdata\n----------------------------------------------------------------------------------------------------------")
        for elem2 in res_list:
         # print(elem2["dst"] + "\t\t" + elem2["src"] + elem2["type"] + "\t\t" + elem2["data"])
            print(elem2["dst"]+"\t"+elem2["src"]+ "\t" + str(elem2["subtype"]) + "\t\t\t\t" + str(elem2["type"])+ "\t\t" + str(elem2["data"]) )
    else:
        for elem2 in res_list:
         # print(elem2["dst"] + "\t\t" + elem2["src"] + elem2["type"] + "\t\t" + elem2["data"])
            print(elem2["dst"]+"\t"+elem2["src"]+ "\t" + str(elem2["subtype"]) + "\t\t\t\t" + str(elem2["type"])+ "\t\t" + str(elem2["data"]) )


for i in range(60):
    k=k+1
    scan_list = scan("01:00:0c:cc:cc:cd", ' ')
    print_list(scan_list)
    time.sleep(5)


#actor- SW2,  partner-SW1

#scapy.ls(IP)



