#!/bin/bash

echo "Applying ZT rules on DPSGW"

Port_CC=$(ovs-vsctl get Interface DPSGW-eth2 ofport)   # to CONTROLSW / CONTROL side
Port_DPS=$(ovs-vsctl get Interface DPSGW-eth3 ofport)  # DPSRS substation side


ovs-vsctl set-fail-mode DPSGW secure

ovs-ofctl -O OpenFlow13 del-flows DPSGW

ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=0,actions=drop"

#block IEC 61850 GOOSE/SV
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=400,dl_type=0x88b8,actions=drop"  #gOOSE
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=400,dl_type=0x88ba,actions=drop"  #SV

# Allow ARP (needed for IP to work)
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=200,arp,in_port=$Port_CC,actions=output:$Port_DPS"
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=200,arp,in_port=$Port_DPS,actions=output:$Port_CC"

#only ping, can be changed to ip instead of icmp 
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=230,icmp,nw_src=1.1.10.10,nw_dst=1.1.3.10,in_port=$Port_CC,actions=output:$Port_DPS"
ovs-ofctl -O OpenFlow13 add-flow DPSGW "priority=230,icmp,nw_src=1.1.3.10,nw_dst=1.1.10.10,in_port=$Port_DPS,actions=output:$Port_CC"


echo "ZT added to DPSGW"
