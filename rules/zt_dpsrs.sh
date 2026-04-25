#!/bin/bash

echo "Applying ZT rules on DPSRS"

Port_GW=$(ovs-vsctl get Interface DPSRS-eth1 ofport)
Port_HV=$(ovs-vsctl get Interface DPSRS-eth2 ofport)
Port_MV=$(ovs-vsctl get Interface DPSRS-eth3 ofport)
Port_HMI=$(ovs-vsctl get Interface DPSRS-eth4 ofport)
Port_ATK=$(ovs-vsctl get Interface DPSRS-eth5 ofport)

ovs-vsctl set-fail-mode DPSRS secure

ovs-ofctl -O OpenFlow13 del-flows DPSRS

ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=0,actions=drop"

# Block attacker, can be enhanced? without many conditions? 
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=500,ip,in_port=$Port_ATK,dl_src=00:06:5B:00:00:66,nw_src=1.1.3.66,actions=drop"


# Notes 

#SV dl_dst = 01:0c:cd:01:00:01
# GOOSE dl_dst = 01:0c:cd:01:00:06


# EtherTypes
#GOOSE = 0x88b8
#SV = 0x88ba
# Publishers in SGSim found in python 
#GOOSE publishers IED1 (b4:b1:5a:0a:b4:01), IED4 (00:30:a7:00:00:04)
#SV publishers IED2 (b4:b1:5a:00:00:02), IED3 (00:30:a7:00:00:03)


# Goose to HMI 
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=260,dl_type=0x88b8,dl_dst=01:0c:cd:01:00:06,in_port=$Port_HV,dl_src=b4:b1:5a:0a:b4:01,actions=output:$Port_HMI"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=260,dl_type=0x88b8,dl_dst=01:0c:cd:01:00:06,in_port=$Port_MV,dl_src=00:30:a7:00:00:04,actions=output:$Port_HMI"

# SV to HMI
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=260,dl_type=0x88ba,dl_dst=01:0c:cd:01:00:01,in_port=$Port_HV,dl_src=b4:b1:5a:00:00:02,actions=output:$Port_HMI"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=260,dl_type=0x88ba,dl_dst=01:0c:cd:01:00:01,in_port=$Port_MV,dl_src=00:30:a7:00:00:03,actions=output:$Port_HMI"

#HMI > HV/MV
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=250,dl_type=0x88b8,dl_dst=01:0c:cd:01:00:06,in_port=$Port_HMI,actions=output:$Port_HV,output:$Port_MV"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=250,dl_type=0x88ba,dl_dst=01:0c:cd:01:00:01,in_port=$Port_HMI,actions=output:$Port_HV,output:$Port_MV"

# CONTROL and HMI via GW

ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=230,ip,nw_src=1.1.10.10,nw_dst=1.1.3.10,in_port=$Port_GW,actions=output:$Port_HMI"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=230,ip,nw_src=1.1.3.10,nw_dst=1.1.10.10,in_port=$Port_HMI,actions=output:$Port_GW"


# ARP (needed for IP)

ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=200,arp,in_port=$Port_HMI,actions=output:$Port_HV,output:$Port_MV,output:$Port_GW"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=200,arp,in_port=$Port_HV,actions=output:$Port_HMI"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=200,arp,in_port=$Port_MV,actions=output:$Port_HMI"
ovs-ofctl -O OpenFlow13 add-flow DPSRS "priority=200,arp,in_port=$Port_GW,actions=output:$Port_HMI"

echo "ZT added to DPSRS"
