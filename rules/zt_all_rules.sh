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

#!/bin/bash

echo "Applying ZT rules on DPSHV"

port_UP=$(ovs-vsctl get Interface DPSHV-eth2 ofport)
port_IED1=$(ovs-vsctl get Interface DPSHV-eth3 ofport)
port_IED2=$(ovs-vsctl get Interface DPSHV-eth4 ofport)

ovs-vsctl set-fail-mode DPSHV secure
ovs-ofctl -O OpenFlow13 del-flows DPSHV

ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=0,actions=drop"

# block IP/ARP
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=50,ip,in_port=$port_IED1,actions=drop"
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=50,ip,in_port=$port_IED2,actions=drop"
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=50,arp,actions=drop"

# GOOSE (IED1 publisher)
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=200,dl_type=0x88b8,in_port=$port_IED1,dl_src=b4:b1:5a:0a:b4:01,actions=output:$port_UP"
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=200,dl_type=0x88b8,in_port=$port_UP,actions=output:$port_IED1,output:$port_IED2"

# SV (IED2 publisher)
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=200,dl_type=0x88ba,in_port=$port_IED2,dl_src=b4:b1:5a:00:00:02,actions=output:$port_UP"
ovs-ofctl -O OpenFlow13 add-flow DPSHV "priority=200,dl_type=0x88ba,in_port=$port_UP,actions=output:$port_IED1,output:$port_IED2"

echo "ZT added to DPSHV"

#!/bin/bash

echo "Applying ZT rules on DPSMV"

port_UP=$(ovs-vsctl get Interface DPSMV-eth1 ofport)
port_IED3=$(ovs-vsctl get Interface DPSMV-eth2 ofport)
port_IED4=$(ovs-vsctl get Interface DPSMV-eth3 ofport)

ovs-vsctl set-fail-mode DPSMV secure
ovs-ofctl -O OpenFlow13 del-flows DPSMV

ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=0,actions=drop"

# block IP/ARP
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=50,ip,in_port=$port_IED3,actions=drop"
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=50,ip,in_port=$port_IED4,actions=drop"
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=50,arp,actions=drop"

# GOOSE (IED4 publisher)
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=200,dl_type=0x88b8,in_port=$port_IED4,dl_src=00:30:A7:00:00:04,actions=output:$port_UP"
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=200,dl_type=0x88b8,in_port=$port_UP,actions=output:$port_IED3,output:$port_IED4"

# SV (IED3 publisher)
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=200,dl_type=0x88ba,in_port=$port_IED3,dl_src=00:30:A7:00:00:03,actions=output:$port_UP"
ovs-ofctl -O OpenFlow13 add-flow DPSMV "priority=200,dl_type=0x88ba,in_port=$port_UP,actions=output:$port_IED3,output:$port_IED4"


echo "ZT added to DPSMV"

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
