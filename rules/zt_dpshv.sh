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
