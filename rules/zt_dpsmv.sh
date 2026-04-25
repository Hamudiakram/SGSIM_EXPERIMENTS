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
