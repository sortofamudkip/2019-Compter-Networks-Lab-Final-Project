#!/bin/sh

sudo mn --custom ~/mnet/loopnet.py --topo=mytopo --mac --switch=ovsk,protocols=OpenFlow13 --controller remote
