#!/bin/bash
sudo iptables -A OUTPUT -m mark --mark 0x14 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1488
sudo iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1488
