#!/bin/bash
sudo iptables -D OUTPUT -m mark --mark 0x14 -j ACCEPT
sudo iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1488
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1488
