#!/bin/sh

export IF_EXT="eth0"

export IPT="/sbin/iptables"
export IPT6="/sbin/ip6tables"


$IPT -F
$IPT -F -t nat
$IPT -F -t mangle
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X
$IPT6 --flush


$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT


$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP


echo 1 &gt; /proc/sys/net/ipv4/ip_forward


$IPT -t nat -A POSTROUTING -s 192.168.1.0/24 -j SNAT --to-source SERVERING IP ADRESI


$IPT -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A OUTPUT -p tcp ! --syn -m state --state NEW -j DROP


$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A FORWARD -m state --state INVALID -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $IF_EXT -p tcp --dport 22 -j ACCEPT
$IPT -A INPUT -i $IF_EXT -p tcp --dport 443 -j ACCEPT


$IPT -A FORWARD -s 192.168.1.0/24 -j ACCEPT
$IPT -A FORWARD -p all -m state --state ESTABLISHED,RELATED -j ACCEPT



$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


/sbin/iptables-save &gt; /etc/sysconfig/iptables
