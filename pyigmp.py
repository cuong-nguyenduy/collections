"""
Creates IGMPv2 reports and sends out to the network on a specific interface.

This script uses scapy (https://github.com/secdev/scapy) module
"""
from scapy.utils import rdpcap
from scapy.contrib.igmp import IGMP


eth = Ether(dst='01:00:5e:00:00:fb', type=0x800)

ipoption = IPOption_Router_Alert(
    copy_flag=1,
    optclass='control',
    option='router_alert',
    length=4,alert='router_shall_examine_packet'
)

number_of_packets = 10000
for p in range(number_of_packets):
    hi = p // 256
    lo = p - 256*hi
    gaddr = "224.224." + str(hi) + "." + str(lo)
    ip = IP(
        version=4,
        proto=2,
        ttl=1,
        src='10.255.0.1',
        dst=gaddr,
        options=[ipoption]
    )

    igmp = IGMP(type=0x16, mrcode=0, gaddr=gaddr)

    pkt = eth / ip / igmp
    pkt[IGMP].igmpize()

    sendp(pkt, iface='ens33')  # interface on which the packets are sent out
