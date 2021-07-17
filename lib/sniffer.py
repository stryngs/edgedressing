from Queue import Queue
from pyDot11 import *
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import EAPOL
from scapy.sendrecv import sniff
from threading import Thread

class Sniffer(object):
    """This is the highest level object in the library.

    It uses an instance of Handler as the processing engine
    for packets received from scapy's sniff() function.
    """

    def __init__(self, packethandler, args):
        self.packethandler = packethandler
        self.i = args.i
        self.shake = Handshake(args.wpa, args.essid, False)
        self.packethandler.shake = self.shake

    def sniff(self, q):
        """Target function for Queue (multithreading)"""
        sniff(iface = self.i, prn = lambda x: q.put(x), lfilter = lambda x: x[Dot11].type == 2, store = 0)


    def handler(self, q, m, pkt, args):
        """This function exists solely to reduce lines of code"""
        eType = self.shake.encDict.get(self.tgtMAC)

        ### ccmp || tkip
        encKey = None
        if eType == 'ccmp':
            encKey = self.shake.tgtInfo.get(self.tgtMAC)[1]
        elif eType == 'tkip':
            encKey = self.shake.tgtInfo.get(self.tgtMAC)[0]

        ## Deal with pyDot11 bug
        if encKey is not None:

            ## Decrypt
            self.packethandler.shake.origPkt, decodedPkt, self.packethandler.shake.PN = wpaDecrypt(encKey, pkt, eType, False)

            ## Process
            self.packethandler.process(m, decodedPkt, args)
        q.task_done()


    def threaded_sniff(self, args):
        """This starts a Queue which receives packets and processes them.

        It uses the Handler.process function.
        Call this function to begin actual sniffing + injection.

        Useful reminder:
            to-DS is:    1L (open) / 65L (crypted)
            from-DS is:  2L (open) /66L (crypted)
        """
        q = Queue()
        sniffer = Thread(target = self.sniff, args = (q,))
        sniffer.daemon = True
        sniffer.start()
        while True:
            try:

                ## Grab from the queue
                pkt = q.get(timeout = 1)

                ## Check for handshake
                if pkt.haslayer(EAPOL):
                    self.shake.eapolGrab(pkt)

                ## Check if we have the handshake
                elif pkt[Dot11].addr1 == args.bssid and pkt[Dot11].FCfield == 65:
                    self.tgtMAC = False

                    ## MAC verification
                    if pkt.addr1 in self.shake.availTgts:
                        self.tgtMAC = pkt.addr1
                    elif pkt.addr2 in self.shake.availTgts:
                        self.tgtMAC = pkt.addr2

                    ## Pass the packet
                    if self.tgtMAC:
                        self.handler(q, self.i, pkt, args)
            except Exception as E:
                print(E)
