#!/usr/bin/python3

import argparse
import os
import signal
import subprocess
import sys
from airpwn_ng.lib.core import Core
from airpwn_ng.lib.menu import Menu

if __name__ == '__main__':

    ## Menu creation
    menu = Menu()
    args = menu.parser.parse_args()

    ## Import airpwn-ng
    airPwn = Core(args)

    ## Signal handler
    signal_handler = airPwn.crtlC(args)
    signal.signal(signal.SIGINT, signal_handler)

    ## Launch
    airPwn.main()
