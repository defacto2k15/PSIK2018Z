#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os

from ryu.cmd import manager

#Skrypt pozwalający na uruchomienie ryu z kody pythonowego, a nie z linii poleceń
def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')
    sys.argv.append('ryuApp')  # nazwa pliku z klasą co obsuguje requesty
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    main()
