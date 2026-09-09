#!/usr/bin/env python3
"""Entry point for the wifiscanner Wi-Fi survey system.

Usage:  python3 main.py <command> [options]     (try: python3 main.py --help)
"""
import sys

from wifiscanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
