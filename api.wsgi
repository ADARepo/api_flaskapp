#!/usr/bin/python3

import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/carebit/carebitenv/lib/python3.8/site-packages")
sys.path.append("/var/www/carebit/api")

from api import app as application