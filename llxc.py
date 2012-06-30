#!/usr/bin/python3
"""LLXC Linux Containers"""

# Copyright (c) 2012 Jonathan Carter
# This file is released under the MIT/expat license.

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import argparse, os, sys, gettext
from gettext import gettext as _

# Set up translations via gettext
gettext.textdomain("llxc")
parser = argparse.ArgumentParser(
         description=_("LLXC Linux Container Script"),
         formatter_class=argparse.RawTextHelpFormatter)

# Optional arguements
parser.add_argument("--interface", type=str, default="eth0",
    help=_("Interface that you would like to list, ex: eth0, eth1"))
parser.add_argument("--ipstack", type=str, default="ipv4",
    help=_("Network IP to list, ex: ipv4, ipv6"))

# test arguments:
args = parser.parse_args()
#print("You chose to list the " + args.ipstack + " address on " + args.interface)

# Set some variables
CONTAINER_PATH = "/var/lib/lxc/"
AUTOSTART_PATH = "/etc/lxc/auto/"

# Set colours, unless llxcmono is set
try:
    os.environ['llxcmono']
    GRAY = RED = GREEN = YELLOW = BLUE = \
           PURPLE = CYAN = NORMAL = ""
except KeyError:
    GRAY   = "\033[1;30m"
    RED    = "\033[1;31m"
    GREEN  = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE   = "\033[1;34m"
    PURPLE = "\033[1;35m"
    CYAN   = "\033[1;36m"
    NORMAL = "\033[0m"

def help():
    """Prints LLXC Usage"""
    print ( "%sLLXC Linux Containers (llxc) \n\nUsage:%s" % (CYAN, NORMAL) )
    print ( """    * llxc enter containername
    * llxc exec containername
    * llxc status containername
    * llxc stop containername
    * llxc start containername
    * llxc create containername
    * llxc destroy containername
    * llxc updatesshkeys
    * llxc gensshkeys
    """ )
    print ( "%sTips:%s" % (CYAN,NORMAL) )
    print ( """    * Set environment variable llxcmono=1 to disable colours
    * llxc gensshkeys is usually run when the llxc package is installed
    * Tell your friends to use LXC!
    """ )

def list():
    """Provides a list of LXC Containers"""
    print ("%s  NAME \t\t TASKS \t STATUS \tIP_ADDR_ETH0%S" % (CYAN, NORMAL) )
    for VZ in "vzlist":
        print ("  aptcache01 \t 12 \t RUNNING \t172.17.1.119")

def status():
    """Prints a status report for specified container"""
    print (CYAN + """
    Status report for container:  """ + "container" + NORMAL + """
                    LXC Version:  %s
                       LXC Host:  %s
                     Disk Usage:  %s
                   Memory Usage:  %s
                     Swap Usage:  %s
                     Swappiness:  %s
         Autostart on host boot:  %s
                  Current state:  %s
              Running processes:  %s
    """ % ('lxcversion', 'lxchost', 'diskusage', 'memusage', 'swap', \
           'swappiness', 'autostart', 'state', 'runproc'))
    print (CYAN + "    Tip: " + NORMAL + \
           "'llxc status' is experimental and subject to behavioural change")

def stop():
    """Stop LXC Container"""

def start():
    """Start LXC Container"""

def toggleautostart():
    """Toggle autostart of LXC Container"""
    requiresroot()
    containername = "autostart01" # FIXME: must get this from command line
    if os.path.lexists(AUTOSTART_PATH + containername):
        print ("%sINFO%s: %s is currently set to autostart" % (CYAN, NORMAL, 'containername') )
        print ("%sACTION:%s disabling autostart..." % (GREEN, NORMAL) )
        os.unlink(AUTOSTART_PATH + containername)
    else:
        print ("%sINFO%s: %s is not currently set to autostart" % (CYAN, NORMAL, 'container') )
        print ("%sACTION:%s enabling autostart..." % (GREEN, NORMAL) ) 
        os.symlink(CONTAINER_PATH + containername, AUTOSTART_PATH + containername)

def create():
    """Create LXC Container"""

def destroy():
    """Destroy LXC Container"""

def updatesshkeys():
    """Update Container SSH Keys"""

def gensshkeys():
    """Generate SSH Keys for use with LLXC"""

# Tests

def requiresroot():
    """Tests whether the user is root. Required for many functions"""
    if not os.getuid() == 0:
        print(_( "%sError 403:%s This function requires root. Further execution has been aborted." % (RED, NORMAL) ))
        sys.exit(403) 

def confirm_container_existance():
    """Checks whether specified container exists before execution."""
    try:
        if checkifdir/var/lib/lxc/containerexists:
            print (_( "%sError 404:%s That container $CONTAINER could not be found." % (RED, NORMAL) ))
            sys.exit(404)
    except NameError:
        print (_( "%sError 400:%s You must specify a container." % (RED, NORMAL) ))
        sys.exit(404)

# Print help if no options are specified
if len(sys.argv) == 1:
    #status()
    #help()
    toggleautostart()
