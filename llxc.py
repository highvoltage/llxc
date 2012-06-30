#!/usr/bin/python3
""" LLXC Linux Containers"""

import argparse, os, sys, gettext

# Set up translations via gettext
gettext.textdomain("llxc")

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
    print (CYAN + "LLXC Linux Containers (llxc) \n\nUsage:" + NORMAL)
    print ("""    * llxc enter containername
    * llxc exec containername
    * llxc status containername
    * llxc stop containername
    * llxc start containername
    * llxc create containername
    * llxc destroy containername
    * llxc updatesshkeys
    * llxc gensshkeys
    """)
    print (CYAN + "Tips:" + NORMAL)
    print ("""    * Set environment variable llxcmono=1 to disable colours
    * llxc gensshkeys is usually run when the llxc package is installed
    * Tell your friends to use LXC!
    """)

def list():
    """Provides a list of LXC Containers"""
    print (CYAN + "  NAME \t\t TASKS \t STATUS \tIP_ADDR_ETH0" + NORMAL)
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
    if fileexists:
        print (containername + " is currently set to autostart")
        print ("disabling autostart...")
    else:
        print (containername + " is not currently set to autostart")
        print ("enabling autostart...")

def create():
    """Create LXC Container"""

def destroy():
    """Destroy LXC Container"""

def updatesshkeys():
    """Update Container SSH Keys"""

def gensshkeys():
    """Generate SSH Keys for use with LLXC"""

# Print help if no options are specified
if len(sys.argv) == 1:
    help()
