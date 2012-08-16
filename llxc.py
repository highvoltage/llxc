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

import argparse, os, sys, lxc, glob, gettext, time
from gettext import gettext as _

# Set up translations via gettext
gettext.textdomain("llxc")

parser = argparse.ArgumentParser(
         description=_("LLXC Linux Container Management"),
         formatter_class=argparse.RawTextHelpFormatter)

# Optional arguements
parser.add_argument("-if", "--interface", type=str, default="eth0",
    help=_("Ethernet Interface, eg: eth0, eth1"))
parser.add_argument("-ip", "--ipstack", type=str, default="ipv4",
    help=_("Network IP to list, ex: ipv4, ipv6"))

sp = parser.add_subparsers(help='sub command help')

parser_create = sp.add_parser('create', help='Create a container')
parser_create.add_argument('containername', type=str,
                           help='name of the container')

parser_destroy = sp.add_parser('destroy', help='Destroy a container')
parser_destroy.add_argument('containername', type=str,
                            help='name of the container')

parser_status = sp.add_parser('status', help='Display container status')
parser_status.add_argument('containername', type=str,
                           help='Name of the container')

parser_stop = sp.add_parser('stop', help='Stops a container')
parser_stop.add_argument('containername', type=str,
                         help='Name of the container')

parser_start = sp.add_parser('start', help='Starts a container')
parser_start.add_argument('containername', type=str,
                          help='Name of the container')

parser_toggleautostart = sp.add_parser('toggleautostart',
    help='Toggles the state of starting up on boot time for a container')
parser_toggleautostart.add_argument('containername', type=str,
                                    help='Name of the container')

parser_list = sp.add_parser('list', help='Displays a list of containers')

args = parser.parse_args()

try:
    containername = args.containername
except AttributeError:
    pass

#print("You chose to list the " + args.ipstack +
#      " address on " + args.interface)

# Set some variables
CONTAINER_PATH = "/var/lib/lxc/"
AUTOSTART_PATH = "/etc/lxc/auto/"
CGROUP_PATH = "/sys/fs/cgroup/"

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

def examples():
    """Prints LLXC Usage"""
    print ( "%sLLXC Linux Containers (llxc) \n\nExamples:%s"
            % (CYAN, NORMAL) )
    print ( """    * llxc enter containername
    * llxc exec containername
    * llxc status containername
    * llxc stop containername
    * llxc start containername
    * llxc create containername
    * llxc destroy containername
    * llxc toggleautostart containername
    * llxc -h
    """ )
    print ( "%sTips:%s" % (CYAN, NORMAL) )
    print ( """    * Set environment variable llxcmono=1 to disable colours
    * Type "llxc -h" for full command line usage 
    * llxc gensshkeys is usually run when the llxc package is installed
    * Tell your friends to use LXC!
    """ )

def list():
    """Provides a list of LXC Containers"""
    print ("%s  NAME \t\t TASKS \t   STATUS \tIP_ADDR_%s%s"
           % (CYAN, args.interface.swapcase(), NORMAL) )
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        containername = container.replace(CONTAINER_PATH,"").rstrip("/config")
        cont = lxc.Container(containername)
        try:
            ipaddress = cont.get_ips(protocol="ipv4",
                                     interface="eth0", timeout=0.1)
            ipaddress = ipaddress[0]
        except TypeError:
            ipaddress = "Unavailable"
        except IndexError:
            ipaddress = "Unavailable"
        try:
            tasks = sum(1 for line in open(CGROUP_PATH + "cpuset/lxc/" +
                        containername + "/tasks", 'r'))
        except IOError:
            tasks = "00"
        print ("  %s \t %s \t   %s \t%s" % (containername, tasks,
	       cont.state.swapcase(), ipaddress))

def status():
    """Prints a status report for specified container"""
    confirm_container_existance()
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
    requires_root()
    confirm_container_existance()
    print (" * Stopping %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.stop():
        print ("   %s%s sucessfully stopped%s" % (GREEN, containername, NORMAL))

def start():
    """Start LXC Container"""
    requires_root()
    print (" * Starting %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.start():
        print ("   %s%s sucessfully started%s" % (GREEN, containername, NORMAL))

def toggle_autostart():
    """Toggle autostart of LXC Container"""
    requires_root()
    confirm_container_existance()
    if os.path.lexists(AUTOSTART_PATH + containername):
        print ("%sInfo%s: %s was set to autostart on boot"
	       % (CYAN, NORMAL, containername) )
        print ("%sAction:%s disabling autostart for %s..."
               % (GREEN, NORMAL, containername) )
        os.unlink(AUTOSTART_PATH + containername)
    else:
        print ("%sInfo%s: %s was set to autostart on boot"
	       % (CYAN, NORMAL, containername) )
        print ("%sAction:%s enabling autostart for %s..."
               % (GREEN, NORMAL, containername) ) 
        os.symlink(CONTAINER_PATH + containername,
	           AUTOSTART_PATH + containername)

def create():
    """Create LXC Container"""
    requires_root()
    print ("Create " + containername)

def destroy():
    """Destroy LXC Container"""
    # TODO: Eventually we'll do everything from here, but for now,
    # we just call lxc-destroy externally
    requires_root()
    confirm_container_existance()
    if container_is_running():
        print (" * %sWARNING:%s Container is running, stopping before destroying in 10 seconds..." % (YELLOW, NORMAL))
        time.sleep(10)
        stop()
    print (" * Destroying container " + containername + "...")
    result = (os.popen("lxc-destroy -n " + containername).read())
    print ("   %s%s successfully destroyed %s" % (GREEN, containername, NORMAL))

# Tests

def requires_root():
    """Tests whether the user is root. Required for many functions"""
    if not os.getuid() == 0:
        print(_( "%sError 403:%s This function requires root. \
                 Further execution has been aborted." % (RED, NORMAL) ))
        sys.exit(403) 

def confirm_container_existance():
    """Checks whether specified container exists before execution."""
    try:
        if not os.path.exists(CONTAINER_PATH + containername):
            print (_( "%sError 404:%s That container (%s) could not be found."
                      % (RED, NORMAL, containername) ))
            sys.exit(404)
    except NameError:
        print (_( "%sError 400:%s You must specify a container."
                  % (RED, NORMAL) ))
        sys.exit(404)

def container_is_running():
    """Check whether a container is running."""
    if lxc.Container("mysql01").state == "RUNNING":
        return 1 
    else:
        return 0
# End tests

# Run functions
try:
    function = sys.argv[1]
    if function == "list":
        list()
    if function == "create":
        create()
    if function == "destroy":
        destroy()
    if function == "start":
        start()
    if function == "stop":
        stop()
    if function == "toggleautostart":
        toggle_autostart()
except IndexError:
    examples()
