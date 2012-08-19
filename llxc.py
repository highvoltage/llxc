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

#print("You chose to list the " + args.ipstack +
#      " address on " + args.interface)

# Set some variables
CONTAINER_PATH = "/var/lib/lxc/"
AUTOSTART_PATH = "/etc/lxc/auto/"
CGROUP_PATH = "/sys/fs/cgroup/"

# Set colours, unless llxcmono is set
try:
    if os.environ['llxcmono']:
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
    * llxc start containername
    * llxc halt containername
    * llxc stop containername
    * llxc freeze containername
    * llxc unfreeze containername
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


def listing():
    """Provides a list of LXC Containers"""
    print ("%s   NAME \tTASKS \t   STATUS \tIP_ADDR_%s%s"
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
        print ("   %s \t %s \t   %s \t%s" % (containername, tasks,
	       cont.state.swapcase(), ipaddress))


def status():
    """Prints a status report for specified container"""
    # TODO: Add disk usage depending on LVM or plain directory
    # TODO: Add cpuset.cpu - show how many cpus are used
    confirm_container_existance()
    #cont = lxc.Container(containername)

    # gather some data
    state = lxc.Container(containername).state.swapcase()
    if os.path.lexists(AUTOSTART_PATH + containername):
        autostart = "enabled"
    else:
        autostart = "disabled"
    lxcversion = os.popen("lxc-version | awk {'print $3'}").read()
    #TODO: Add version to this line:
    lxchost = os.popen("lsb_release -d | awk '{print $2, $3}'").read()
    tasks = sum(1 for line in open(CGROUP_PATH + "cpuset/lxc/" +
                containername + "/tasks", 'r'))
    swappiness = open(CGROUP_PATH + "memory/lxc/" + containername + "/memory.swappiness",
                      'r').read()
    memusage = int(open(CGROUP_PATH + "memory/lxc/" + containername + "/memory.memsw.usage_in_bytes", 'r').read())/1000/1000
    # FIXME: Add swap usage
    # swapusage = open(CGROUP_PATH + "memory/lxc/" + containername + "/..."

    print (CYAN + """\
    Status report for container:  """ + containername + NORMAL + """
                         System:
                    LXC Version:  %s\
                       LXC Host:  %s\

                         Memory:
                   Memory Usage:  %s MiB
                     Swappiness:  %s\

                          State:
         Autostart on host boot:  %s
                  Current state:  %s
              Running processes:  %s
    """ % (lxcversion, lxchost, memusage, \
           swappiness, autostart, state, tasks))
    print (CYAN + "    Tip: " + NORMAL + \
           "'llxc status' is experimental and subject to behavioural change")


def kill():
    """Force stop LXC container"""
    requires_root()
    confirm_container_existance()
    print (" * Killing %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.stop():
        print ("   %s%s sucessfully killed%s"
               % (GREEN, containername, NORMAL))

def stop():
    """Displays information about kill and halt"""
    print ("\n"
           "    %sTIP:%s 'stop' is ambiguous, use one of the following instead:"
           "\n\n"
           "    halt: trigger a shut down in the container and safely shut down"
           "\n"
           "    kill: stop all processes running inside the container \n"
           % (CYAN, NORMAL))


def start():
    """Start LXC Container"""
    # TODO: confirm that networking (ie, lxcbr) is available before starting
    requires_root()
    confirm_container_existance()
    print (" * Starting %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.start():
        print ("   %s%s sucessfully started%s"
               % (GREEN, containername, NORMAL))


def halt():
    "Shut Down LXC Container"""
    requires_root()
    confirm_container_existance()
    print (" * Shutting down %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.shutdown():
        print ("   %s%s successfully shut down%s"
               % (GREEN, containername, NORMAL))


def freeze():
    """Freeze LXC Container"""
    requires_root()
    confirm_container_existance()
    if lxc.Container(containername).state == "RUNNING":
        print (" * Freezing container: %s..." % (containername))
        cont = lxc.Container(containername)
        if cont.freeze():
            print ("    %scontainer successfully frozen%s"
                   % (GREEN, NORMAL))
        else:
            print ("    %ERROR:% Something went wrong, please check status."
                   % (RED, NORMAL))
    else:
        print ("   %sERROR:%s The container state is %s,\n"
               "          it needs to be in the 'RUNNING'"
               " state in order to be frozen."
                % (RED, NORMAL, lxc.Container(containername).state))


def unfreeze():
    """Unfreeze LXC Container"""
    requires_root()
    confirm_container_existance()
    if lxc.Container(containername).state == "FROZEN":
        print (" * Unfreezing container: %s..." % (containername))
        cont = lxc.Container(containername)
        if cont.unfreeze():
            print ("    %scontainer successfully unfrozen%s"
                   % (GREEN, NORMAL))
        else:
            print ("    %sERROR:%s Something went wrong, please check status."
                   % (RED, NORMAL))
    else:
        print ("   %sERROR:%s The container state is %s,\n"
               "   it needs to be in the 'FROZEN' state in order to be unfrozen."
                % (RED, NORMAL, lxc.Container(containername).state))


def toggleautostart():
    """Toggle autostart of LXC Container"""
    requires_root()
    confirm_container_existance()
    if os.path.lexists(AUTOSTART_PATH + containername):
        print ("   %sINFO:%s %s was set to autostart on boot"
	       % (CYAN, NORMAL, containername) )
        print ("   %sACTION:%s disabling autostart for %s..."
               % (GREEN, NORMAL, containername) )
        os.unlink(AUTOSTART_PATH + containername)
    else:
        print ("   %sINFO%s: %s was unset to autostart on boot"
	       % (CYAN, NORMAL, containername) )
        print ("   %sACTION:%s enabling autostart for %s..."
               % (GREEN, NORMAL, containername) ) 
        os.symlink(CONTAINER_PATH + containername,
	           AUTOSTART_PATH + containername)

def create():
    """Create LXC Container"""
    requires_root()
    # TODO: check that container does not exist
    # TODO: check that we have suficient disk space on LXC partition first
    # TODO: warn at least if we're very low on memory or using a lot of swap
    print (" * Creating container: %s..." % (containername))
    cont = lxc.Container(containername)
    if cont.create('ubuntu'):
        print ("   %scontainer %s successfully created%s"
               % (GREEN, containername, NORMAL))
    else:
        print ("   %ERROR:% Something went wrong, please check status"
               % (RED, NORMAL))
    toggleautostart()
    start()


def destroy():
    """Destroy LXC Container"""
    requires_root()
    confirm_container_existance()
    if lxc.Container(containername).state == "RUNNING":
        print (" * %sWARNING:%s Container is running, stopping before"
               " destroying in 10 seconds..."
               % (YELLOW, NORMAL))
        time.sleep(10)
        stop()
    print (" * Destroying container " + containername + "...")
    cont = lxc.Container(containername)
    if cont.destroy():
        print ("   %s%s successfully destroyed %s"
               % (GREEN, containername, NORMAL))
    else:
        print ("   %sERROR:%s Something went wrong, please check status"
               % (RED, NORMAL))


def clone():
    """Clone LXC container"""
    requires_root()
    confirm_container_existance()
    cont = lxc.Container(containername)
    print (" * Cloning %s in to %s..." % (containername, "new container"))
    if cont.clone("newcont01"):
        print ("   %scloning operation succeeded")
    else:
         print ("   %sERROR:%s Something went wrong, please check status"
         % (RED, NORMAL))


def archive():
    """Archive LXC container by tarring it up and removing it."""
    requires_root()
    confirm_container_existance()
    print (" * Archiving container: %s..." % (containername))
    #tar -czf
    # rm container
    print ("   %scontainer archived in to %s%s.tar.gz%s"
            % (GREEN, CONTAINER_PATH, containername, NORMAL))


def unarchive():
    """Unarchive LXC container"""
    requires_root()
    #TODO: confirm container doesn't exist
    print (" * Unarchiving container: %s..." % (containername))
    # tar -xc in python
    # rm tarball
    print ("   %scontainer unarchived%s" % (GREEN, NORMAL))


def startall():
    """Start all LXC containers"""
    requires_root()
    print (" * Starting all containers...")
    # make a loop, if already if already started, skip
    print ("The following containers will be started:")


def haltall():
    """Halt all LXC containers"""
    requires_root()
    print (" * Halting all containers...")
    # make a loop, if already in stopped state, skip
    print ("The following containers will be halted:")

def killall():
    """Kill all LXC containers"""
    print ("Function not implemented")

# Tests

def requires_root():
    """Tests whether the user is root. Required for many functions"""
    if not os.getuid() == 0:
        print(_( "   %sERROR 403:%s This function requires root. \
                 Further execution has been aborted." % (RED, NORMAL) ))
        sys.exit(403) 


def confirm_container_existance():
    """Checks whether specified container exists before execution."""
    try:
        if not os.path.exists(CONTAINER_PATH + containername):
            print (_( "   %sERROR 404:%s That container (%s) could not be found."
                      % (RED, NORMAL, containername) ))
            sys.exit(404)
    except NameError:
        print (_( "   %sERROR 400:%s You must specify a container."
                  % (RED, NORMAL) ))
        sys.exit(404)


# Argument parsing

parser = argparse.ArgumentParser(
         description=_("LLXC Linux Container Management"),
         formatter_class=argparse.RawTextHelpFormatter)

# Optional arguements

parser.add_argument("-if", "--interface", type=str, default="eth0",
                     help=_("Ethernet Interface, eg: eth0, eth1"))
parser.add_argument("-ip", "--ipstack", type=str, default="ipv4",
                     help=_("Network IP to list, ex: ipv4, ipv6"))

sp = parser.add_subparsers(help='sub command help')

sp_create = sp.add_parser('create', help='Create a container')
sp_create.add_argument('containername', type=str,
                        help='name of the container')
sp_create.set_defaults(function=create)

sp_destroy = sp.add_parser('destroy', help='Destroy a container')
sp_destroy.add_argument('containername', type=str,
                         help='name of the container')
sp_destroy.set_defaults(function=destroy)

sp_status = sp.add_parser('status', help='Display container status')
sp_status.add_argument('containername', type=str,
                        help='Name of the container')
sp_status.set_defaults(function=status)

sp_stop = sp.add_parser('stop', help='Not used')
sp_stop.add_argument('containername', type=str,
                      help='Name of the container')
sp_stop.set_defaults(function=stop)

sp_start = sp.add_parser('start', help='Starts a container')
sp_start.add_argument('containername', type=str,
                       help='Name of the container')
sp_start.set_defaults(function=start)

sp_kill = sp.add_parser('kill', help='Kills a container')
sp_kill.add_argument('containername', type=str,
                      help='Name of the container to be killed')
sp_kill.set_defaults(function=kill)


sp_halt = sp.add_parser('halt', help='Shuts down a container')
sp_halt.add_argument('containername', type=str,
                          help='Name of the container')
sp_halt.set_defaults(function=halt)

sp_toggleautostart = sp.add_parser('toggleautostart',
    help='Toggles the state of starting up on boot time for a container')
sp_toggleautostart.add_argument('containername', type=str,
                                    help='Name of the container')
sp_toggleautostart.set_defaults(function=toggleautostart)

sp_freeze = sp.add_parser('freeze', help='Freezes a container')
sp_freeze.add_argument('containername', type=str,
                          help='Name of the container')
sp_freeze.set_defaults(function=freeze)

sp_unfreeze = sp.add_parser('unfreeze', help='Unfreezes a container')
sp_unfreeze.add_argument('containername', type=str,
                          help='Name of the container')
sp_unfreeze.set_defaults(function=unfreeze)

sp_list = sp.add_parser('list', help='Displays a list of containers')
sp_list.set_defaults(function=listing)

sp_clone = sp.add_parser('clone', help='Clone a container into a new one')
sp_clone.add_argument('containername', type=str,
                       help='Name of the container to be cloned')
sp_clone.add_argument('newcontainername', type=str,
                       help='Name of the new container to be created')
sp_clone.set_defaults(function=clone)

sp_archive = sp.add_parser('archive', help='Archive a container')
sp_archive.add_argument('containername', type=str,
                        help="Name of the container to be archived")
sp_archive.set_defaults(function=archive)

sp_unarchive = sp.add_parser('unarchive', help='Unarchive a container')
sp_unarchive.add_argument('containername', type=str,
                        help="Name of the container to be unarchived")
sp_unarchive.set_defaults(function=unarchive)

sp_startall = sp.add_parser('startall', help='Start all stopped containers')
sp_startall.set_defaults(function=startall)

sp_haltall = sp.add_parser('haltall', help='Halt all started containers')
sp_haltall.set_defaults(function=haltall)

sp_killall = sp.add_parser('killall', help='Kill all started containers')
sp_killall.set_defaults(function=killall)

args = parser.parse_args()

try:
    containername = args.containername
except AttributeError:
    pass

# Run functions
try:
    args.function()
except KeyboardInterrupt:
    print ("\n   %sINFO:%s Aborting operation, at your request"
           % (CYAN, NORMAL))
