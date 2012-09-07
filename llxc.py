#!/usr/bin/env python3
"""LLXC Wrapper for LXC Container Managemenr"""

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

# The little perfectionist in me likes to keep this alphabetical.
import argparse
import glob
import gettext
import os
import sys
import time
import tarfile
import shutil
import warnings

# For now we need to filter the warning that python3-lxc produces
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=Warning)
    import lxc

from gettext import gettext as _
from subprocess import call

# Set up translations via gettext
gettext.textdomain("llxc")

# Set some variables
CONTAINER_PATH = "/var/lib/lxc/"
AUTOSTART_PATH = "/etc/lxc/auto/"
CGROUP_PATH = "/sys/fs/cgroup/"
ARCHIVE_PATH = CONTAINER_PATH + ".archive/"
LLXCHOME_PATH = "/var/lib/llxc/"
# 5000000000 = 5 GiB
MIN_REQ_DISK_SPACE = 5000000000

# Set colours, unless llxcmono is set
try:
    if os.environ['llxcmono']:
        GRAY = RED = GREEN = YELLOW = BLUE = \
        PURPLE = CYAN = NORMAL = ""
except KeyError:
    # Light Colour Scheme
    GRAY = "\033[1;30m"
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    PURPLE = "\033[1;35m"
    CYAN = "\033[1;36m"
    NORMAL = "\033[0m"


def listing():
    """Provides a list of LXC Containers"""
    print (_("%s   NAME \tTASKS \t   STATUS \tIP_ADDR_%s%s"
           % (CYAN, args.interface.swapcase(), NORMAL)))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        containername = container.replace(CONTAINER_PATH, "").rstrip("/config")
        cont = lxc.Container(containername)
        try:
            ipaddress = cont.get_ips(protocol="ipv4",
                                     interface="eth0", timeout=0.5)
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
        print (_("   %s \t %s \t   %s \t%s" % (containername, tasks,
               cont.state.swapcase(), ipaddress)))


def listarchive():
    """Print a list of archived containers"""
    print (_("    %sNAME \tSIZE \t     DATE%s" % (CYAN, NORMAL)))
    try:
        for container in glob.glob(ARCHIVE_PATH + '*tar.gz'):
            containername = container.replace(ARCHIVE_PATH,
                                              "").rstrip(".tar.gz")
            containersize = os.path.getsize(container)
            containerdate = time.ctime(os.path.getctime(container))
            print (_("    %s \t%.0f MiB\t     %s")
                   % (containername, containersize / 1000 / 1000,
                      containerdate))
    except IOError:
        print (_("    Error: Confirm that the archive directory exists"
               "and that it is accessable"))


def status():
    """Prints a status report for specified container"""
    requires_container_existance()

    cont = lxc.Container(containername)

    # System Stuff:
    state = lxc.Container(containername).state.swapcase()

    if os.path.lexists(AUTOSTART_PATH + containername):
        autostart = "enabled"
    else:
        autostart = "disabled"

    lxcversion = os.popen("lxc-version | awk {'print $3'}").read()

    lxchost = os.popen("lsb_release -d | awk '{print $2, $3}'").read()

    try:
        tasks = sum(1 for line in open(CGROUP_PATH + "cpuset/lxc/" +
                    containername + "/tasks", 'r'))
    except IOError:
        tasks = 0

    init_pid = lxc.Container(containername).init_pid

    config_file = lxc.Container(containername).config_file_name

    console_tty = cont.get_config_item('lxc.tty')

    # Memory Stuff:
    for line in open(CGROUP_PATH + "memory/lxc/" +
                     containername + "/memory.stat", 'r'):
        if "total_swap" in line:
            swap_usage = (int(line.replace('total_swap ', '')) / 1000 / 1000)

    swappiness = open(CGROUP_PATH + "memory/lxc/" + containername +
                      "/memory.swappiness", 'r').read()

    memusage = int(open(CGROUP_PATH + "memory/lxc/" + containername +
                   "/memory.memsw.usage_in_bytes", 'r').read()) / 1000 / 1000

    # Networking Stuff:
    # TODO: Should use the same loops here as in the require_network_bridge
    #       check

    if cont.get_config_item('lxc.network.link'):
        bridge_device = cont.get_config_item('lxc.network.link')
    else:
        bridge_device = "unknown"

    if cont.get_config_item('lxc.network.hwaddr'):
        macaddress = cont.get_config_item('lxc.network.hwaddr')
    else:
        macaddress = "unknown"

    ipaddress = cont.get_ips()

    try:
        ipaddress = cont.get_ips(protocol="ipv4",
                                 interface="eth0", timeout=0.5)
        ipaddress = ipaddress[0]
    except TypeError:
        ipaddress = "Unavailable"
    except IndexError:
        ipaddress = "Unavailable"

    # Currently Unsorted:
    lxcguest = "Not implemented"
    lxc.arch = cont.get_config_item('lxc.arch')
    lxc.tty = cont.get_config_item('lxc.tty')
    root_fs = cont.get_config_item('lxc.rootfs')
    cpu_set = open(CGROUP_PATH + "cpuset/lxc/" +
                   containername + "/cpuset.cpus", 'r').read()

    print (_(CYAN + """\
    Status report for container:  """ + containername + NORMAL + """
                         SYSTEM:
                    LXC Version:  %s\
                       LXC Host:  %s\
                      LXC Guest:  %s
             Guest Architecture:  %s
             Configuration File:  %s
                    Console TTY:  %s

                        STORAGE:
                Root Filesystem:  %s
                     Space Used:
                     Free Space:

                         MEMORY:
                   Memory Usage:  %.2f MiB
                     Swap Usage:  %.2f MiB
                     Swappiness:  %s\

                      PROCESSOR:
                        CPU Set:  %s\

                          STATE:
                       Init PID:  %s
         Autostart on host boot:  %s
                  Current state:  %s
              Running processes:  %s

                     NETWORKING:
                     IP Address:  %s
                    MAC Address:  %s
                         Bridge:  %s
    """ % (lxcversion, lxchost, lxcguest, lxc.arch, config_file,
           console_tty,
           root_fs,
           memusage, swap_usage, swappiness,
           cpu_set,
           init_pid, autostart, state, tasks,
           ipaddress, macaddress, bridge_device)))
    print (_(CYAN + "    Tip: " + NORMAL +
           "'llxc status' is experimental and subject to behavioural change"))


def kill():
    """Force stop LXC container"""
    requires_root()
    print (_(" * Killing %s..." % (containername)))
    requires_container_existance()
    cont = lxc.Container(containername)
    if cont.stop():
        print (_("   %s%s sucessfully killed%s"
               % (GREEN, containername, NORMAL)))


def stop():
    """Displays information about kill and halt"""
    print (_("\n"
           "    %sTIP:%s 'stop' is ambiguous, "
           "use one of the following instead:"
           "\n\n"
           "    halt: trigger a shut down in the"
           "container and safely shut down"
           "\n"
           "    kill: stop all processes running"
           "inside the container \n"
           % (CYAN, NORMAL)))


def start():
    """Start LXC Container"""
    requires_root()
    print (_(" * Starting %s..." % (containername)))
    requires_network_bridge()
    requires_container_existance()
    cont = lxc.Container(containername)
    if cont.start():
        print (_("   %s%s sucessfully started%s"
               % (GREEN, containername, NORMAL)))


def halt():
    "Shut Down LXC Container"""
    requires_root()
    print (_(" * Shutting down %s..." % (containername)))
    requires_container_existance()
    cont = lxc.Container(containername)
    if cont.shutdown():
        print (_("   %s%s successfully shut down%s"
               % (GREEN, containername, NORMAL)))


def freeze():
    """Freeze LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(containername).state == "RUNNING":
        print (_(" * Freezing container: %s..." % (containername)))
        cont = lxc.Container(containername)
        if cont.freeze():
            print (_("    %scontainer successfully frozen%s"
                   % (GREEN, NORMAL)))
        else:
            print (_("    %ERROR:% Something went wrong, please check status."
                   % (RED, NORMAL)))
    else:
        print (_("   %sERROR:%s The container state is %s,\n"
               "          it needs to be in the 'RUNNING'"
               " state in order to be frozen."
                % (RED, NORMAL, lxc.Container(containername).state)))


def unfreeze():
    """Unfreeze LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(containername).state == "FROZEN":
        print (_(" * Unfreezing container: %s..." % (containername)))
        cont = lxc.Container(containername)
        if cont.unfreeze():
            print (_("    %scontainer successfully unfrozen%s"
                   % (GREEN, NORMAL)))
        else:
            print (_("    %sERROR:%s Something went wrong, "
                     "please check status."
                   % (RED, NORMAL)))
    else:
        print (_("   %sERROR:%s The container state is %s,\n"
               "   it needs to be in the 'FROZEN' state in"
               "order to be unfrozen."
                % (RED, NORMAL, lxc.Container(containername).state)))


def toggleautostart():
    """Toggle autostart of LXC Container"""
    requires_root()
    requires_container_existance()
    if os.path.lexists(AUTOSTART_PATH + containername):
        print (_("   %saction:%s disabling autostart for %s..."
               % (GREEN, NORMAL, containername)))
        os.unlink(AUTOSTART_PATH + containername)
    else:
        print (_("   %saction:%s enabling autostart for %s..."
               % (GREEN, NORMAL, containername)))
        os.symlink(CONTAINER_PATH + containername,
                   AUTOSTART_PATH + containername)


def create():
    """Create LXC Container"""
    requires_root()
    print (_(" * Creating container: %s..." % (containername)))
    requires_container_nonexistance()
    requires_free_disk_space()
    cont = lxc.Container(containername)
    if cont.create('ubuntu'):
        print (_("   %scontainer %s successfully created%s"
               % (GREEN, containername, NORMAL)))
    else:
        print (_("   %ERROR:% Something went wrong, please check status"
               % (RED, NORMAL)))
    toggleautostart()
    update_sshkeys()
    start()


def destroy():
    """Destroy LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(containername).state == "RUNNING":
        print (_(" * %sWARNING:%s Container is running, stopping before"
               " destroying in 10 seconds..."
               % (YELLOW, NORMAL)))
        time.sleep(10)
        kill()
    print (_(" * Destroying container " + containername + "..."))
    cont = lxc.Container(containername)
    if cont.destroy():
        print (_("   %s%s successfully destroyed %s"
               % (GREEN, containername, NORMAL)))
    else:
        print (_("   %sERROR:%s Something went wrong, please check status"
               % (RED, NORMAL)))


def clone():
    """Clone LXC container"""
    #TODO: Confirm source container exists, destination one doesn't
    requires_root()
    cont = lxc.Container(args.newcontainername)
    print (_(" * Cloning %s in to %s..."
           % (containername, args.newcontainername)))
    if cont.clone(containername):
        print (_("   %scloning operation succeeded%s"
               % (GREEN, NORMAL)))
    else:
        print (_("   %serror:%s Something went wrong, "
               "please check list and status"
               % (RED, NORMAL)))


def archive():
    """Archive LXC container by tarring it up and removing it."""
    if not os.path.exists(ARCHIVE_PATH):
        os.path.mkdir(ARCHIVE_PATH)
    requires_root()
    requires_container_existance()
    halt()
    print (_(" * Archiving container: %s..." % (containername)))
    previous_path = os.getcwd()
    os.chdir(CONTAINER_PATH)
    tar = tarfile.open(ARCHIVE_PATH + containername + ".tar.gz", "w:gz")
    tar.add(containername)
    tar.close
    os.chdir(previous_path)
    print (_("   %scontainer archived in to %s%s.tar.gz%s"
           % (GREEN, CONTAINER_PATH, containername, NORMAL)))
    print (_(" * Removing container path %s..."
           % (CONTAINER_PATH + containername)))
    if os.path.isdir(CONTAINER_PATH + containername):
        shutil.rmtree(CONTAINER_PATH + containername)
    if os.path.lexists(AUTOSTART_PATH + containername):
        print (_(" * Autostart was enabled for this container, disabling..."))
        os.remove(AUTOSTART_PATH + containername)
    print (_("   %sarchiving operation complete%s"
           % (GREEN, NORMAL)))


def unarchive():
    """Unarchive LXC container"""
    #TODO: confirm container doesn't exist
    print (_(" * Unarchiving container: %s..." % (containername)))
    requires_container_nonexistance()
    previous_path = os.getcwd()
    os.chdir(CONTAINER_PATH)
    tar = tarfile.open(ARCHIVE_PATH + containername + ".tar.gz", "r:gz")
    tar.extractall()
    os.chdir(previous_path)
    print (_("   %stip:%s archive file not removed, container not started,\n"
           "        autostart not restored automatically."
           % (CYAN, NORMAL)))
    print (_("   %scontainer unarchived%s" % (GREEN, NORMAL)))


def startall():
    """Start all LXC containers"""
    requires_root()
    print (_(" * Starting all stopped containers:"))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        global containername
        containername = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(containername).state.swapcase() == "stopped":
            start()


def runinall():
    """Runs a command in all containers"""
    requires_root()
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        global containername
        containername = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(containername).state.swapcase() == "running":
            print (_(" * Executing %s in %s..." % (args.command,
                     containername)))
            return_code = call("ssh %s %s"
                               % (containername, args.command), shell=True)
            if not return_code == 0:
                print (_("    %swarning:%s last exit code in container: %s"
                         % (YELLOW, NORMAL, return_code)))

        else:
            print (_(" * %sWarning:%s Container %s not running, skipped..."
                     % (YELLOW, NORMAL, containername)))


def haltall():
    """Halt all LXC containers"""
    requires_root()
    print (_(" * Halting all containers:"))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        global containername
        containername = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(containername).state.swapcase() == "running":
            halt()


def killall():
    """Kill all LXC containers"""
    print (_(" * Killing all running containers:"))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        global containername
        containername = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(containername).state.swapcase() == "running":
            kill()


def gen_sshkeys():
    """Generate SSH keys to access containers with"""
    # m2crypto hasn't been ported to python3 yet
    # so for now we do it via shell
    print (_(" * Generating ssh keypair..."))
    if os.path.exists("/var/lib/llxc/ssh/container_rsa"):
        print (_("   %swarning:%s old keypair found, making a backup..."
                 % (YELLOW, NORMAL)))
        shutil.copy2("/var/lib/llxc/ssh/container_rsa",
                     "container_rsa.bak")
        shutil.copy2("/var/lib/llxc/ssh/container_rsa.pub",
                     "container_rsa.pub.bak")
    directory = os.path.dirname("/var/lib/llxc/ssh/")
    if not os.path.exists(directory):
        os.makedirs(directory)
    if os.popen("ssh-keygen -f %sssh/container_rsa -N ''"
                % (LLXCHOME_PATH)):
        print (_("   %skeypair generated%s" % (GREEN, NORMAL)))
    else:
        print (_("   %skeypair generation failed%s" % (RED, NORMAL)))


def update_sshkeys():
    """Update ssh keys in LXC containers"""
    print (_(" * Updating keys..."))
    # read public key file:
    pkey = open(LLXCHOME_PATH + "ssh/container_rsa.pub", "r")
    pkeydata = pkey.read()
    pkey.close()
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        containerpath = container.rstrip("/config")
        if not os.path.exists(containerpath + "/rootfs/root/.ssh"):
            os.makedirs(containerpath + "/rootfs/root/.ssh")
        # append public key to authorized_keys in container
        keypresent = False
        try:
            for publickey in open(containerpath +
                                  "/rootfs/root/.ssh/authorized_keys"):
                if pkeydata in publickey:
                    keypresent = True
        except IOError:
            pass
        if not keypresent:
            print (_("   %sinstalling key in container: %s%s"
                     % (GREEN, container.replace
                       (CONTAINER_PATH, "").rstrip("/config"), NORMAL)))
            fout = open(containerpath +
                        "/rootfs/root/.ssh/authorized_keys", "a+")
            fout.write(pkeydata)
            fout.close()


def execute():
    """Execute a command in a container via SSH"""
    #FIXME: There should be a way to exec commands without having
    #       to enclose it in ticks
    print (_(" * Executing '%s' in %s..." % (args.command, containername)))
    return_code = call("ssh %s %s"
                       % (containername, args.command), shell=True)
    if not return_code == 0:
        print (_("    %swarning:%s last exit code in container: %s"
               % (YELLOW, NORMAL, return_code)))
    print (_("    %sexecution completed for container: %s...%s"
           % (GREEN, containername, NORMAL)))


def enter():
    """Enter a container via SSH"""
    print (_(" * Entering container %s..." % (containername)))
    #print (os.popen("ssh %s" % (containername)).read())
    return_code = call("ssh %s" % (containername), shell=True)
    if not return_code == 0:
        print (_("    %swarning:%s last exit code in container: %s"
               % (YELLOW, NORMAL, return_code)))
    print (_("    %sexiting container: %s...%s"
           % (GREEN, containername, NORMAL)))


def diagnostics():
    """Prints any information we can provide on the LXC Host system"""
    # TODO: make the capability to use an external config filelike
    #       lxc-checkconfig
    print (_("LXC Diagnostics"))
    print (_("  NAMESPACES:"))
    print (_("    Namespaces: %s"))
    print (_("    Utsname namespace: %s"))
    print (_("    Ipc namespace: %s"))
    print (_("    Pid namespace: %s"))
    print (_("    User namespace: %s"))
    print (_("    Network namespace: %s"))
    print (_("    Multiple /dev/pts instances: %s"))
    print (_("  CONTROL GROUPS:"))
    print (_("    Cgroup: %s"))
    print (_("    Cgroup clone_children flag: %s"))
    print (_("    Cgroup device: %s"))
    print (_("    Cgroup sched: %s"))
    print (_("    Cgroup cpu account: %s"))
    print (_("    Cgroup memory controller: %s"))
    print (_("    Cgroup cpuset: %s"))
    print (_("  MISC:"))
    print (_("    Veth pair device: %s"))
    print (_("    Macvlan: %s"))
    print (_("    Vlan: %s"))
    print (_("    File capabilities: %s"))


def printconfig():
    """Prints LXC Configuration"""
    cont = lxc.Container(containername)
    conffile = lxc.Container(containername).config_file_name
    for line in open(conffile, 'r'):
        print (line)


def console():
    """Attaches to an LXC console"""
    requires_container_existance()
    print (_(" * Entering LXC Console: %s" % (containername)))
    cont = lxc.Container(containername)
    if cont.console():
        print (_("Detached from LXC console: %s" % (containername)))
    else:
        print (_("   %serror:%s please check status" % (RED, NORMAL)))


# Tests

def requires_root():
    """Tests whether the user is root. Required for many functions"""
    if not os.getuid() == 0:
        print (_("   %sERROR 403:%s This function requires root. \
                 Further execution has been aborted." % (RED, NORMAL)))
        sys.exit(403)


def requires_container_nonexistance():
    """Prints an error message if a container exists and exits"""
    if os.path.exists(CONTAINER_PATH + containername):
        print (_("   %serror:%s That container already exists."
                 % (RED, NORMAL)))
        sys.exit(1)


def requires_network_bridge():
    """Prints an error message if container's network bridge is unavailable"""

    cont = lxc.Container(containername)

    # How many cards are configured:
    network_configurations = len(cont.network)

    # Loop through them and check that they're at least kind of up
    count = 0
    while count < network_configurations:
        network_bridge = cont.network[count].link
        count = count + 1
        ifconfig_output = os.popen("ifconfig " + network_bridge)

        if "Device not found" in ifconfig_output:
            print (_("   %serror:%s The network device %s does not seem to be"
                   " available."
                   % (RED, NORMAL, network_bridge)))


def requires_container_existance():
    """Checks whether specified container exists before execution."""
    try:
        if not os.path.exists(CONTAINER_PATH + containername):
            print (_("   %serror 404:%s That container (%s) "
                     "could not be found."
                      % (RED, NORMAL, containername)))
            sys.exit(404)
    except NameError:
        print (_("   %serror 400:%s You must specify a container."
                  % (RED, NORMAL)))
        sys.exit(400)


def requires_free_disk_space():
    """Checks whether we have anough free disk space on the LXC partition"""
    """before proceding."""
    # config is in: MIN_REQ_DISK_SPACE
    stat = os.statvfs(CONTAINER_PATH)
    free_space = stat.f_bsize * stat.f_bavail / 1000 / 1000
    total_space = stat.f_blocks * stat.f_frsize / 1000 / 1000
    used_space = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
    if free_space <= MIN_REQ_DISK_SPACE:
        print (_("   %serror:%s Insuficcient available disk space: %.2f MiB"
               % (RED, NORMAL, free_space)))
        sys.exit(1)


def requires_free_memory():
    """Checkss memory status and warns if memory usage is high"""
    print (_("Not Implemented"))


def is_path_on_btrfs(path):
    """Check whether a path is on btrfs, returns true if it is"""
    btrfs_output = os.popen("btrfs filesystem df " + path).read()
    if "Data" in btrfs_output:
        return True
    else:
        return False


# Argument parsing

parser = argparse.ArgumentParser(
         description=_("LLXC Linux Container Management"),
         formatter_class=argparse.RawTextHelpFormatter)

# Optional arguements

parser.add_argument("-if", "--interface", type=str, default="eth0",
                     help=_("Ethernet Interface, eg: eth0, eth1"))
parser.add_argument("-ip", "--ipstack", type=str, default="ipv4",
                     help=_("Network IP to list, ex: ipv4, ipv6"))

sp = parser.add_subparsers(help=_('sub command help'))

sp_create = sp.add_parser('create', help=_('Create a container'))
sp_create.add_argument('containername', type=str,
                        help=_('name of the container'))
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

sp_gensshkeys = sp.add_parser('gensshkeys', help='Generates new SSH keypair')
sp_gensshkeys.set_defaults(function=gen_sshkeys)

sp_listarchive = sp.add_parser('listarchive', help='List archived containers')
sp_listarchive.set_defaults(function=listarchive)

sp_updatesshkeys = sp.add_parser('updatesshkeys', help='Update SSH public'
                                 'keys in containers')
sp_updatesshkeys.set_defaults(function=update_sshkeys)

sp_exec = sp.add_parser('exec', help='Execute a command in container via SSH')
sp_exec.add_argument('containername', type=str,
                        help="Name of the container to execute command in")
sp_exec.add_argument('command', type=str, nargs='?',
                        help="Command to be executed")
sp_exec.set_defaults(function=execute)

sp_enter = sp.add_parser('enter', help='Log in to a container via SSH')
sp_enter.add_argument('containername', type=str,
                        help="Name of the container to enter")
sp_enter.set_defaults(function=enter)

sp_diagnostics = sp.add_parser('diagnostics',
                               help='Print available diagnostics information')
sp_diagnostics.set_defaults(function=diagnostics)

sp_runinall = sp.add_parser('runinall',
                            help='Run command in all containers')
sp_runinall.set_defaults(function=runinall)
sp_runinall.add_argument('command', type=str, nargs='?',
                        help="Command to be executed")

sp_printconfig = sp.add_parser('printconfig',
                               help='Print LXC container configuration')
sp_printconfig.set_defaults(function=printconfig)
sp_printconfig.add_argument('containername', type=str,
                        help="Name of the container to attach console")

sp_console = sp.add_parser('console',
                           help='Enter LXC Console')
sp_console.set_defaults(function=console)
sp_console.add_argument('containername', type=str,
                        help="Name of the container to attach console")

args = parser.parse_args()

try:
    containername = args.containername
except AttributeError:
    pass

# Run functions
try:
    args.function()
except KeyboardInterrupt:
    print (_("\n   %sinfo:%s Aborting operation, at your request"
             % (CYAN, NORMAL)))
