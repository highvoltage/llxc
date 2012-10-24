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
import subprocess
import warnings

# For now we need to filter the warning that python3-lxc produces
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=Warning)
    import lxc

from gettext import gettext as _

# Set up translations via gettext
gettext.textdomain("llxc")

# Set Paths
CONTAINER_PATH = "/var/lib/lxc/"
AUTOSTART_PATH = "/etc/lxc/auto/"
CGROUP_PATH = "/sys/fs/cgroup/"
ARCHIVE_PATH = CONTAINER_PATH + ".archive/"
LLXCHOME_PATH = "/var/lib/llxc/"

# Other settings

# 5000 = 5 GiB
MIN_REQ_DISK_SPACE = 5000
KERNEL_VERSION = os.popen("uname -r").read().rstrip()

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
           % (CYAN, ARGS.interface.swapcase(), NORMAL)))
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

    cont = lxc.Container(CONTAINERNAME)

    # System Stuff:
    state = lxc.Container(CONTAINERNAME).state.swapcase()

    if os.path.lexists(AUTOSTART_PATH + CONTAINERNAME):
        autostart = "enabled"
    else:
        autostart = "disabled"

    lxcversion = os.popen("lxc-version | awk {'print $3'}").read()

    lxchost = os.popen("lsb_release -d | awk '{print $2, $3}'").read()

    try:
        tasks = sum(1 for line in open(CGROUP_PATH + "cpuset/lxc/" +
                    CONTAINERNAME + "/tasks", 'r'))
    except IOError:
        tasks = 0

    init_pid = lxc.Container(CONTAINERNAME).init_pid

    config_file = lxc.Container(CONTAINERNAME).config_file_name

    console_tty = cont.get_config_item('lxc.tty')

    # Memory Stuff:
    for line in open(CGROUP_PATH + "memory/lxc/" +
                     CONTAINERNAME + "/memory.stat", 'r'):
        if "total_swap" in line:
            swap_usage = (int(line.replace('total_swap ', '')) / 1000 / 1000)

    swappiness = open(CGROUP_PATH + "memory/lxc/" + CONTAINERNAME +
                      "/memory.swappiness", 'r').read()

    memusage = int(open(CGROUP_PATH + "memory/lxc/" + CONTAINERNAME +
                   "/memory.memsw.usage_in_bytes", 'r').read()) / 1000 / 1000

    # Currently Unsorted:
    lxcguest = "Not implemented"
    lxc.arch = cont.get_config_item('lxc.arch')
    lxc.tty = cont.get_config_item('lxc.tty')
    root_fs = cont.get_config_item('lxc.rootfs')
    cpu_set = open(CGROUP_PATH + "cpuset/lxc/" +
                   CONTAINERNAME + "/cpuset.cpus", 'r').read()

    print (_(CYAN + """\
    Status report for container:  """ + CONTAINERNAME + NORMAL + """
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
    """ % (lxcversion, lxchost, lxcguest, lxc.arch, config_file,
           console_tty,
           root_fs,
           memusage, swap_usage, swappiness,
           cpu_set,
           init_pid, autostart, state, tasks)))

    # Networking report:
    network_configurations = len(cont.network)
    count = 0
    while count < network_configurations:
        network_bridge = cont.network[count].link
        macaddress = cont.network[count].hwaddr
        count = count + 1

    ipaddress = cont.get_ips()

    try:
        ipaddress = cont.get_ips(protocol="ipv4",
                                 interface="eth0", timeout=0.5)
        ip4address = ipaddress[0]
    except TypeError:
        ip4address = "Unavailable"
    except IndexError:
        ip4address = "Unavailable"

    try:
        ipaddress = cont.get_ips(protocol="ipv6",
                                 interface="eth0", timeout=0.5)
        ip6address = ipaddress[0]
    except TypeError:
        ip6address = "Unavailable"
    except IndexError:
        ip6address = "Unavailable"

    print ("""                     NETWORKING:
         Network Configurations:  %s
              IPv4 eth0 Address:  %s
              IPv6 eth0 Address:  %s
                    MAC Address:  %s
                         Bridge:  %s
""" % (network_configurations, ip4address, ip6address, macaddress,
       network_bridge))

    print (_(CYAN + "    Tip: " + NORMAL +
           "'llxc status' is experimental and subject to behavioural change"))


def kill():
    """Force stop LXC container"""
    requires_root()
    print (_(" * Killing %s..." % (CONTAINERNAME)))
    requires_container_existance()
    cont = lxc.Container(CONTAINERNAME)
    if cont.stop():
        print (_("   %s%s sucessfully killed%s"
               % (GREEN, CONTAINERNAME, NORMAL)))


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


def start(CONTAINERNAME):
    """Start LXC Container"""
    requires_root()
    print (_(" * Starting %s..." % (CONTAINERNAME)))
    requires_network_bridge()
    requires_container_existance()
    cont = lxc.Container(CONTAINERNAME)
    if cont.start():
        print (_("   %s%s sucessfully started%s"
               % (GREEN, CONTAINERNAME, NORMAL)))


def halt(CONTAINERNAME):
    "Shut Down LXC Container"""
    requires_root()
    print (_(" * Shutting down %s..." % (CONTAINERNAME)))
    requires_container_existance()
    cont = lxc.Container(CONTAINERNAME)
    if cont.shutdown():
        print (_("   %s%s successfully shut down%s"
               % (GREEN, CONTAINERNAME, NORMAL)))


def freeze():
    """Freeze LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(CONTAINERNAME).state == "RUNNING":
        print (_(" * Freezing container: %s..." % (CONTAINERNAME)))
        cont = lxc.Container(CONTAINERNAME)
        if cont.freeze():
            print (_("    %scontainer successfully frozen%s"
                   % (GREEN, NORMAL)))
        else:
            print (_("    %sERROR:%s Something went wrong,"
                     " please check status."
                   % (RED, NORMAL)))
    else:
        print (_("   %sERROR:%s The container state is %s,\n"
               "          it needs to be in the 'RUNNING'"
               " state in order to be frozen."
                % (RED, NORMAL, lxc.Container(CONTAINERNAME).state)))


def unfreeze():
    """Unfreeze LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(CONTAINERNAME).state == "FROZEN":
        print (_(" * Unfreezing container: %s..." % (CONTAINERNAME)))
        cont = lxc.Container(CONTAINERNAME)
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
                % (RED, NORMAL, lxc.Container(CONTAINERNAME).state)))


def toggleautostart():
    """Toggle autostart of LXC Container"""
    requires_root()
    requires_container_existance()
    if os.path.lexists(AUTOSTART_PATH + CONTAINERNAME):
        print (_("   %saction:%s disabling autostart for %s..."
               % (GREEN, NORMAL, CONTAINERNAME)))
        os.unlink(AUTOSTART_PATH + CONTAINERNAME)
    else:
        print (_("   %saction:%s enabling autostart for %s..."
               % (GREEN, NORMAL, CONTAINERNAME)))
        os.symlink(CONTAINER_PATH + CONTAINERNAME,
                   AUTOSTART_PATH + CONTAINERNAME)


def create():
    """Create LXC Container"""
    requires_root()
    print (_(" * Creating container: %s..." % (CONTAINERNAME)))
    requires_container_nonexistance()
    requires_free_disk_space()
    cont = lxc.Container(CONTAINERNAME)
    if cont.create('ubuntu'):
        print (_("   %scontainer %s successfully created%s"
               % (GREEN, CONTAINERNAME, NORMAL)))
    else:
        print (_("   %sERROR:%s Something went wrong, please check status"
               % (RED, NORMAL)))
    toggleautostart()
    update_sshkeys()
    start()


def destroy():
    """Destroy LXC Container"""
    requires_root()
    requires_container_existance()
    if lxc.Container(CONTAINERNAME).state == "RUNNING":
        print (_(" * %sWARNING:%s Container is running, stopping before"
               " destroying in 10 seconds..."
               % (YELLOW, NORMAL)))
        time.sleep(10)
        kill()
    print (_(" * Destroying container " + CONTAINERNAME + "..."))
    cont = lxc.Container(CONTAINERNAME)
    if cont.destroy():
        print (_("   %s%s successfully destroyed %s"
               % (GREEN, CONTAINERNAME, NORMAL)))
    else:
        print (_("   %sERROR:%s Something went wrong, please check status"
               % (RED, NORMAL)))


def clone():
    """Clone LXC container"""
    requires_root()
    origcont = lxc.Container(CONTAINERNAME)
    if not origcont.defined:
        print ("   %serror 404:%s container %s does not exist"
               % (RED, NORMAL, CONTAINERNAME))
        sys.exit(404)
    cont = lxc.Container(ARGS.newCONTAINERNAME)
    if cont.defined:
        print ("   %serror:%s container %s already exists"
               % (RED, NORMAL, ARGS.CONTAINERNAME))
        sys.exit(1)
    print (_(" * Cloning %s in to %s..."
           % (CONTAINERNAME, ARGS.newCONTAINERNAME)))
    if cont.clone(CONTAINERNAME):
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
    print (_(" * Archiving container: %s..." % (CONTAINERNAME)))
    previous_path = os.getcwd()
    os.chdir(CONTAINER_PATH)
    tar = tarfile.open(ARCHIVE_PATH + CONTAINERNAME + ".tar.gz", "w:gz")
    tar.add(CONTAINERNAME)
    tar.close
    os.chdir(previous_path)
    print (_("   %scontainer archived in to %s%s.tar.gz%s"
           % (GREEN, CONTAINER_PATH, CONTAINERNAME, NORMAL)))
    print (_(" * Removing container path %s..."
           % (CONTAINER_PATH + CONTAINERNAME)))
    if is_path_on_btrfs(CONTAINER_PATH + CONTAINERNAME):
        print (_("   container is on btrfs, removing subvolume..."))
        os.popen("btrfs subvolume delete " + CONTAINERNAME + "/rootfs")
        # Stupid race conditions. There's a delay
        time.sleep(0.5)
    if os.path.isdir(CONTAINER_PATH + CONTAINERNAME):
        shutil.rmtree(CONTAINER_PATH + CONTAINERNAME)
    if os.path.lexists(AUTOSTART_PATH + CONTAINERNAME):
        print (_(" * Autostart was enabled for this container, disabling..."))
        os.remove(AUTOSTART_PATH + CONTAINERNAME)
    print (_("   %sarchiving operation complete%s"
           % (GREEN, NORMAL)))


def unarchive():
    """Unarchive LXC container"""
    print (_(" * Unarchiving container: %s..." % (CONTAINERNAME)))
    cont = lxc.Container(CONTAINERNAME)
    if cont.defined:
        print ("   %serror:%s a container by name %s already exists unarchived"
               % (RED, NORMAL, CONTAINERNAME))
        exit(1)
    requires_container_nonexistance()
    # If we're on btrfs we should create a subvolume
    if is_path_on_btrfs(CONTAINER_PATH):
        print ("   container path is on btrfs, creating subvolume...")
        os.popen("btrfs subvolume create " + CONTAINERNAME)
    previous_path = os.getcwd()
    os.chdir(CONTAINER_PATH)
    tar = tarfile.open(ARCHIVE_PATH + CONTAINERNAME + ".tar.gz", "r:gz")
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
        CONTAINERNAME = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(CONTAINERNAME).state.swapcase() == "stopped":
            start(CONTAINERNAME)


def runinall():
    """Runs a command in all containers"""
    requires_root()
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        global CONTAINERNAME
        CONTAINERNAME = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(CONTAINERNAME).state.swapcase() == "running":
            print (_(" * Executing %s in %s..." % (' '.join(ARGS.command),
                     CONTAINERNAME)))
            return_code = subprocess.call("ssh %s %s"
                          (CONTAINERNAME, ' '.join(ARGS.command)), shell=True)
            if not return_code == 0:
                print (_("    %swarning:%s last exit code in container: %s"
                         % (YELLOW, NORMAL, return_code)))

        else:
            print (_(" * %sWarning:%s Container %s not running, skipped..."
                     % (YELLOW, NORMAL, CONTAINERNAME)))


def haltall():
    """Halt all LXC containers"""
    requires_root()
    print (_(" * Halting all containers:"))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        CONTAINERNAME = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(CONTAINERNAME).state.swapcase() == "running":
            halt(CONTAINERNAME)


def killall():
    """Kill all LXC containers"""
    print (_(" * Killing all running containers:"))
    for container in glob.glob(CONTAINER_PATH + '*/config'):
        CONTAINERNAME = container.replace(CONTAINER_PATH, "").rstrip("/config")
        if lxc.Container(CONTAINERNAME).state.swapcase() == "running":
            kill(CONTAINERNAME)


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
    print (_(" * Executing '%s' in %s..." % (' '.join(ARGS.command),
                                             CONTAINERNAME)))
    return_code = subprocess.call("ssh %s %s"
                       % (CONTAINERNAME, ' '.join(ARGS.command)), shell=True)
    if not return_code == 0:
        print (_("    %swarning:%s last exit code in container: %s"
               % (YELLOW, NORMAL, return_code)))
    print (_("    %sexecution completed for container: %s...%s"
           % (GREEN, CONTAINERNAME, NORMAL)))


def enter():
    """Enter a container via SSH"""
    print (_(" * Entering container %s..." % (CONTAINERNAME)))
    return_code = subprocess.call("ssh %s -i %s"
                  % (CONTAINERNAME, LLXCHOME_PATH + "/ssh/container_rsa"),
                     shell=True)
    if not return_code == 0:
        print (_("    %swarning:%s last exit code in container: %s"
               % (YELLOW, NORMAL, return_code)))
    print (_("    %sexiting container: %s...%s"
           % (GREEN, CONTAINERNAME, NORMAL)))


def checkconfig():
    """Prints any information we can provide on the LXC Host system"""

    if not ARGS.configpath:
        configpath = "/boot/config-" + KERNEL_VERSION
    else:
        configpath = ARGS.configpath

    if not os.path.exists(configpath):
        print ("   %serror 404:%s the kernel config could not be found, "
               "please report a bug with your system info"
              % (RED, NORMAL))
        sys.exit(404)

    kernelconfig = open(configpath, 'r').read()

    def confcheck(configkey):
        """Checks whether a kernel module has been enabled as a built-in
        or a module"""
        if configkey + "=y" or configkey + "=m" in kernelconfig:
            return GREEN + "enabled" + NORMAL
        else:
            return RED + "disabled" + NORMAL

    def cgroupcheck(path):
        """Checks whether a CGROUP path exists"""
        if os.path.exists(CGROUP_PATH + path):
            return GREEN + "enabled" + NORMAL
        else:
            return RED + "disabled" + NORMAL

    print (_("LXC Kernel Config Report for: %s%s%s\n")
             % (CYAN, configpath, NORMAL))
    print (_("  NAMESPACES:"))
    print (_("    Namespaces: %s")
             % (confcheck('CONFIG_NAMESPACES')))
    print (_("    UTS name namespace: %s")
             % (confcheck('CONFIG_UTS_NS')))
    print (_("    IPS namespace: %s")
             % (confcheck('CONFIG_IPC_NS')))
    print (_("    PID namespace: %s")
             % (confcheck('CONFIG_PID_NS')))
    print (_("    User namespace: %s")
             % (confcheck('CONFIG_USER_NS')))
    print (_("    Network namespace: %s")
             % (confcheck('CONFIG_NET_NS')))
    print (_("    Multiple /dev/pts instances: %s")
             % (confcheck('DEVPTS_MULTIPLE_INSTANCES')))
    print (_("  CONTROL GROUPS:"))
    print (_("    Cgroup: %s")
             % (confcheck('CONFIG_CGROUPS')))
    print (_("    Cgroup clone_children flag: %s")
             % (cgroupcheck('/cpuset//cgroup.clone_children')))
    print (_("    Cgroup device: %s")
             % (confcheck('CONFIG_CGROUP_DEVICE')))
    print (_("    Cgroup sched: %s")
             % (confcheck('CONFIG_CGROUP_SCHED')))
    print (_("    Cgroup cpu account: %s")
             % (confcheck('CONFIG_CGROUP_CPUACCT')))
    print (_("    Cgroup memory controller: %s")
             % (confcheck('CONFIG_CGROUP_MEM_RES_CTLR')))
    print (_("    Cgroup cpuset: %s")
             % (confcheck('CONFIG_CPUSETS')))
    print (_("  MISC:"))
    print (_("    Veth pair device: %s")
             % (confcheck('CONFIG_VETH')))
    print (_("    Macvlan: %s")
             % (confcheck('CONFIG_MACVLAN')))
    print (_("    Vlan: %s")
             % (confcheck('CONFIG_VLAN_8021Q')))
    print (_("    File capabilities: %s")
             % (confcheck('CONFIG_SECURITY_FILE_CAPABILITIES')))


def printconfig():
    """Prints LXC Configuration"""
    # Currently unused here:
    #cont = lxc.Container(CONTAINERNAME)
    conffile = lxc.Container(CONTAINERNAME).config_file_name
    for line in open(conffile, 'r'):
        print (line)


def console():
    """Attaches to an LXC console"""
    requires_container_existance()
    print (_(" * Entering LXC Console: %s" % (CONTAINERNAME)))
    cont = lxc.Container(CONTAINERNAME)
    if cont.console():
        print (_("Detached from LXC console: %s" % (CONTAINERNAME)))
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
    if os.path.exists(CONTAINER_PATH + CONTAINERNAME):
        print (_("   %serror:%s That container already exists."
                 % (RED, NORMAL)))
        sys.exit(1)


def requires_network_bridge():
    """Prints an error message if container's network bridge is unavailable"""

    cont = lxc.Container(CONTAINERNAME)

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
        if not os.path.exists(CONTAINER_PATH + CONTAINERNAME):
            print (_("   %serror 404:%s That container (%s) "
                     "could not be found."
                      % (RED, NORMAL, CONTAINERNAME)))
            sys.exit(404)
    except NameError:
        print (_("   %serror 400:%s You must specify a container."
                  % (RED, NORMAL)))
        sys.exit(400)


def requires_free_disk_space():
    """Checks whether we have anough free disk space on the LXC partition
    before proceding."""
    # config is in: MIN_REQ_DISK_SPACE
    stat = os.statvfs(CONTAINER_PATH)
    free_space = stat.f_bsize * stat.f_bavail / 1000 / 1000
    # currently unused:
    #total_space = stat.f_blocks * stat.f_frsize / 1000 / 1000
    #used_space = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
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

PARSER = argparse.ArgumentParser(
         description=_("LLXC Linux Container Management"),
         formatter_class=argparse.RawTextHelpFormatter)

# Optional arguements

PARSER.add_argument("-if", "--interface", type=str, default="eth0",
                     help=_("Ethernet Interface, eg: eth0, eth1"))
PARSER.add_argument("-ip", "--ipstack", type=str, default="ipv4",
                     help=_("Network IP to list, ex: ipv4, ipv6"))

SP = PARSER.add_subparsers(help=_('sub command help'))

SP_CREATE = SP.add_parser('create', help=_('Create a container'))
SP_CREATE.add_argument('CONTAINERNAME', type=str,
                        help=_('name of the container'))
SP_CREATE.set_defaults(function=create)

SP_DESTROY = SP.add_parser('destroy', help='Destroy a container')
SP_DESTROY.add_argument('CONTAINERNAME', type=str,
                         help='name of the container')
SP_DESTROY.set_defaults(function=destroy)

SP_STATUS = SP.add_parser('status', help='Display container status')
SP_STATUS.add_argument('CONTAINERNAME', type=str,
                        help='Name of the container')
SP_STATUS.set_defaults(function=status)

SP_STOP = SP.add_parser('stop', help='Not used')
SP_STOP.add_argument('CONTAINERNAME', type=str,
                      help='Name of the container')
SP_STOP.set_defaults(function=stop)

SP_START = SP.add_parser('start', help='Starts a container')
SP_START.add_argument('CONTAINERNAME', type=str,
                       help='Name of the container')
SP_START.set_defaults(function=start)

SP_KILL = SP.add_parser('kill', help='Kills a container')
SP_KILL.add_argument('CONTAINERNAME', type=str,
                      help='Name of the container to be killed')
SP_KILL.set_defaults(function=kill)

SP_HALT = SP.add_parser('halt', help='Shuts down a container')
SP_HALT.add_argument('CONTAINERNAME', type=str,
                          help='Name of the container')
SP_HALT.set_defaults(function=halt(CONTAINERNAME))

SP_TOGGLEAUTOSTART = SP.add_parser('toggleautostart',
    help='Toggles the state of starting up on boot time for a container')
SP_TOGGLEAUTOSTART.add_argument('CONTAINERNAME', type=str,
                                    help='Name of the container')
SP_TOGGLEAUTOSTART.set_defaults(function=toggleautostart)

SP_FREEZE = SP.add_parser('freeze', help='Freezes a container')
SP_FREEZE.add_argument('CONTAINERNAME', type=str,
                          help='Name of the container')
SP_FREEZE.set_defaults(function=freeze)

SP_UNFREEZE = SP.add_parser('unfreeze', help='Unfreezes a container')
SP_UNFREEZE.add_argument('CONTAINERNAME', type=str,
                          help='Name of the container')
SP_UNFREEZE.set_defaults(function=unfreeze)

SP_LIST = SP.add_parser('list', help='Displays a list of containers')
SP_LIST.set_defaults(function=listing)

SP_CLONE = SP.add_parser('clone', help='Clone a container into a new one')
SP_CLONE.add_argument('CONTAINERNAME', type=str,
                       help='Name of the container to be cloned')
SP_CLONE.add_argument('newCONTAINERNAME', type=str,
                       help='Name of the new container to be created')
SP_CLONE.set_defaults(function=clone)

SP_ARCHIVE = SP.add_parser('archive', help='Archive a container')
SP_ARCHIVE.add_argument('CONTAINERNAME', type=str,
                        help="Name of the container to be archived")
SP_ARCHIVE.set_defaults(function=archive)

SP_UNARCHIVE = SP.add_parser('unarchive', help='Unarchive a container')
SP_UNARCHIVE.add_argument('CONTAINERNAME', type=str,
                        help="Name of the container to be unarchived")
SP_UNARCHIVE.set_defaults(function=unarchive)

SP_STARTALL = SP.add_parser('startall', help='Start all stopped containers')
SP_STARTALL.set_defaults(function=startall)

SP_HALTALL = SP.add_parser('haltall', help='Halt all started containers')
SP_HALTALL.set_defaults(function=haltall)

SP_KILLALL = SP.add_parser('killall', help='Kill all started containers')
SP_KILLALL.set_defaults(function=killall)

SP_GENSSHKEYS = SP.add_parser('gensshkeys', help='Generates new SSH keypair')
SP_GENSSHKEYS.set_defaults(function=gen_sshkeys)

SP_LISTARCHIVE = SP.add_parser('listarchive', help='List archived containers')
SP_LISTARCHIVE.set_defaults(function=listarchive)

SP_UPDATESSHKEYS = SP.add_parser('updatesshkeys', help='Update SSH public'
                                 'keys in containers')
SP_UPDATESSHKEYS.set_defaults(function=update_sshkeys)

SP_EXEC = SP.add_parser('exec', help='Execute a command in container via SSH')
SP_EXEC.add_argument('CONTAINERNAME', type=str,
                        help="Name of the container to execute command in")
SP_EXEC.add_argument('command', metavar='CMD', type=str, nargs='*',
                        help="Command to be executed")
SP_EXEC.set_defaults(function=execute)

SP_ENTER = SP.add_parser('enter', help='Log in to a container via SSH')
SP_ENTER.add_argument('CONTAINERNAME', type=str,
                        help="Name of the container to enter")
SP_ENTER.set_defaults(function=enter)

SP_CHECKCONFIG = SP.add_parser('checkconfig',
                               help='Print available checkconfig information')
SP_CHECKCONFIG.set_defaults(function=checkconfig)
SP_CHECKCONFIG.add_argument('configpath', type=str,
                            help="Name of kernel config to check")

SP_RUNINALL = SP.add_parser('runinall',
                            help='Run command in all containers')
SP_RUNINALL.set_defaults(function=runinall)
SP_RUNINALL.add_argument('command', metavar='CMD', type=str, nargs='*',
                         help="Command to be executed")

SP_PRINTCONFIG = SP.add_parser('printconfig',
                               help='Print LXC container configuration')
SP_PRINTCONFIG.set_defaults(function=printconfig)
SP_PRINTCONFIG.add_argument('CONTAINERNAME', type=str,
                            help="Name of the container to attach console")

SP_CONSOLE = SP.add_parser('console',
                           help='Enter LXC Console')
SP_CONSOLE.set_defaults(function=console)
SP_CONSOLE.add_argument('CONTAINERNAME', type=str,
                        help="Name of the container to attach console")

ARGS = PARSER.parse_args()

try:
    CONTAINERNAME = ARGS.CONTAINERNAME
except AttributeError:
    pass

# Run functions
try:
    ARGS.function()
except KeyboardInterrupt:
    print (_("\n   %sinfo:%s Aborting operation, at your request"
             % (CYAN, NORMAL)))
