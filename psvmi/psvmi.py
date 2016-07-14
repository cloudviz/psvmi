import _psvmi as cext
from collections import namedtuple
import socket
import re
import os
import signal

suser = namedtuple('suser', ['name', 'terminal', 'host', 'started'])
sconn = namedtuple('sconn', ['fd', 'family', 'type', 'laddr', 'raddr',
                             'status', 'pid'])
sysinfo = namedtuple('OSFeature', ["boottime", "ipaddr", "osdistro",
                                   "osname", "osplatform", "osrelease",
                                   "ostype", "osversion", "memory_used",
                                   "memory_buffered", "memory_cached",
                                   "memory_free"])


class pconn(
    namedtuple('pconn',
               ['fd', 'family', 'type', 'laddr', 'raddr', 'status'])):
    __slots__ = ()

    @property
    def local_address(self):
        return self.laddr

    @property
    def remote_address(self):
        return self.raddr

qemuVM = namedtuple('qemuVM', ['memDumpFile', 'numMemChunks',
                               'qemuPid', 'qemuVaStart',
                               'qemuVaEnd', 'startMemAddr',
                               'memSize'])

# --- namedtuples for psutil.Process methods

# psutil.Process.memory_info()
pmem = namedtuple('pmem', ['rss', 'vms'])
# psutil.Process.cpu_times()
pcputimes = namedtuple('pcputimes', ['user', 'system'])
# psutil.Process.open_files()
popenfile = namedtuple('popenfile', ['path', 'fd'])
# psutil.Process.threads()
pthread = namedtuple('pthread', ['id', 'user_time', 'system_time'])
# psutil.Process.uids()
puids = namedtuple('puids', ['real', 'effective', 'saved'])
# psutil.Process.gids()
pgids = namedtuple('pgids', ['real', 'effective', 'saved'])
# psutil.Process.io_counters()
pio = namedtuple('pio', ['read_count', 'write_count',
                         'read_bytes', 'write_bytes'])


class Connections:

    def __init__(self):
        tcp4 = ("tcp", socket.AF_INET, socket.SOCK_STREAM)
        tcp6 = ("tcp6", socket.AF_INET6, socket.SOCK_STREAM)
        udp4 = ("udp", socket.AF_INET, socket.SOCK_DGRAM)
        udp6 = ("udp6", socket.AF_INET6, socket.SOCK_DGRAM)
        unix = ("unix", socket.AF_UNIX, None)
        self.tmap = {
            "all": (tcp4, tcp6, udp4, udp6, unix),
            "tcp": (tcp4, tcp6),
            "tcp4": (tcp4,),
            "tcp6": (tcp6,),
            "udp": (udp4, udp6),
            "udp4": (udp4,),
            "udp6": (udp6,),
            "unix": (unix,),
            "inet": (tcp4, tcp6, udp4, udp6),
            "inet4": (tcp4, udp4),
            "inet6": (tcp6, udp6),
        }

    def decode_address(self, addr, family):
        """Accept an "ip:port" address as displayed in /proc/net/*
        and convert it into a human readable form, like:

        "0500000A:0016" -> ("10.0.0.5", 22)
        "0000000000000000FFFF00000100007F:9E49" -> ("::ffff:127.0.0.1", 40521)

        The IP address portion is a little or big endian four-byte
        hexadecimal number; that is, the least significant byte is listed
        first, so we need to reverse the order of the bytes to convert it
        to an IP address.
        The port is represented as a two-byte hexadecimal number.

        Reference:
        http://linuxdevcenter.com/pub/a/linux/2000/11/16/LinuxAdmin.html
        """
        ip, port = addr.split(':')
        port = int(port, 16)
        # this usually refers to a local socket in listen mode with
        # no end-points connected
        if not port:
            return ()
        if PY3:
            ip = ip.encode('ascii')
        if family == socket.AF_INET:
            # see: https://github.com/giampaolo/psutil/issues/201
            if sys.byteorder == 'little':
                ip = socket.inet_ntop(family, base64.b16decode(ip)[::-1])
            else:
                ip = socket.inet_ntop(family, base64.b16decode(ip))
        else:  # IPv6
            # old version - let's keep it, just in case...
            # ip = ip.decode('hex')
            # return socket.inet_ntop(socket.AF_INET6,
            #          ''.join(ip[i:i+4][::-1] for i in xrange(0, 16, 4)))
            ip = base64.b16decode(ip)
            # see: https://github.com/giampaolo/psutil/issues/201
            if sys.byteorder == 'little':
                ip = socket.inet_ntop(
                    socket.AF_INET6,
                    struct.pack('>4I', *struct.unpack('<4I', ip)))
            else:
                ip = socket.inet_ntop(
                    socket.AF_INET6,
                    struct.pack('<4I', *struct.unpack('<4I', ip)))
        return (ip, port)


def qemu_vm_info(qemu_instance=None, qemuPid=None):
    if not qemu_instance and not qemuPid:
        raise TypeError("Need to specify a qemu instance pid.")

    if not qemuPid:
        raise NotImplementedError("We only support PIDs")

    if not qemuPid:
        raise Exception("Could not find the VM.")

    with open("/proc/" + qemuPid + "/maps") as f:
        for line in f:
            line = line.split()[0].split('-')
            qemuVaStart = int(line[0], 16)
            qemuVaEnd = int(line[1], 16)
            size = qemuVaEnd - qemuVaStart
            if (size > 500000000):
                break

    '''
    XXX
    Ideally we should be getting the size from virsh or libvirt and then
    get the memory region that matches that size. Here we are doing the
    opposite.
    '''
    memSize = str(size)  # in Bytes
    numMemChunks = "1"
    startMemAddr = "0"
    return qemuVM("none", numMemChunks, qemuPid,
                  "%d" % qemuVaStart, "%d" % qemuVaEnd,
                  startMemAddr, memSize)


def kernel_sysmaps(kernel_version, distro="ubuntu", arch="x86_64"):
    systemMapFile = "maps/" + distro
    systemMapFile += "/" + arch + "/System.map-" + kernel_version

    mapDir = {}
    with open(systemMapFile) as f:
        for line in f:
            if line:
                (val, _, key) = line.split()
                mapDir[key] = val

    began = False
    maps = []
    with open("header.h") as f:
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue
            if line[:-1] == "START_SYSMAP":
                began = True
            if line == "END_SYSMAP":
                break
            if not began:
                continue
            offset = line[:-1].lower()
            if offset in mapDir.keys():
                maps.append(mapDir[offset])
            else:
                maps.append("-1")
    return maps


def kernel_offsets(kernel_version, distro="ubuntu", arch="x86_64"):
    offsetFile = "offsets/" + distro
    offsetFile += "/" + arch + "/offsets_" + kernel_version

    offsetDir = {}
    with open(offsetFile) as f:
        for line in f:
            (key, val) = line.split()
            offsetDir[key] = val

    began = False
    offsets = []
    with open("header.h") as f:
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue
            if line[:-1] == "START_OFFSETS":
                began = True
            if line == "END_OFFSETS":
                break
            if not began:
                continue
            offset = line[:-1]
            if offset in offsetDir.keys():
                offsets.append(offsetDir[offset])
            else:
                offsets.append("-1")
    return offsets


def get_supported_kernel(version, arch="x86_64"):
    for dirpath, subdirs, files in os.walk("offsets/"):
        for f in files:
            if version in f:
                kernel = f.replace("offsets_", "")
                arch = dirpath.split('/')[-1]
                distro = dirpath.split('/')[-2]
                keyword = version
                return [arch, distro, kernel]
    return [None, None, None]


def system_info(qemu_instance=None, qemu_pid=None, kernel_version=None,
                distro="ubuntu", arch="x86_64"):
    vm = qemu_vm_info(qemu_instance, qemu_pid)
    sysmaps = kernel_sysmaps(kernel_version, distro, arch)
    offsets = kernel_offsets(kernel_version, distro, arch)
    try:
        sys = sysinfo._make(cext.system_info(vm.memDumpFile, vm.numMemChunks,
                                             vm.qemuPid, vm.qemuVaStart,
                                             vm.qemuVaEnd, vm.startMemAddr,
                                             vm.memSize, sysmaps, offsets))
    except Exception, e:
        print("Calling system_info for %s failed with: \"%s\". Most likely "
              "this is not the correct kernel." % (qemu_instance, e))
        return None
    return sys


class Error(Exception):
    """Base exception class. All other psutil exceptions inherit
    from this one.
    """


class NoSuchProcess(Error):
    """Exception raised when a process with a certain PID doesn't
    or no longer exists (zombie).
    """

    def __init__(self, pid, name=None, msg=None):
        Error.__init__(self)
        self.pid = pid
        self.name = name
        self.msg = msg
        if msg is None:
            if name:
                details = "(pid=%s, name=%s)" % (self.pid, repr(self.name))
            else:
                details = "(pid=%s)" % self.pid
            self.msg = "process no longer exists " + details

    def __str__(self):
        return self.msg


class AccessDenied(Error):
    """Exception raised when permission to perform an action is denied."""

    def __init__(self, pid=None, name=None, msg=None):
        Error.__init__(self)
        self.pid = pid
        self.name = name
        self.msg = msg
        if msg is None:
            if (pid is not None) and (name is not None):
                self.msg = "(pid=%s, name=%s)" % (pid, repr(name))
            elif (pid is not None):
                self.msg = "(pid=%s)" % self.pid
            else:
                self.msg = ""

    def __str__(self):
        return self.msg


# https://code.google.com/p/psutil/source/browse/psutil/__init__.py
class Process(object):

    def __init__(self, pid=None, name=None, cmdline=None, exe=None,
                 create_time=None, cwd=None, ppid=None,
                 username=None, connections=[], openfiles=[]):
        self._pid = pid
        self._name = name
        self._exe = exe
        self._create_time = create_time
        self._gone = False
        self._hash = None
        self._ppid = ppid
        self._cmdline = cmdline
        self._cwd = cwd
        self._openfiles = openfiles
        self._username = username
        self._connections = connections
        self._last_sys_cpu_times = None
        self._last_proc_cpu_times = None
        self._ident = (self.pid, self._create_time)
        self._status = 'running'

    def __str__(self):
        try:
            pid = self.pid
            name = repr(self.name())
        except NoSuchProcess:
            details = "(pid=%s (terminated))" % self.pid
        except AccessDenied:
            details = "(pid=%s)" % (self.pid)
        else:
            details = "(pid=%s, name=%s)" % (pid, name)
        return "%s.%s%s" % (self.__class__.__module__,
                            self.__class__.__name__, details)

    def __repr__(self):
        return "<%s at %s>" % (self.__str__(), id(self))

    def __eq__(self, other):
        # Test for equality with another Process object based
        # on PID and creation time.
        if not isinstance(other, Process):
            return NotImplemented
        return self._ident == other._ident

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(self._ident)
        return self._hash

    # --- utility methods

    def as_dict(self, attrs=[], ad_value=None):
        """Utility method returning process information as a
        hashable dictionary.

        If 'attrs' is specified it must be a list of strings
        reflecting available Process class' attribute names
        (e.g. ['cpu_times', 'name']) else all public (read
        only) attributes are assumed.

        'ad_value' is the value which gets assigned in case
        AccessDenied  exception is raised when retrieving that
        particular process information.
        """
        excluded_names = set(
            ['send_signal', 'suspend', 'resume', 'terminate', 'kill', 'wait',
             'is_running', 'as_dict', 'parent', 'children', 'rlimit'])
        retdict = dict()
        ls = set(attrs or [x for x in dir(self) if not x.startswith('get')])
        for name in ls:
            if name.startswith('_'):
                continue
            if name.startswith('set_'):
                continue
            if name.startswith('get_'):
                msg = "%s() is deprecated; use %s() instead" % (name, name[4:])
                warnings.warn(msg, category=DeprecationWarning, stacklevel=2)
                name = name[4:]
                if name in ls:
                    continue
            if name == 'getcwd':
                msg = "getcwd() is deprecated; use cwd() instead"
                warnings.warn(msg, category=DeprecationWarning, stacklevel=2)
                name = 'cwd'
                if name in ls:
                    continue

            if name in excluded_names:
                continue
            try:
                attr = getattr(self, name)
                if callable(attr):
                    ret = attr()
                else:
                    ret = attr
            except AccessDenied:
                ret = ad_value
            except NotImplementedError:
                # in case of not implemented functionality (may happen
                # on old or exotic systems) we want to crash only if
                # the user explicitly asked for that particular attr
                if attrs:
                    raise
                continue
            retdict[name] = ret
        return retdict

    def parent(self):
        """Return the parent process as a Process object pre-emptively
        checking whether PID has been reused.
        If no parent is known return None.
        """
        ppid = self.ppid()
        if ppid is not None:
            try:
                parent = Process(ppid)
                if parent.create_time() <= self.create_time():
                    return parent
                # ...else ppid has been reused by another process
            except NoSuchProcess:
                pass

    def is_running(self):
        """Return whether this process is running.
        It also checks if PID has been reused by another process in
        which case return False.
        """
        if self._gone:
            return False
        try:
            # Checking if PID is alive is not enough as the PID might
            # have been reused by another process: we also want to
            # check process identity.
            # Process identity / uniqueness over time is greanted by
            # (PID + creation time) and that is verified in __eq__.
            return self == Process(self.pid)
        except NoSuchProcess:
            self._gone = True
            return False

    # --- actual API

    @property
    def pid(self):
        """The process PID."""
        return self._pid

    def ppid(self):
        return self._ppid

    def connections(self):
        return self.connections

    def openfiles(self):
        return self.openfiles

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def cmdline(self):
        return self._cmdline

    def status(self):
        return self._status

    def username(self):
        return self._username

    def create_time(self):
        return self._create_time

    def cwd(self):
        return self._cwd

    def nice(self, value=None):
        return 0

    def uids(self):
        """Return process UIDs as a (real, effective, saved)
        namedtuple.
        """
        return self.uids()

    def gids(self):
        """Return process GIDs as a (real, effective, saved)
        namedtuple.
        """
        return self.gids()

    def terminal(self):
        """The terminal associated with this process, if any,
        else None.
        """
        return self.terminal()

    def num_fds(self):
        """Return the number of file descriptors opened by this
        process (POSIX only).
        """
        return self.num_fds()

    def io_counters(self):
        """Return process I/O statistics as a
        (read_count, write_count, read_bytes, write_bytes)
        """
        return (0, 0, 0, 0)

    def ionice(self, ioclass=None, value=None):
        return 0

    def rlimit(self, resource, limits=None):
        return (0, 0)

    def cpu_affinity(self, cpus=None):
        return []

    def num_ctx_switches(self):
        return 0

    def num_threads(self):
        return 0

    def threads(self):
        return 0

    def children(self, recursive=False):
        return []

    def cpu_percent(self, interval=None):
        return 0.0

    def cpu_times(self):
        return 0

    def memory_info(self):
        return []

    def memory_info_ex(self):
        return []

    def memory_percent(self):
        return 0.0

    def memory_maps(self, grouped=True):
        return []

    def get_open_files(self):
        retlist = []
        for rawitem in self._openfiles:
            ntuple = popenfile._make(rawitem)
            retlist.append(ntuple)
        return retlist

    def get_connections(self, kind='inet'):
        retlist = []
        for rawitem in self._connections:
            ntuple = pconn._make(rawitem)
            retlist.append(ntuple)
        return retlist

    def send_signal(self, sig):
        pass

    def suspend(self):
        pass

    def resume(self):
        pass

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0

    # --- deprecated APIs

    _locals = set(locals())

    del _locals


def sync_processes(qemu_instance, qemu_pid, kernel_version, distro, arch):
    vm = qemu_vm_info(qemu_instance, qemu_pid)

    retlist = []
    rawlist = cext.get_processes(vm.memDumpFile, vm.numMemChunks,
                                 vm.qemuPid, vm.qemuVaStart,
                                 vm.qemuVaEnd, vm.startMemAddr,
                                 vm.memSize,
                                 kernel_sysmaps(kernel_version, distro, arch),
                                 kernel_offsets(kernel_version, distro, arch))

    for item in rawlist:
        pid, name, cmdline, exe, create_time, cwd, ppid, username, connections, openfiles = item
        proc = Process(pid, name, cmdline, exe, create_time,
                       cwd, ppid, username, connections, openfiles)
        retlist.append(proc)
    return retlist


def process_iter(qemu_instance=None, qemu_pid=None, kernel_version=None,
                 distro="ubuntu", arch="x86_64"):
    processes = sync_processes(
        qemu_instance, qemu_pid, kernel_version, distro, arch)
    for proc in processes:
        yield proc


def kernel_version_detection(qemu_instance=None, qemu_pid=None):
    vm = qemu_vm_info(qemu_instance, qemu_pid)

    # This is the memory range that seems to always
    # have some kernel version related variable.
    start = 0xffffffff81631960
    end = 0xffffffff81a8e940

    # 0. Read raw memory from the VM
    str = cext.read_mem_as_text(vm.memDumpFile, vm.numMemChunks,
                                vm.qemuPid, vm.qemuVaStart,
                                vm.qemuVaEnd, vm.startMemAddr,
                                vm.memSize, start, end)

    # 1. Extract any string that looks like a kernel version
    picked_versions = []
    string = '' + str
    version = "no-match"
    longregex = re.compile("(.{1000}[ubuntu\s[2-3]|el[1-9]].{1000})", re.I)
    shortregex = re.compile("\s([2-3]{1}\.[0-9]{1,3}\."
                            "[0-9|\-|\.|generic|virtual|server|el|x|amd|_]{1,100})", re.I)
    matchObj = re.findall(longregex, string)
    if matchObj:
        for match in matchObj:
            versionObj = re.findall(shortregex, match)
            for v in versionObj:
                # XXX this only works for ubuntu or redhat kernels
                if ('el' in v or 'generic' in v or 'virtual' in v
                        or 'server' in v):
                    picked_versions.append(v)
    else:
        print "No match!!"
    print "Picked kernels 1:", picked_versions

    # 2.a Expand the list of potential kernels a bit by removing
    #     the last sub-version string (i.e. "-generic" from
    #     "x.x.x.x-generic")
    for picked_version in picked_versions:
        tmp = re.sub("-[a-zA-Z]+", "", picked_version)
        if tmp not in picked_versions:
            picked_versions.append(tmp)
    print "Picked kernels 2:", picked_versions

    # 2.b Expand the list of potential kernels by removing some
    #     part of the version name. This is required because
    #     the related kernel for 2.6.32-504.1.3.el6.x86_64 is
    #     System.map-2.6.32-504.el6.x86_64.
    for picked_version in picked_versions:
        tmp = re.sub(r"([0-9]+-[0-9]+)\.[0-9\.]+\.el[0-9].*",
                     r"\1", picked_version)
        if tmp not in picked_versions:
            picked_versions.append(tmp)
    print "Picked kernels 3:", picked_versions

    # 3. Try to get offset and map files for the picked kernels
    supported_versions = []
    for picked_version in picked_versions:
        arch, distro, supported_version = get_supported_kernel(picked_version)
        if supported_version:
            supported_versions.append([supported_version, arch,
                                       distro, picked_version])
    print "Picked and supported kernels:"
    for supported_version in supported_versions:
        print supported_version

    # 4. Now check that offset and map to see if the kernel version
    #    string at the expected position is the expected value.
    for supported_version, arch, distro, picked_version in supported_versions:
        sys = system_info(qemu_instance, qemu_pid,
                          supported_version, distro, arch)
        if sys == None:
            continue
        if (supported_version in sys.osname or picked_version in sys.osname or
                supported_version in sys.osrelease or picked_version in sys.osrelease):
            return [supported_version, arch, distro]

    return [None, None, None]
