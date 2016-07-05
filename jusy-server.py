#!/usr/bin/python
__version__ = "0.1"
__scripturl__ = "https://raw.githubusercontent.com/junk-systems/jusy/master/jusy-server.py"
# This file is a part of Junk.Systems project
# for more information please visit http://junk.systems
# Copyright (C) 2016 Andrew Gryaznov <realgrandrew@gmail.com>
# License: BSD 3-Clause License

import sys, multiprocessing, signal, socket, select, json, threading
import time, subprocess, random, os, shutil, datetime, string, base64, gzip
from os import stat
from pwd import getpwuid
from pwd import getpwnam

import logging
import logging.handlers
logger = logging.getLogger('jusy')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler = logging.handlers.SysLogHandler(address = '/dev/log')
handler = logging.FileHandler('/var/log/jusy.log')
handler.setFormatter(formatter)
logger.addHandler(handler)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

NCORES = multiprocessing.cpu_count()
NSESSIONS = int(NCORES * 1.3)
API_SERVER = "proxy.junk.systems"
API_PORT = 8001 # V1 API
ESQ_SEQ_BEG = "~\'\"\"\"{~~."
ESQ_SEQ_END = ".~~\'\"\"\"{~"
ESQ_LEN = len(ESQ_SEQ_BEG)
MSG_LEN = 8192
COUNTER = 0
USER_BEG = "jsuser"
MAX_PROC_PER_USER = 50
CPUTIME_MAX = 3600
# CPUTIME_MAX = 30 # for testing - finish after 30 sec

class JuSyProxy(threading.Thread):
    def __init__(self):
        super(JuSyProxy, self).__init__()
        self.started = False
        self.send_sock = None
        self._loop = True
        self.local_bytecount = 0
    def send_dict(self, d):
        s = json.dumps(d)
        self.send_sock.send(ESQ_SEQ_BEG+s+ESQ_SEQ_END)
    def handle_connect(self):
        pass
    def finish(self, fin_code):
        pass
    def stop(self):
        self._loop = False
    def handle_message(self, d):
        logger.debug("message received %s", repr(d))
        if d["type"] == 'push_key':
            logger.info('adding pubkey %s', d['pubkey'])
            self.add_pubkey(d['pubkey'])
        if d['type'] == 'prng_test':
            ts = time.time()
            cr = prng_compute(d['seed'])
            self.send_dict({"type": "prng_result", "result": str(float(cr))})
            logger.debug("Replying with computation %s - %s that took %ss",
                         d['seed'], cr, time.time() - ts)
    def add_pubkey(self, key):
        'to be overwritten by inherit'
        pass
    def run(self):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s1.connect(("localhost", LOCAL_SSH_PORT))
        except:
            logger.error("Could not establish local SSH connection")
            self.finish("FIN_CONN_CLOSED")
            return
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s2.connect((API_SERVER, API_PORT))
        except:
            logger.error("Could not establish connection to proxy server")
            s1.close()
            self.finish("FIN_CONN_CLOSED")
            return

        self.send_sock = s2
        inputs = [s1, s2]
        outputs = []
        data = ""
        msg_wait = False
        msg = ""

        while self._loop:
            readable, writable, exceptional = select.select(inputs, outputs, inputs, 2)
            for s in readable:
                if not self.started:
                    self.started = True
                    self.handle_connect()
                if s is s1:
                    data = s1.recv(4096)
                    s2.send(data)
                    self.local_bytecount += len(data)
                if s is s2:
                    read = s2.recv(4096)
                    if not msg_wait:
                        if ESQ_SEQ_BEG in read: #TODO: startswith will be faster!
                            pos = read.index(ESQ_SEQ_BEG)
                            msg = read[pos+ESQ_LEN:]
                            read = read[:pos]
                            if ESQ_SEQ_END in msg:
                                pos = msg.index(ESQ_SEQ_END)
                                read += msg[pos+ESQ_LEN:]
                                msg = msg[:pos]
                                try:
                                    self.handle_message(json.loads(msg))
                                except ValueError:
                                    logger.warning("could not decode server message %s", msg)
                            else:
                                msg_wait = True
                    if msg_wait:
                        if ESQ_SEQ_END in read:
                            pos = read.index(ESQ_SEQ_END)
                            msg += read[:pos]
                            read = read[pos+ESQ_LEN:]
                            msg_wait = False
                            try:
                                self.handle_message(json.loads(msg))
                            except ValueError:
                                logger.warning("could not decode server message")
                        else:
                            msg += read
                            read = ""
                            if len(msg) > MSG_LEN:
                                read = msg
                                msg_wait = False
                    if read:
                        s1.send(read)
                        self.local_bytecount += len(read)
            # print "Received:", len(data)
            if readable and len(data) == 0:
                break
            if exceptional:
                break
        logger.info("Connection closed.")
        try:
            s1.close()
            s2.close()
        except socket.error:
            pass
        if self._loop:
            self.finish("FIN_CONN_CLOSED")


class JSSession(JuSyProxy):
    def __init__(self, nobsdacct=False):
        super(JSSession, self).__init__()
        self.username = ""
        self.privkey = "" # will be filled by get_privkey_access
        self.gen_user()
        self.diskfile = "/tmp/"+self.username+".iso"
        self.create_disk()
        self.mount_disk()
        self.gen_privkey_access()
        self.accounting_start_ts = time.time()
        self.session_start_ts = time.time()
        self.old_cpu_time = 0
        self.account_call_count = 0
        self.idle_count = 0
        self.nobsdacct = nobsdacct
        self.run_dict = {}
        if not self.test_login():
            self.run = self.norun

    def no_run(self):
        logger.info("Not running due to errors")
    def test_login(self):
        try:
            subprocess.check_call(["ssh", "-i", self.keyfile, "-oBatchMode=yes", "-p",
                                   str(LOCAL_SSH_PORT), "-l", self.username, "localhost", "ls"])
        except subprocess.CalledProcessError:
            logger.error("Can not log in to myself using ssh key! Check ssh configuration")
            return False
        except OSError:
            logger.error("Can not execute ssh to test connection")
            return False
        logger.debug("login self test OK")
        return True


    def handle_connect(self):
        self.send_dict({"type": "announce", "username": self.username,
                        "privkey": self.privkey, "owner_hash": OWNER_HASH})

    def gen_user(self):
        global COUNTER
        salt = random.randint(100000, 999999)
        self.username = USER_BEG+str(salt)+str(COUNTER)
        COUNTER += 1
        subprocess.call(["addgroup", "nobody"])
        subprocess.call(["adduser", "--disabled-password", "--gecos", "",
                         "--ingroup", "nobody", self.username])
        self.uid = getpwnam(self.username).pw_uid
        self.gid = getpwnam(self.username).pw_gid
        self.home = getpwnam(self.username).pw_dir
        os.chmod(self.home, 0o700)
        self.iptables_check()

    def iptables_check(self):
        try:
            subprocess.check_output("iptables -nL | grep 'owner GID match %s'"
                                    % self.gid, shell=True)
        except subprocess.CalledProcessError:
            logger.debug("Adding new iptables rules")
            self.iptables_set()


    def iptables_set(self):
        try:
            subprocess.call("iptables -A OUTPUT -m owner --gid-owner %s -p tcp -m tcp -m multiport ! --dports 22 -j DROP"
                            % self.gid, shell=True)
            subprocess.call("iptables -A OUTPUT -m owner --gid-owner %s -p udp -j DROP"
                            % self.gid, shell=True)
        except subprocess.CalledProcessError:
            logger.warning("Could not apply iptables rules")

    def create_disk(self):
        try:
            subprocess.call(["truncate", "-s", "5G", self.diskfile])
            subprocess.call(["mkfs.ext2", "-q", "-F", self.diskfile])
        except OSError:
            logger.warning("Can not create virtual disk at %s", self.diskfile)

    def mount_disk(self):
        try:
            subprocess.call(["mount", self.diskfile, self.home, "-o", "loop"])
            os.chown(self.home, self.uid, self.gid)
        except OSError:
            logger.warning("Can not call mount %s %s", self.diskfile, self.home)

    def gen_privkey_access(self):
        os.mkdir(os.path.join(self.home, ".ssh"), 0o700)
        self.keyfile = os.path.join(self.home, ".ssh", "key")
        subprocess.call(["ssh-keygen", "-q", "-t", "rsa", "-N", "", "-f", self.keyfile])
        self.privkey = file(self.keyfile).read()
        shutil.copyfile(self.keyfile+".pub", os.path.join(self.home, ".ssh", "authorized_keys"))
        os.chown(os.path.join(self.home, ".ssh"), self.uid, self.gid)
        os.chown(os.path.join(self.home, ".ssh", "authorized_keys"), self.uid, self.gid)
        os.chmod(os.path.join(self.home, ".ssh", "authorized_keys"), 0o644)

    def add_pubkey(self, key):
        open(os.path.join(self.home, ".ssh", "authorized_keys"), 'a').write('\n'+key)

    def collect_report(self):
        "collect a usage report"
        local_acct = json.dumps(self.run_dict)
        return string.join([get_sa_report_unsafe(self.username), get_sa_stat(self.username),
                            local_acct, top_dump(self.username)], "\n---\n")

    def finish(self, fin_code):
        report = self.collect_report()
        full_rep = {"type": "finish", "fin_code": fin_code, "report": compress_report(report)}
        if fin_code != "FIN_CONN_CLOSED":
            self.send_dict(full_rep)
        self.stop()

    def stop(self):
        subprocess.call("ps -o pid= -u %s | xargs sudo kill -9" % self.username, shell=True)
        time.sleep(1) # TODO: what if page-in is required and more time needed to kill?
        # TODO: implement waiting for user processes to exit
        try:
            subprocess.call(["umount", self.diskfile])
        except OSError:
            logger.warning("Can not call umount %s", self.diskfile)
        try:
            os.remove(self.diskfile)
        except OSError:
            logger.warning("Can not remove diskfile at %s", self.diskfile)
        subprocess.call(["userdel", "-r", self.username])
        self._loop = False

    def sum_run_times(self):
        self.run_dict.update(cpu_time_live_dict(self.username))
        return sum(self.run_dict.values())

    def check_accounting(self):
        "implements all the accounting requirements"
        self.account_call_count += 1
        proccount = count_processes(self.username)
        if self.accounting_start_ts == 0 and proccount > 0:
            self.accounting_start_ts = time.time()
        cputime = 0
        cputime += count_cpu_time_live(self.username)
        tpast = count_cpu_time_past(self.username)
        if tpast:
            cputime += tpast
        else:
            cputime = self.sum_run_times()
        if cputime > CPUTIME_MAX:
            logger.info("max work reached for %s - stopping", self.username)
            self.finish("FIN_DONE")
            return
        if proccount > MAX_PROC_PER_USER:
            self.finish("FIN_MAXPROC_EXCEEDED")
            return
        ram_kb = count_rss_kb_unsafe(self.username)
        if ram_kb > 2e6:
            self.finish("FIN_RAM_EXCEEDED")
            return
        # if time.time() - self.accounting_start_ts > 3600 * 3 and cputime < 500:
        if time.time() - self.accounting_start_ts > 3600 * 3:
            self.finish("FIN_IDLE")
            return
        if self.account_call_count % 10 == 0:
            if cputime - self.old_cpu_time < 10:
                self.idle_count += 1
            else:
                self.idle_count = 0
            self.old_cpu_time = cputime
        # if ram_kb > 2e5 and self.idle_count > 5 * 60 / 5:
        #     self.finish("FIN_IDLE_RAMUSE")
        #     return

# ----------------------------------------------------
# accounting utility functions
# ----------------------------------------------------

def compress_report(report):
    import StringIO
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(report)
    return base64.b64encode(out.getvalue())

def check_acct():
    try:
        subprocess.check_output(["accton"])
    except OSError:
        # error: acct, sa not
        return False
    finally:
        pass
    try:
        subprocess.check_output(["sa", "-m"])
    except subprocess.CalledProcessError:
        return False
    return True

def find_owner(filename):
    return getpwuid(stat(filename).st_uid).pw_name

def count_cpu_time_live(username):
    total = 0
    try:
        for l in subprocess.check_output(["top", "-b", "-n", "1", "-u", username]).split("\n")[7:]:
            tt = l.split()
            if len(tt) < 11:
                continue
            x = time.strptime(tt[10].split(".")[0], '%M:%S')
            total += datetime.timedelta(hours=x.tm_hour, minutes=x.tm_min,
                                        seconds=x.tm_sec).total_seconds()
    except subprocess.CalledProcessError:
        pass
    return total

def count_rss_kb_unsafe(username):
    o = subprocess.check_output("top -b -n 1 -u %s | awk -v var=\"%s\" 'NR>7 { sumC += $9; }; { sumM += $6; } END { print sumM; }'" % (username, username), shell=True)
    if not o: return 0
    return int(o)

def start_acct():
    # will only need this for RPM distros
    subprocess.call("chkconfig psacct on", shell=True)
    subprocess.call("chkconfig acct on", shell=True)
    subprocess.call("/etc/init.d/psacct start", shell=True)
    subprocess.call("/etc/init.d/acct start", shell=True)

def count_cpu_time_past(username):
    try:
        for l in subprocess.check_output(["sa", "-m"]).split("\n"):
            if username in l:
                return float(l.split()[3][:-2])*60
    except OSError:
        return 0
    return 0

def count_processes(username):
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    c = 0
    for pid in pids:
        try:
            if find_owner(os.path.join('/proc', pid)) == username:
                c += 1
        except IOError: # proc has already terminated
            continue
        except OSError: # proc has already terminated
            continue
    return c

def cpu_time_live_dict(username):
    d = {}
    try:
        for l in subprocess.check_output(["top", "-b", "-n", "1", "-u", username]).split("\n")[7:]:
            tt = l.split()
            if len(tt) < 11: continue
            x = time.strptime(tt[10].split(".")[0], '%M:%S')
            c_time = datetime.timedelta(hours=x.tm_hour,
                                        minutes=x.tm_min, seconds=x.tm_sec).total_seconds()
            pid = int(tt[0])
            d[pid] = c_time
    except subprocess.CalledProcessError:
        pass
    return d


def get_sa_report_unsafe(username):
    try:
        return subprocess.check_output("sa -u | grep %s" % username, shell=True)
        # TODO: shell mode won't raise exceptions
    except IOError:
        return "No sa executable"
    except subprocess.CalledProcessError:
        return "Error calling sa -u"

def get_sa_stat(username):
    try:
        for l in subprocess.check_output(["sa", "-m"]).split("\n"):
            if username in l:
                return l
    except OSError:
        return "No sa executable"
    return "User not found in sa -m output"

def top_dump(username):
    return subprocess.check_output(["top", "-b", "-n", "1", "-u", username])


class Worker(object):
    def __init__(self):
        self.sessions = []
        self._loop = True

    def count_sessions(self):
        self.sessions = [t for t in self.sessions if t.isAlive()]
        return len(self.sessions)

    def start_session(self):
        s = JSSession()
        s.start()
        self.sessions.append(s)

    def system_load(self):
        return os.getloadavg()[0]

    def check_cpu_times(self):
        for s in self.sessions:
            s.check_accounting()

    def loop(self):
        loopcount = 0
        update_check = random.randint(720,1080)
        try:
            while self._loop:
                if self.count_sessions() < NSESSIONS and self.system_load() < NCORES*1.3:
                    logger.debug("Starting new session, current: %s", repr(self.sessions))
                    self.start_session()
                self.check_cpu_times()
                if loopcount % update_check == 0:
                    update(__scripturl__)
                loopcount += 1
                time.sleep(5)
        except KeyboardInterrupt:
            self.stop_all()
    def stop_all(self):
        self._loop = False
        for s in self.sessions:
            s.stop()
    def stop_new(self):
        "stop new and unused sessions"
        self._loop = False
        s_count = 0
        w_count = 0
        for s in self.sessions:
            if s.local_bytecount < 5000:
                s.stop()
                s_count += 1
            else:
                w_count += 1
        return s_count, w_count



# to get this, use base64 -w 0 ./rngs
RNGS_BINARY = """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"""

def get_rngs_binary():
    import zlib
    return zlib.decompress(base64.b64decode(RNGS_BINARY), 16+zlib.MAX_WBITS)

def prng_compute(d):
    prng_bin = '/tmp/jusy_prng'
    open(prng_bin, 'w').write(get_rngs_binary())
    os.chmod(prng_bin, 0o700)
    return subprocess.check_output([prng_bin, str(d)]).strip()

def createDaemon():
    """Detach a process from the controlling terminal and run it in the
    background as a daemon.
    """

    try:
        pid = os.fork()
    except OSError, e:
        raise Exception("%s [%d]" % (e.strerror, e.errno))

    if pid == 0:   # The first child.
        os.setsid()
        try:
            pid = os.fork()    # Fork a second child.
        except OSError, e:
            raise Exception("%s [%d]" % (e.strerror, e.errno))

        if pid == 0:    # The second child.
            os.chdir("/tmp")
            os.umask(0o600)
        else:
            os._exit(0)    # Exit parent (the first child) of the second child.
    else:
        os._exit(0)   # Exit parent of the first child.

def main():
    import optparse
    parser = optparse.OptionParser()
    parser.add_option(
        '-p', '--ssh-port', type="int",
        dest='ssh_port', default=22,
        help='Local SSH server port')
    parser.add_option(
        '-n', '--sessions-count',
        type='int', dest='sessions_count', default=0,
        help='Force amount of parallel sessions (= # of CPUs by default)')
    parser.add_option(
        '-d', '--debug', dest='debug', action="store_true",
        help='Enable debugging', default=False)
    parser.add_option(
        '-i', '--install-cronjob', dest='cronjob', action="store_true",
        help='Automatically add cron job to run and update', default=False)
    parser.add_option(
        '-f', '--daemon', dest='daemon', action="store_true",
        help='Fork to background', default=False)
    options, args = parser.parse_args()
    global NSESSIONS, LOCAL_SSH_PORT, OWNER_HASH, w
    OWNER_HASH = args[0] # first parameter is owner hash
    if options.debug:
        ch.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.ERROR)
        logger.setLevel(logging.INFO)
    if options.sessions_count > 0:
        NSESSIONS = options.sessions_count
    LOCAL_SSH_PORT = options.ssh_port
    if os.geteuid():
        logger.error("Must be root to run jusy server")
        return
    if options.cronjob:
        try:
            os.mkdir("/opt")
        except OSError:
            pass # exists
        fn = os.path.realpath(__file__)
        shutil.copyfile(fn, "/opt/jusy-server.py")
        subprocess.call(
            '(crontab -l ; echo "@reboot python /opt/jusy-server.py --daemon") | crontab -',
            shell=True)
    if options.daemon:
        createDaemon()

    w = Worker()
    w.loop()

def shutdown():
    w.stop_all()

signal.signal(signal.SIGTERM, shutdown)

def update(dl_url, force_update=False):
    """
Attempts to download the update url in order to find if an update is needed.
If an update is needed, the current script is backed up and the update is
saved in its place.
"""
    import urllib
    import re
    from subprocess import call
    def compare_versions(vA, vB):
        """
Compares two version number strings
@param vA: first version string to compare
@param vB: second version string to compare
@author <a href="http_stream://sebthom.de/136-comparing-version-numbers-in-jython-pytho/">Sebastian Thomschke</a>
@return negative if vA < vB, zero if vA == vB, positive if vA > vB.
"""
        if vA == vB: return 0

        def num(s):
            if s.isdigit(): return int(s)
            return s

        seqA = map(num, re.findall('\d+|\w+', vA.replace('-SNAPSHOT', '')))
        seqB = map(num, re.findall('\d+|\w+', vB.replace('-SNAPSHOT', '')))

        # this is to ensure that 1.0 == 1.0.0 in cmp(..)
        lenA, lenB = len(seqA), len(seqB)
        for i in range(lenA, lenB): seqA += (0,)
        for i in range(lenB, lenA): seqB += (0,)

        rc = cmp(seqA, seqB)

        if rc == 0:
            if vA.endswith('-SNAPSHOT'): return -1
            if vB.endswith('-SNAPSHOT'): return 1
        return rc

    # dl the first 256 bytes and parse it for version number
    try:
        http_stream = urllib.urlopen(dl_url)
        update_file = http_stream.read(256)
        http_stream.close()
    except IOError, e:
        errno, strerror = e
        logger.error("Unable to retrieve version data")
        logger.error("Error %s: %s", errno, strerror)
        return

    match_regex = re.search(r'__version__ *= *"(\S+)"', update_file)
    if not match_regex:
        logger.error("No version info could be found")
        return
    update_version = match_regex.group(1)

    if not update_version:
        logger.error("Unable to parse version data")
        return

    if force_update:
        logger.info("Forcing update, downloading version %s...", update_version)
    else:
        cmp_result = compare_versions(__version__, update_version)
        if cmp_result < 0:
            logger.info("Newer version %s available, downloading...", update_version)
        elif cmp_result > 0:
            logger.info("Local version %s newer then available %s, not updating.",
                __version__, update_version)
            return
        else:
            logger.info("You already have the latest version.")
            return

    # dl, backup, and save the updated script
    app_path = os.path.realpath(__file__)

    if not os.access(app_path, os.W_OK):
        logger.error("Cannot update -- unable to write to %s", app_path)
        return

    dl_path = app_path + ".new"
    backup_path = app_path + ".old"
    try:
        dl_file = open(dl_path, 'w')
        http_stream = urllib.urlopen(dl_url)
        total_size = None
        bytes_so_far = 0
        chunk_size = 8192
        try:
            total_size = int(http_stream.info().getheader('Content-Length').strip())
        except:
            # The header is improper or missing Content-Length, just download
            dl_file.write(http_stream.read())

        while total_size:
            chunk = http_stream.read(chunk_size)
            dl_file.write(chunk)
            bytes_so_far += len(chunk)

            if not chunk:
                break

            # percent = float(bytes_so_far) / total_size
            # percent = round(percent*100, 2)
            # sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" %
            #     (bytes_so_far, total_size, percent))

            # if bytes_so_far >= total_size:
            #     sys.stdout.write('\n')

        http_stream.close()
        dl_file.close()
    except IOError, e:
        errno, strerror = e
        logger.error("Download failed")
        logger.error("Error %s: %s", errno, strerror)
        return

    try:
        os.rename(app_path, backup_path)
    except OSError, e:
        errno, strerror = e
        logger.error("Unable to rename %s to %s: (%d) %s",
            app_path, backup_path, errno, strerror)
        return

    try:
        os.rename(dl_path, app_path)
    except OSError, e:
        errno, strerror = e
        logger.error("Unable to rename %s to %s: (%d) %s",
            dl_path, app_path, errno, strerror)
        return

    try:
        import shutil
        shutil.copymode(backup_path, app_path)
    except:
        os.chmod(app_path, 0o755)

    logger.info("New version installed as %s", app_path)
    logger.info("(previous version backed up to %s)", backup_path)

    s_count, w_count = w.stop_new()
    logger.info("Stopping %s local tasks waiting for %s tasks", s_count, w_count)
    logger.info("Launching new server")
    os.system("python %s --daemon %s&" % (app_path, OWNER_HASH))
    return

if __name__ == '__main__':
    main()