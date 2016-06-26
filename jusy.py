import sys,multiprocessing
OWNER_HASH = sys.argv[1] # first parameter is owner hash
NCORES = multiprocessing.cpu_count()
NSESSIONS = int(NCORES * 1.3)

# -----------------------------------------------

import socket,select,json,threading,time,subprocess,random,os,shutil,datetime
from os import stat
from pwd import getpwuid
from pwd import getpwnam

import logging
import logging.handlers
logger = logging.getLogger('jusy')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
logger.addHandler(handler)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

ESQ_SEQ_BEG = "~\'\"\"\"{~~."
ESQ_SEQ_END = ".~~\'\"\"\"{~"
ESQ_LEN = len(ESQ_SEQ_BEG)
MSG_LEN = 8192
COUNTER = 0
USER_BEG = "jsuser"
MAX_PROC_PER_USER = 50

class JuSyProxy(threading.Thread):
    def __init__(self, session):
        self.started = False
        pass
    def send_dict(self, d):
        s = json.dumps(d)
        self.send_sock.send(ESQ_SEQ_BEG+s+ESQ_SEQ_END)
    def handle_connect(self):
        pass
    def finish(self, fin_code):
        pass
    def stop(self):
        self._loop = False
    def run(self):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect(("localhost", 8022))
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.connect(("p1.plotti.co", 8880))
        self.send_sock = s2
        inputs = [ s1, s2 ]
        outputs = [ ]
        data = ""
        msg_wait = False
        msg = ""
        self._loop = True
        
        while self._loop:
            readable, writable, exceptional = select.select(inputs, outputs, inputs, timeout=2)
            for s in readable:
                if not self.started:
                    self.started = True
                    self.handle_connect()
                if s is s1:
                    data = s1.recv(4096)
                    s2.send(data)
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
                                print json.loads(msg)
                            else:
                                msg_wait = True
                    if msg_wait:
                        if ESQ_SEQ_END in read:
                            pos = read.index(ESQ_SEQ_END)
                            msg += read[:pos]
                            read = read[pos+ESQ_LEN:]
                            msg_wait = False
                            print json.loads(msg)
                        else:
                            msg += read
                            read = ""
                            if len(msg) > MSG_LEN:
                                read = msg
                                msg_wait = False
                    if read: s1.send(read)
            # print "Received:", len(data)
            if readable and len(data) == 0:
                break
            if exceptional: 
                break
        print "Connection closed."
        s1.close()
        s2.close()
        if self._loop:
            self.finish("FIN_CONN_CLOSED") # it is obviously impossible to send fin status if connection is closed...
 

class JSSession(JuSyProxy):
    def __init__(self):
        super(JSSession, self).__init__()
        self.username = ""
        self.privkey = "" # will be filled by get_privkey_access
        self.gen_user()
        self.diskfile = "/tmp/"+self.username+".iso"
        self.create_disk()
        self.mount_disk()
        self.gen_privkey_access()
        self.accounting_start_ts = 0
        self.session_start_ts = time.time()
        
    def handle_connect(self):
        self.send_dict({"type": "announce", "username": self.username, "privkey": self.privkey, "owner_hash": OWNER_HASH })
    
    def gen_user(self):
        salt = random.randint(100000, 99999)
        self.username = USER_BEG+str(salt)+str(COUNTER)
        COUNTER += 1
        subprocess.call(["addgroup", "nobody"])
        subprocess.call(["adduser", "--disabled-password", "--gecos", "", "--ingroup", "nobody", self.username])
        self.uid = getpwnam(self.username).pw_uid
        self.gid = getpwnam(self.username).pw_gid
        self.home = getpwnam(self.username).pw_dir
    
    def create_disk(self):
        subprocess.call(["truncate", "-s", "10G", self.diskfile])
        subprocess.call(["mkfs.ext2", self.diskfile])
    
    def mount_disk(self):
        subprocess.call(["mount", self.diskfile, "/home/"+self.username, "-o", "loop"])
        os.chown(self.home, self.uid, self.gid)
        
    def gen_privkey_access(self):
        self.keyfile = os.path.join(self.home, "key")
        subprocess.call(["ssh-keygen", "-t", "rsa", "-f", self.keyfile])
        self.privkey = file(self.keyfile).read()
        os.mkdir(os.path.join(self.home, ".ssh"), 0o700)
        shutil.copyfile(self.keyfile+".pub", os.path.join(self.home, ".ssh", "authorized_keys"))
        os.chown(os.path.join(self.home, ".ssh"), self.uid, self.gid)
        os.chown(os.path.join(self.home, ".ssh", "authorized_keys"), self.uid, self.gid)
        os.chmod(os.path.join(self.home, ".ssh", "authorized_keys"), 0o644)
    
    def check_accounting(self):
        "implements all the accounting requirements"
        proccount = count_processes(self.username)
        if self.accounting_start_ts == 0 and proccount > 0:
            self.accounting_start_ts = time.time()
        cputime = 0
        cputime += count_cpu_time_live(self.username)
        cputime += count_cpu_time_past(self.username)
        if cputime > 3600:
            logger.info("max work reached for %s - stopping" % self.username)
            self.finish("FIN_DONE")
            return
        if proccount > MAX_PROC_PER_USER:
            self.finish("FIN_MAXPROC_EXCEEDED")
            return
        ram_kb = count_rss_kb_unsafe(self.username)
        if ram_kb > 2e6:
            self.finish("FIN_RAM_EXCEEDED")
            return
        if time.time() - self.accounting_start_ts > 3600 * 3 and cputime < 500:
            self.finish("FIN_IDLE")
            return
        
        
        
        
class Accounting(object):
    def __init__(self, session):
        self.session = session
        # now start acct http://www.cyberciti.biz/tips/howto-log-user-activity-using-process-accounting.html
        
# ----------------------------------------------------
# accounting utility functions
# ----------------------------------------------------

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
            if len(tt) < 11: continue
            x = time.strptime(tt[10].split(".")[0], '%M:%S')
            total += datetime.timedelta(hours=x.tm_hour,minutes=x.tm_min,seconds=x.tm_sec).total_seconds()
    except subprocess.CalledProcessError:
        pass
    return total

def count_rss_kb_unsafe(username):
    o = subprocess.check_output("top -b -n 1 -u %s | awk -v var=\"%s\" 'NR>7 { sumC += $9; }; { sumM += $6; } END { print sumM; }'" % (username,username), shell=True)
    if not o: return 0
    return int(o)

def start_acct():
    # will only need this for RPM distros
    subprocess.call("chkconfig psacct on", shell=True)
    subprocess.call("chkconfig acct on", shell=True)
    subprocess.call("/etc/init.d/psacct start", shell=True)
    subprocess.call("/etc/init.d/acct start", shell=True)
    
def count_cpu_time_past(username):
    for l in subprocess.check_output(["sa", "-m"]).split("\n"):
        if username in l:
            return float(l.split()[3][:-2])*60
    return 0
    
def count_processes(username):
    import os
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    c = 0
    for pid in pids:
        try:
            if find_owner(os.path.join('/proc', pid)) == username:
                c += 1
        except IOError: # proc has already terminated
            continue
    return c

class Worker(object):
    def __init__(self):
        self.sessions = []
    
    def count_sessions(self):
        self.sessions = [t for t in self.sessions if not t.isAlive()]
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
        while True:
            if self.count_sessions() < NSESSIONS and self.system_load() < NCORES*1.3:
                self.start_session()
            self.check_cpu_times()
            time.sleep(5)

    
    