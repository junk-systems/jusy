import urllib2, json, sys, subprocess, os, time, signal
# pyjusy helper module
'''
This module asks for credentials and creates master connection.

The class JunkSystem can be instantiated as many times as is desirable, 
creating more contracts.
'''
CLIENT_HASH = None

class Alarm(Exception):
    'Helps with exec timeout'
    pass

def alarm_handler(signum, frame):
    raise Alarm

signal.signal(signal.SIGALRM, alarm_handler)

class JunkSystem(object):
    "Creates a new Junk.Systems order and by default opens a background master SSH connection"
    def __init__(self, client_hash, start_master=True):
        "Takes only client_hash and immediately opens order. Returns(object checks as) False if it has failed to create"
        self.client_hash = client_hash
        response = urllib2.urlopen('https://proxy.junk.systems/order/' + client_hash) 
        r = response.read()
        d = json.loads(r)
        if not "privkey" in d:
            self._open = False
            return
        self._open = True
        self.credentials = d
        self.__dict__.update(d)
        self.privkey_file = "/tmp/jusy_"+self.username+str(self.port) # pylint: disable=no-member
        open(self.privkey_file, 'w').write(self.privkey) # pylint: disable=no-member
        os.chmod(self.privkey_file, 0o600)
        self.ssh_param_list = ["ssh", '-oControlMaster=auto', '-oControlPath=~/.ssh/control:%h:%p:%r', '-oControlPersist=5', '-i', self.privkey_file, "-l", self.username, "-oUserKnownHostsFile=/dev/null", "-oStrictHostKeyChecking=no", "-p", str(self.port), self.host] # pylint: disable=no-member
        if start_master:
            self.start_master()
    
    def start_master(self):
        "Start master connection for SSH"
        # call and test the master channel
        signal.alarm(5)
        try:
            subprocess.call(self.ssh_param_list+["touch /dev/null"]) # pylint: disable=no-member
            signal.alarm(0)
        except Alarm:
            print "ERROR: could not start master connection"
            self._open = False
            return
        # now as no exception received - launch a background process
        self.master_pid = os.forkpty()[0]
        if not self.master_pid:
            os.system(" ".join(self.ssh_param_list+["sleep infinity"]))
    
    def remote_call_status(self, cmd):
        "return exit code of remote command execution"
        signal.alarm(5)
        try:
            retval = subprocess.call(self.ssh_param_list+[cmd]) # pylint: disable=no-member
            signal.alarm(0)
        except Alarm:
            return -1
        return retval
    
    def open_ssh_session(self):
        'Starts interactive ssh session in current terminal'
        subprocess.call(self.ssh_param_list)
    
    def close_master(self):
        'Close master connection, if any'
        if hasattr(self, "master"):
            self.master.kill()
            # print "Closing master connecion"
        if hasattr(self, "master_pid"):
            os.kill(self.master_pid, signal.SIGTERM) 

    def __bool__(self):
        return self._open
    __nonzero__=__bool__
    
    def __str__(self):
        if self._open: return "<JunkSystem instance>"
        else: return "<JunkSystem FAIL>"
    __repr__ = __str__
    
    def __del__(self):
        if hasattr(self, "privkey_file"):
            try:
                os.remove(self.privkey_file)
            except OSError:
                pass
        self.close_master()

def set_client_hash(s):
    global CLIENT_HASH
    CLIENT_HASH = s

def open_channels(nr, python=False):
    systems = []
    for i in range(nr):
        ch = JunkSystem(CLIENT_HASH)
        if ch._open and ((not python) or (ch.remote_call_status("python --version") == 0)):
            systems.append(ch)
    return systems
    
if __name__ == '__main__':
    CLIENT_HASH = sys.argv[1] # first argument is client hash
    ch = JunkSystem(CLIENT_HASH)
    print('Opened master SSH onnection. You can spawn more sessions with:')
    print(' '.join(ch.ssh_param_list))
    ch.open_ssh_session()
        