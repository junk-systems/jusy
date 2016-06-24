"""
+ send the announce call
+ check that user can get it
+ add startup for user
- start # of threads as # or cores
- implement accounting: 
    - periodic check that we have less processes than cores
    - fork
    - create user
    - launch:
        - connection
        - accounting loop
- implement finish
    - delete user
    - umount
    - remove
- periodic performance-ping check using paramiko?? -> reconnect to same port!?! -> test by JSON!
- if no I/O was possible (20 sec?) -> remove contract
- check finish
- account cpu
- restartless server (+ attach to system?) http://stackoverflow.com/questions/4163964/python-is-it-possible-to-attach-a-console-into-a-running-process
- coinbase integration
- bitcoin transfer-out request
"""
import sys
OWNER_HASH = sys.argv[1] # first parameter is owner hash

import socket,select,json,threading,time,subprocess,random,os,shutil
from pwd import getpwnam
import multiprocessing

NCORES = multiprocessing.cpu_count()

ESQ_SEQ_BEG = "~\'\"\"\"{~~."
ESQ_SEQ_END = ".~~\'\"\"\"{~"
ESQ_LEN = len(ESQ_SEQ_BEG)
MSG_LEN = 8192
COUNTER = 0

PRIVKEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA8mkapurvGCGwl1qZmyvQiSLQF/Sc5MxtN6V0ItPmbdvl+uqg
2CWE2rozuddtlSo8WYxOtfVTWdP3bBt55bMRlT3WUPeQ+X2rb68r9aQqvCNUOYB/
M6l5/TGdZUVF7jQvvCT5EW3XozS3Ue5tCqowLnFYnjacluHwdn7rYa09LdC4Z1xK
oQAXyTsMM9QgV6QM6VM/kGwpnxk9HyhGyAIXc6vj1rKcFUm5RJiY2dMHgTDX5RdY
h/hKING5PYPOYG+3db5Ifzueb/VtoOGNxwGqkiOOk1zKdA4FaN2T+iAiUnTIWO2C
29csUBk1pdOpZ2up8ulBVvSguFCtn81PXWsi6wIDAQABAoIBAQDAEcU7UlSlgzQf
iHrC9yFhN0M4Z+nUY6F6AM+XNNyUWTLM8BEHkhrFD9oiOu4pzXBJ56EKDVrAhvG5
J8Aa3xpkbL2eI7or5IXslRg4pp3xufBnK0geT/9HPYOflRbGmXTlF0p9o9HDD+bc
tRSS6awJcGet3EmQR283BHNOTmx2GirZo4srktx2PqOZbIwEEtlXvadfn6PuAQwj
r8RLCTD0gewh/qESbzp/omQQGnYqm7xHt+gsIqW8JS1NygoP7vcUQ13ouxlZeM28
Ru9vpMLpkBFbK1Us/mRz+CUqBtNxa95bgEXcnl3sCnG686OgMOcE4hN/Ak/+qzDz
WSIe0KP5AoGBAP40TdJdDmYfoeJp6B1Go0s5zMFt1WAjGwdsSnJH8fhvZYcmEwKH
ffA1vZVJHrkU39JGNBCyjIcpop56s7DswpBvENdPESDixlEdLmOBJwnKe7v6MCbX
+gqeT58BarSkMVIh7jGFovdVFwQWDUKtbcVPlBNKPXUvxmD7dTCU+e+3AoGBAPQf
eP5B2oheSYKRXoORlTiu2tqxx94Mkz4t+pjCbuK4KUWc7yelXquJsmMmigZ9OhQL
KNVjdH+IuRA5yrUjXxsHwAM5XEIkZ/GBN34cC/Hrz/A9wkrbti8qbh+OVY1tvjwP
CqFZ4/QrMo7ZmtZDfeJ60AdUPGX2us11zLjlHH5tAoGAdRnHF7cCYQ0FV/WNlZ7q
rkasChb8ilLhqqO6D7cQwm8eiAmEDFA6NaOr9889NellycnJRj/Z+JG3deX0TPZk
EoD3cxfbPhj5Xnhg3DmssBf0s/1mnR408xtGdmsCqsBQcBNtVKbJEcLC3YEDDsox
nQkxn0k90nP1oMt1irG2CTUCgYEA2ezejdsrwmCpLq2mubzUgO1W4bOiwE5pgzB4
bLXlVu8fqM0XkUTG5krdvDVDMdfIaOwtX5CRBuh+jEWK93jEBdU9S6OBAGqPf7/i
UemnoCbqUYRQVZMdZ61w8SqWpNI66FJlIvSj0exeDbejyXImhm8sFd7UrBE9YPyv
7L5aWWECgYEAyBxQyPXfIHAJ7NjvCVkXgh4IUz/kt3ZEkZJIuOpbdLqfn0e/1MNm
6IhD2IDYoVhR8uq8JSFuwbRWjX+HNDHC1E4rZpQPEPjjTQyvX7ZHJ48lR3d4Qqt/
bbVEZMQThUGEMq3zRTMW++srfrDmBkaN/uEfj52wTUcvJ7Pk4GsieVg=
-----END RSA PRIVATE KEY-----
"""

class JuSyProxy(object):
    def __init__(self, session):
        self.session = session
        self.started = False
        pass
    def send_dict(self, d):
        s = json.dumps(d)
        self.send_sock.send(ESQ_SEQ_BEG+s+ESQ_SEQ_END)
    def handle_connect(self):
        self.send_dict({"type": "announce", "username": self.session.username, "privkey": self.session.privkey, "owner_hash": OWNER_HASH })
    def loop(self):
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
        
        while True:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
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
            if len(data) == 0:
                break
            if exceptional: 
                break
        print "Connection closed."
        s.close()
 

class JSSession(object):
    def __init__(self):
        self.username = ""
        self.privkey = "" # will be filled by get_privkey_access
        self.gen_user()
        self.diskfile = "/tmp/"+self.username+".iso"
        self.create_disk()
        self.mount_disk()
        self.gen_privkey_access()
    
    def gen_user(self):
        salt = random.randint(100000, 99999)
        self.username = "user"+str(salt)+str(COUNTER)
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
    
    def run(self):
        self.jproxy = JuSyProxy(self)
        self.t = threading.Thread(target=self.jproxy.loop)
        self.t.start()
        
        self.start_accounting()
    
    def start_accounting(self):
        raise NotImplementedError
        
        
        
class Worker(object):
    def __init__(self):
        pass
    
    def loop(self):
        while True:
            time.sleep()

    
    