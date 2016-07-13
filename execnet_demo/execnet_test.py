import pyjusy, execnet, sys

client_hash = sys.argv[1] # first argument is your client_hash
proc_count = int(sys.argv[2]) # second argument is amount of contracts to create

pyjusy.set_client_hash(client_hash) # sets client identity

jusy_channels = pyjusy.open_channels(proc_count, python=True) # will open **at most** proc_count channels, depends on supply
print("Opened %s channels" % len(jusy_channels))

if not jusy_channels:
    print("Could not open a single channel, please retry")
    sys.exit()

cdfd = open("creds","w")
for ch in jusy_channels: cdfd.write(repr(ch.credentials)+"\n")
cdfd.close()

EXECNET_GATEWAYS = [ 
'ssh=-oControlMaster=auto \
-oControlPath=~/.ssh/control:%h:%p:%r \
-oControlPersist=5 \
-oUserKnownHostsFile=/dev/null \
-oStrictHostKeyChecking=no \
-i {privkey_file} \
-l {user} \
-p {port} \
{host}\
//python=python//chdir=/home/{user}'\
.format(user=ch.username, host=ch.host, port=ch.port, privkey_file=ch.privkey_file) for ch in jusy_channels]
# instead of "python" it is more convenient to use "pypy" for math
 
# the same can be written as (less readable):
# EXECNET_GATEWAYS = [ "ssh="+" ".join(ch.ssh_param_list[1:]) for ch in jusy_channels]

group = execnet.Group(EXECNET_GATEWAYS)

def count_primes_in_range(channel):
    while not channel.isclosed():
        lower, upper = channel.receive()
        ret = []
        for num in range(lower,upper + 1):
           if num > 1:
               for i in range(2,num):
                   if (num % i) == 0:
                       break
               else:
                   ret.append(num)
        channel.send((lower, upper, len(ret)))

channels = [gw.remote_exec(count_primes_in_range) for gw in group]
print "Execnet channels", len(channels), repr(channels)

start = 10000
step = 1000

while True:
    for channel in channels:
        try:
            channel.send((start, start+step))
        except:
            pass
        start += step
    i=0
    # since we receive from all channels first
    # we effectively sync on this step
    # it is better to rather use execnet callbacks instead
    closed = 0
    for channel in channels:
        try:
            print i, channel.receive()
        except:
            print i, "closed"
            closed += 1
        i+=1
    if closed == i:
        print 'All finished'
        break

