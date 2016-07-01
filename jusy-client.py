import urllib2, json, sys, subprocess, os

CLIENT_HASH = sys.argv[1] # first argument should be client hash

response = urllib2.urlopen('https://proxy.junk.systems/order/' + CLIENT_HASH)
r = response.read()
d = json.loads(r)
if not "privkey" in d:
    print "Error", repr(d)
    sys.exit(1)

file("./pkey", "w").write(d["privkey"])
os.chmod("./pkey", 0o600)
d["privkey"] = "<hidden>"
print "Connect with", repr(d)
subprocess.call(["ssh", "-i", "./pkey", "-oStrictHostKeyChecking=no", "-l", d["username"], "-p", str(d["port"]), "localhost"])
