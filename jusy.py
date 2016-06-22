import socket,select,json

ESQ_SEQ_BEG = "~\'\"\"\"{~~."
ESQ_SEQ_END = ".~~\'\"\"\"{~"
ESQ_LEN = len(ESQ_SEQ_BEG)
MSG_LEN = 8192

def netcat():
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect(("localhost", 8022))
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect(("p1.plotti.co", 8880))
    inputs = [ s1, s2 ]
    outputs = [ ]
    data = ""
    msg_wait = False
    msg = ""
    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for s in readable:
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
    
netcat()
