#!/usr/bin/env python
# --*--coding: utf-8 --*--

import os
import time
import threading
from subprocess import Popen,PIPE,STDOUT,call
from datetime import datetime
from scapy.all import TCP, IP, sniff, Raw
from logger import log

COUNTGET = []

def increment(url):
    print url
    global COUNTGET
    #COUNTGET.append('==>'.join([url, os.environ['HOME']]))
    COUNTGET.append(url)

def printit():
  threading.Timer(5.0, printit).start()

  if (len(COUNTGET) == 0):
    print "Lista vacia"
  else:
    if (COUNTGET.count('192.168.31.112:30080/get-ip') > 5):
        print "aaaa"
        #os.system("sshpass -p 'raspberry' ssh pi@192.168.31.232 'bash -s' < /home/worker00/Documents/tfg_project/nodeSelector/move2worker00.sh")
        os.system("ssh -T pi@192.168.31.232 './tfg_project/nodeSelector/move2worker00.sh'")
        #subprocess.call(["sshpass", "-p", "raspberry", "ssh", "pi@192.168.31.232", "bash", "-s" , "<", "/home/worker00/Documents/tfg_project/nodeSelector/move2worker00.sh"])
        #os.system("sshpass -p \'raspberry\'ssh pi@192.168.31.232  \'./home/pi/tfg_project/nodeSelector/move2worker00.sh\'")
        del COUNTGET[:]
        #proc = subprocess.Popen('ssh pi@192.168.31.232 \'./tfg_project/nodeSelector/move2worker00.sh\'',shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
        #stdout_value, stderr_value = proc.communicate('through stdin to stdout\n')
        #print '\tcombined output:', repr(stdout_value)
        #print '\tstderr value   :', repr(stderr_value)


    if (COUNTGET.count('192.168.31.102:30080/get-ip') > 5):
        print "bbb"
        #subprocess.call(["sshpass", "-p", "'raspberry'", "ssh", "pi@192.168.31.232", "'bash -s'" , "<", "/home/worker00/Documents/tfg_project/nodeSelector/move2worker01.sh"])
        os.popen("sshpass -p 'raspberry' ssh pi@192.168.31.232 'bash -s' < /home/worker00/Documents/tfg_project/nodeSelector/move2worker01.sh").read()





class HttpRequestCapture(object):
    def __init__(self, port=80, iface='en0', filter='tcp'):
        self.port = port
        self.iface = iface
        self.filter = filter

        self.http_load = ''
        self.http_fragged = False
        self.http_pack = None

    def parser(self, pkt):
        if not pkt.haslayer(Raw):
            return
        elif self.port not in [pkt[TCP].sport, pkt[TCP].dport]:
            return

        self.parse_http(pkt[Raw].load, pkt[IP].ack)

    def parse_http(self, load, ack):
        # try decode to utf-8
        try:
            load = load.decode('utf-8')
        except (AttributeError, UnicodeDecodeError):
            pass

        if ack == self.http_pack:
            self.http_load = self.http_load + load
            load = self.http_load
            self.http_fragged = True
        else:
            self.http_load = load
            self.http_pack = ack
            self.http_fragged = False

        try:
            header_lines = load.split('\r\n\r\n')[0].split('\r\n')
        except ValueError:
            header_lines = load.split('\r\n')

        http_req_url = self.get_http_req_url(header_lines)

        if http_req_url:
            log(time.strftime('%a, %d %b %Y %H:%M:%S %z: '), http_req_url, True)
            increment(http_req_url)

    @staticmethod
    def get_http_req_url(header_lines):

        host = ''
        uri = ''
        http_method = header_lines[0][0:header_lines[0].find('/')].strip()

        if http_method != 'GET':
            return

        for line in header_lines:
            # find host
            if 'Host:' in line:
                host = line.split('Host: ')[1].strip()

            # find uri
            if 'GET /' in line:
                uri = line.split('GET ')[1].split(' HTTP/')[0].strip()

        return ''.join([host, uri])

    def start(self):
        sniff(
            prn=self.parser,
            filter=self.filter,
            iface=self.iface,
        )



if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    # get args from cli
    parser.add_argument('--port', default=80, type=int)
    parser.add_argument('--iface', default='en0', type=str)
    parser.add_argument('--filter', default='tcp', type=str)
    args = parser.parse_args()

    printit()

    try:
        log('HTTP REQUEST CAPTURE STARTED')
        httpRequestCapture = HttpRequestCapture(
            port=args.port,
            iface=args.iface,
            filter=args.filter,
        )
        httpRequestCapture.start()
    except KeyboardInterrupt:
        exit()
