#!/usr/bin/env python

import os
import pwd
import sys
import nids
import json
import socket
import mimetools
from StringIO import StringIO

NOTROOT = "nobody"   # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

HOSTNAMES = {}


def _wrap_with_ansi(code):
    def inner(text, bold=False):
        c = "1;%s" % code if bold else code
        return "\033[%sm%s\033[0m" % (c, text)
    return inner

red = _wrap_with_ansi('31')
green = _wrap_with_ansi('32')
yellow = _wrap_with_ansi('33')
blue = _wrap_with_ansi('34')
magenta = _wrap_with_ansi('35')
cyan = _wrap_with_ansi('36')
white = _wrap_with_ansi('37')

stdout = sys.stdout


def pprint_http(data):
    s = StringIO(data)
    req = s.readline()
    message = mimetools.Message(s, 0)
    if message.getheader('content-length'):
        body = s.read(int(message.getheader('content-length')))
    else:
        body = ""
    stdout.write(yellow(req))
    for header, value in message.items():
        if header == 'x-auth-token':
            value = "<TOKEN>"
        print "%s: %s" % (blue(header), value)
    print ""
    if message.type.lower() == 'application/json':
        try:
            json.dump(json.loads(body),
                      sys.stdout, sort_keys=True,
                      indent=2, separators=(',', ': '))
        except ValueError:
            print body
    else:
        print body


def lookup_hostnames(addresses):
    for ip, port in addresses:
        if ip in HOSTNAMES:
            yield HOSTNAMES[ip], port
        else:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except:
                pass
            HOSTNAMES[ip] = name
            yield HOSTNAMES[ip], port


def handle_tcp(tcp):
    addresses = list(lookup_hostnames(tcp.addr))
    hosts = "%s -> %s" % tuple("%s:%s" % a for a in addresses)
    hosts1= "%s -> %s" % tuple(reversed(["%s:%s" % a for a in addresses]))
    stdout.write("#")
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        tcp.client.collect = 1
        tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
    	tcp.discard(0)
    elif tcp.nids_state in end_states:
        if ("HTTP" in tcp.server.data[:tcp.server.count]
                and "HTTP" in tcp.server.data[:tcp.server.count]):
            print green("\n\n%s" % hosts)
            pprint_http(tcp.server.data[:tcp.server.count])
            print green("\n\n%s" % hosts1)
            pprint_http(tcp.client.data[:tcp.client.count])
            print ""
        else:
            print "BINARY"


def main():
    args = sys.argv[1:]
    print args

    nids.param("pcap_filter", ' '.join(args) + ' and tcp')

    # disable portscan detection
    nids.param("scan_num_hosts", 0)

    # disable check-summing
    nids.chksum_ctl([('0.0.0.0/0', False)])

    nids.init()

    (uid, gid) = pwd.getpwnam(NOTROOT)[2:4]
    os.setgroups([gid, ])
    os.setgid(gid)
    os.setuid(uid)
    if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
        print "error - drop root, please!"
        sys.exit(1)

    nids.register_tcp(handle_tcp)

    while True:
        try:
            nids.next()
        except nids.error, e:
            print "nids/pcap error:", e
