#!/usr/bin/env python3

import socket
import sys

from socks4 import SocksSocket

sock = SocksSocket(sys.argv[1], int(sys.argv[2]), 'user')
print('hw')
print(sock.init())

def request():
  print(sock.connect(('50.19.243.236', 80)))
  req = b"GET /?format=json HTTP/1.1\r\nConnection: close\r\nHost: api.ipify.org\r\nAccept: */*\r\nUser-Agent: curl/1.1.1\r\n\r\n"

  sock.sendall(req)

  r = b''
  while True:
    rr = sock.recv()
    if rr is None or len(rr) == 0:
      print('none')
      break
    print(len(r), r)
    r += rr
  print(r.decode('utf-8'))


request()
