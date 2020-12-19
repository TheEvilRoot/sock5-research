#!/usr/bin/env python3

import socket
import sys

from socks import SocksSocket

sock = SocksSocket('188.124.36.164', 1080)
print(sock.init())
print(sock.connect(('api.ipify.org', 80)))
req = b"GET /?format=json HTTP/1.1\r\nConnection: close\r\nHost: api.ipify.org\r\nAccept: */*\r\nUser-Agent: curl/1.1.1\r\n\r\n"
sock.sendall(req)

r = b''
while True:
  rr =sock.recv()
  if rr is None or len(rr) == 0:
    break
  r += rr
print(r.decode('utf-8'))



