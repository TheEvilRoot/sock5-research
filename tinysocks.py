#!/usr/bin/env python3

import socket
import sys

def hexlify(s):
  if isinstance(s, str):
    s = s.encode('utf-8')
  return ' '.join([hex(x) for x in s])

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print('connecting...')
serv.connect(('188.124.36.164', 1080))
print('connected')

method_pack = b'\x05\x01\x00'

print('sending method pack')
serv.sendall(method_pack)

print('recv for method resp...')
r = serv.recv(2)
print('method resp:', hexlify(r))

if r[0] != method_pack[0]:
  print('socks version missmatch: client:', method_pack[0], 'server:', r[0])
  serv.close()
  sys.exit(1)

if r[1] == 0x00:
  print('using no auth')
else:
  print('auth method', r[1], 'is not supported')
  serv.close()
  sys.exit(1)


# api.myip.com
# '61 70 69 2e 6d 79 69 70 2e 63 6f 6d'

domain = b'api.ipify.org'
domain_len = b'\x0d'
connect_pack = b'\x05\x01\x00\x03' + domain_len + domain + b'\x00\x50'

print('sending connect pack...')
serv.sendall(connect_pack)

print('recv for connect resp...')
r = serv.recv(4)
print('connect resp header:', hexlify(r))
if r[-1] == 0x1:
  print('got resp with ipv4 addr')
  l = 0x4
elif r[-1] == 0x3:
  print('got resp with domain addr')
  r += serv.recv(1)
  l = r[-1]
elif r[-1] == 0x4:
  print('got resp with ipv6 addr')
  l = 0x10
else:
  print('unknown addr type:', hex(r[-1]))
  serv.close()
  sys.exit(1)

print('reading address with len:', hex(l))
r += serv.recv(l + 2)
print('connect resp:', hexlify(r))

if r[3] == 0x1:
  print('address:', '.'.join([str(x) for x in r[4:-2]]))
elif r[3] == 0x3:
  l = r[4]
  print('address:', r[4:-3].decode('utf-8'))
elif r[3] == 0x4:
  print('address:', hexlify(r[4:-2]))
print('port:', (r[-2] << 8) + r[-1])

print('sending http request')
req = b"GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nAccept: */*\r\nUser-Agent: curl/1.1.1\r\n\r\n"

serv.sendall(req)
print('recv for response...')

r = b'' 
while True:
  r += serv.recv(1)
  print(len(r), r.decode('utf-8'), hexlify(r))
  if input() == 'n':
    break
 

print('closing...')
serv.close()



