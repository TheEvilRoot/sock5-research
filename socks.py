import socket
import re

class SocksSocket(object):
  def __init__(self, addr, port, cred=None):
    self.addr = addr
    self.port = port
    self.cred = cred
    assert port < 0xffff
    self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.auth = 0x00 
    self.conn_addr = None

    if cred is not None:
      assert len(cred) == 2
      assert len(cred[0]) <= 0xff
      assert len(cred[1]) <= 0xff
      self.auth = 0x02

  def init(self):
    self.serv.connect((self.addr, self.port))
    return self.socks_negotiate()

  def connect(self, isa):
    addr, port = isa
    assert port < 0xffff
    ip_re = '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'
    is_ip = bool(re.match(re.compile(ip_re), addr))
    if is_ip:
      atype = 0x01
      addr = bytes([int(x) for x in addr.split('.')])
    else:
      atype = 0x3
      addr = addr.encode('utf-8')
    port = bytes([port >> 8, port & 0xff])
    assert len(addr) <= 0xff
    command = b'\x05\x01\x00' + bytes([atype]) + bytes([len(addr)]) + addr + port
   
    self.serv.sendall(command)

    r = self.serv.recv(4)
    self.check_version(command[0], r[0])

    if r[-1] == 0x1:
      addr_len = 0x4
      to_addr = lambda x: '.'.join([str(y) for y in x])
    elif r[-1] == 0x3:
      r += self.serv.recv(1)
      addr_len = r[-1]
      to_addr = lambda x: x.decode('utf-8')
    elif r[-1] == 0x4:
      addr_len = 0x10
      to_addr = lambda x: ':'.join([hex(y) for y in x])
    else:
      self.serv.close()
      raise Error(f'unknown atype in connect response {r[-1]}')

    r += self.serv.recv(addr_len + 2)
    self.conn_addr = (to_addr(r[4:-2]), (r[-2] << 8) + r[-1])
    
    return r[1]

  def sendall(self, data, enc='utf-8'):
    if isinstance(data, str):
      data = data.decode(enc)
    if self.conn_addr is None:
      return False
    self.serv.sendall(data)
    return True

  def recv(self, count=1):
    if self.conn_addr is None:
      return None
    return self.serv.recv(count)

  def close(self):
    if self.serv is not None:
      self.serv.close()

  def check_version(self, cl, srv):
    if cl != srv or cl != 0x05:
      self.serv.close()
      raise Error(f'socks version missmatch. client {hex(cl)}, server {hex(srv)}, expected 0x05')

  def user_pass_negotiate(self):
    assert cred is not None
    # version of subnegotiation
    auth_header = b'\x01'
    # ulen + uname
    auth_header += bytes([len(self.cred[0])]) + self.cred[0].encode('utf-8')
    # plen + passwd
    auth_header += bytes([len(self.cred[1])]) + self.cred[1].encode('utf-8')

    self.serv.sendall(auth_header)

    r = self.serv.recv(2)
    self.check_version(auth_header[0], r[0])

    return r[-1] == 0x00
    
  def socks_negotiate(self):
    header = b'\x05'
    if self.cred is None:
      header += b'\x01\x00'
    else:
      header += b'\x02\x02\x00'
    self.serv.sendall(header)
    r = self.serv.recv(2)
    self.check_version(header[0], r[0]) 
    if r[-1] == 0xff:
      self.serv.close()
      raise Error(f'socks server cannot use such auth methods')
    elif r[-1] == 0x00:
      self.auth = 0x00
      return True
    elif r[-1] == 0x02:
      self.auth = 0x02
      return self.user_pass_negotiate()
    else:
      self.serv.close()
      raise Error(f'socks server method {hex(r[-1])} is not supported')
    return True

