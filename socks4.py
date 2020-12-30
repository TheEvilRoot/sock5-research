import socket
import re

class SocksSocket(object):
  def __init__(self, addr, port, user):
    self.addr = addr
    self.port = port
    self.user = user
    assert port < 0xffff
    self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.conn_addr = None

  def init(self):
    self.serv.connect((self.addr, self.port))
    return True 

  def connect(self, isa):
    addr, port = isa
    assert port < 0xffff
    ip_re = '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'
    is_ip = bool(re.match(re.compile(ip_re), addr))
    if is_ip:
      addr = bytes([int(x) for x in addr.split('.')])
      extra = b''
    else:
      extra = b'\x00' + addr.encode('utf-8')
      addr = b'\x00\x00\x00\x01'
    port = bytes([port >> 8, port & 0xff])
    command = b'\x04\x01' + port + addr + self.user.encode('utf-8') + extra + b'\x00'
   
    self.serv.sendall(command)
    r = self.serv.recv(8)
   
    print([hex(x) for x in r])
    return r[1] == 90 

  def sendall(self, data, enc='utf-8'):
    if isinstance(data, str):
      data = data.decode(enc)
    self.serv.sendall(data)
    return True

  def recv(self, count=1):
    return self.serv.recv(count)

  def close(self):
    if self.serv is not None:
      self.serv.close()

  def check_version(self, cl, srv):
    if cl != srv or cl != 0x04:
      self.serv.close()
      raise Error(f'socks version missmatch. client {hex(cl)}, server {hex(srv)}, expected 0x04')

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
