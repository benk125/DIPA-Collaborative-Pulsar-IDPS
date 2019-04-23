import os
import time
from scapy.all import DNS, DNSQR, IP, sr1, UDP

time.sleep(10)

time.sleep(32)
os.system('hping3 -S -2 -p 53 -s 53 -c 3 10.0.0.4 &')
time.sleep(0.5)
os.system('hping3 -S -p 48101 -s 48101 10.0.0.1 &')
os.system('hping3 -S -p 23 -c 10 10.0.0.4 &')
time.sleep(3)
os.system('hping3 -1 10.0.0.x --rand-dest -I eth0 -i u800000 &')
time.sleep(3)
os.system('killall -9 hping3')
time.sleep(9)
"""
os.system('hping3 -S -p 23 --rand-source -i u90000 10.0.0.1 ')
time.sleep(20)
"""
os.system('killall -9 hping3')




