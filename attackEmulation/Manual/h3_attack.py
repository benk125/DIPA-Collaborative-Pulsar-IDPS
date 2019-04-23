import os
import time
from scapy.all import DNS, DNSQR, IP, sr1, UDP

time.sleep(10)

time.sleep(24)
os.system('hping3 -S -2 -p 53 -s 53 -c 3 10.0.0.4 &')
time.sleep(0.5)
os.system('hping3 -S -p 48101 10.0.0.5 &')
os.system('hping3 -S -p 23  -c 10 10.0.0.4 &')
time.sleep(6)
os.system('hping3 -1 10.0.0.x --rand-dest -I eth0 -i u800000 &')
time.sleep(15)
"""
os.system('hping3 -S -p 23 --rand-source -i u300000 10.0.0.1 &')
time.sleep(20)
"""
os.system('killall -9 hping3')



