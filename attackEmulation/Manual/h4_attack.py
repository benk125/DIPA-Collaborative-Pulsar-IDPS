import os
import time

time.sleep(10)

os.system('hping3 -1 10.0.0.x --rand-dest -I eth0 -i u300000 &')
time.sleep(16)
#os.system('hping3 -S -p 23  -i u999999 10.0.0.8 &')
time.sleep(8)
os.system('hping3 -S -p 23  -i u999999 10.0.0.3 &')
#time.sleep(4)
#os.system('hping3 -S -p 23  -i u999999 10.0.0.5 &')
#time.sleep(2)
#os.system('hping3 -S -p 23  -i u999999 10.0.0.6 &')
#time.sleep(2)
#os.system('hping3 -S -p 23  -i u999999 10.0.0.7 &')




