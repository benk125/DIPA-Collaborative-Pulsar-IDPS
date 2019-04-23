#!/usr/bin/env python

import pulsar
from pulsar import ConsumerType
import time
from datetime import datetime, timedelta
import netifaces as ni
import numpy as np
from threading import Thread

class PulsarConsumer():

    def __init__(self, *args, **kwargs):
        self.ip = ni.ifaddresses('enp0s8')[ni.AF_INET][0]['addr']
        self.client = pulsar.Client('pulsar://{}:6650'.format(self.ip))
        #timeStack = deque([],5)

    def runall(self):
        self.num_subnets = int(raw_input("How Many Subnets are being tested ?"))
        self.consumer_arr = [None] * self.num_subnets
        self.time_details = np.zeros((self.num_subnets, 2))
        for i in range(0, self.num_subnets):
            self.mass_subscriptions(i)
            t = Thread(target=self.receiver, args=(i,self.num_subnets))
            t.daemon = True
            t.start()
            time.sleep(2)
        self.merging()
        #t = Thread(target=self.merging, args=())
        #t.start()

    def mass_subscriptions(self,vm_index):
        self.consumer_arr[vm_index] = self.client.subscribe('non-persistent://sample/standalone/timer/time{}'.format(vm_index),
                              'my-subbing{}'.format(vm_index),
                              consumer_type=ConsumerType.Shared)

    def receiver(self,vm_index, num_subnets): 
        while True:
            try:
                consumer = self.consumer_arr[vm_index]
                msg = consumer.receive(timeout_millis=10000)

                print("Received message from subnet {} :  '{}' id= '{}'".format( vm_index, msg.data() , msg.message_id()))
                msg_arr = msg.data().split("@")
                msg_print = datetime.strptime(msg_arr[1], "%Y-%m-%d %H:%M:%S.%f")
                nowTime = datetime.now()
                print("nowTime :", nowTime)
                latency = nowTime - msg_print
                self.time_details[vm_index, 0] = msg_arr[0]
                self.time_details[vm_index, 1] = latency.total_seconds()
            except Exception:
                print("No message Received from subnet {} in 10 seconds".format(vm_index))

    def merging(self):
        while True:
            if np.count_nonzero(self.time_details) == self.num_subnets*2:
                self.minTotalTime = float(min(self.time_details, key=sum)[0]) + float(min(self.time_details, key=sum)[1])
                self.maxTotalTime = float(max(self.time_details, key=sum)[0]) + float(max(self.time_details, key=sum)[1])
                self.meanTotalTime = np.mean(self.time_details.sum(axis=1))
                print("Min Total Time : ", self.minTotalTime)
                print("Max Total Time : ", self.maxTotalTime)
                print("Mean Total Time : :", self.meanTotalTime)
                self.time_details = np.zeros((self.num_subnets,2))
            else:
                print("\nAll subnets havents produced a results yet")
                time.sleep(10)
                    
                        
run = PulsarConsumer()
run.runall()
