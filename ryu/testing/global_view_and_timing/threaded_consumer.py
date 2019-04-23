#!/usr/bin/env python

import pulsar
from pulsar import ConsumerType
import time
from datetime import datetime, timedelta
import netifaces as ni
import numpy as np
from threading import Thread
from collections import deque

class PulsarConsumer():

    def __init__(self, *args, **kwargs):
        self.ip = ni.ifaddresses('enp0s8')[ni.AF_INET][0]['addr']
        self.client = pulsar.Client('pulsar://{}:6650'.format(self.ip))
        self.flows = {0:{}, 1:{}}
        #timeStack = deque([],5)

    def runall(self):
        self.num_subnets = int(raw_input("How Many Subnets are being tested ?"))
        self.consumer_arr = [None] * self.num_subnets
        self.consumer_arr2 = [None] * self.num_subnets
        self.elements = [None] * self.num_subnets
        self.time_details = np.zeros((self.num_subnets, 2))
        for i in range(0, self.num_subnets):
            self.mass_subscriptions(i)
            t = Thread(target=self.receiver, args=(i,self.num_subnets))
            t.daemon = True
            t.start()
            time.sleep(1)
            t = Thread(target=self.global_updates, args=(i,self.num_subnets))
            t.daemon = True
            t.start()
            time.sleep(1)
        self.merging()

    def mass_subscriptions(self,vm_index):
        self.consumer_arr[vm_index] = self.client.subscribe('non-persistent://sample/standalone/timer/time{}'.format(vm_index),
                              'my-subbing{}'.format(vm_index),
                              consumer_type=ConsumerType.Shared)
        self.consumer_arr2[vm_index] = self.client.subscribe('non-persistent://sample/standalone/update/update{}'.format(vm_index),
                              'updates{}'.format(vm_index),
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

    def dict_handler(self,vm_index,my_dict, eth_src, tcp_dst, packet_count):
        try:
            my_dict[vm_index][eth_src][tcp_dst].appendleft(packet_count)
        except:
            try:
                my_dict[vm_index][eth_src][tcp_dst] = deque([],5)
                my_dic[vm_index][eth_src][tcp_dst].appendleft(packet_count)
            except:
                my_dict[vm_index][eth_src] = {tcp_dst : deque([],5)}
                my_dict[vm_index][eth_src][tcp_dst].appendleft(packet_count) 
        return my_dict

    def anomoly(self, eth_src , tcp_dst, vm_index):
        total = 0
        tmp = []

        self.elements[vm_index] = np.mean(self.flows[vm_index][eth_src][tcp_dst], axis=0)
        tmp = filter(lambda x: x != None, self.elements)
        if len(tmp) > 1 :
            mean = np.mean(tmp, axis=0)
            std = np.std(tmp, axis=0)
            print("Mean : {} , Std :{}".format(mean, std))
        else:
            print("collaborative mode not in use, tmp : ", tmp)

    def global_updates(self,vm_index, num_subnets):
        while True:
            try:
                consumer = self.consumer_arr2[vm_index]
                msg = consumer.receive(timeout_millis=10000)

                print("Received message from subnet {} :  '{}' id= '{}'".format( vm_index, msg.data() , msg.message_id()))
                msg_arr = msg.data().split("@")
                self.flows = self.dict_handler(vm_index, self.flows, msg_arr[0],msg_arr[1], float(msg_arr[2]))
                self.anomoly(msg_arr[0],msg_arr[1], vm_index)

            except Exception:
                print("gettin here".format(vm_index))
                    
                        
run = PulsarConsumer()
run.runall()
