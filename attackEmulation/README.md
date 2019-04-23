# Attack Files 
This section is split into multiple different attack emulations

Each of the attacks are modelled of the the early phases of a botnet attack
The CTU13 Dataset constructed by stratosphere is proposed if you want to use a more comprehensive dataset against this system .

# Manual 
These tests were used to demo the different stages of the attack for the project showcase and oral. This consists of a series of scripts that should be run on each of the nodes . These scripts are best used with MiniNam to show packets traversing throughout the network

To run the script execute the following in the mininet shell

``` 
xterm h1
```
Once inside your given host , run the given script as follows : 

```
Sudo python h3_attack.py
```

# Bonesi 
This is an popular attack tool that is highly configurable . This was used to tbench mark the collaborative performacne when there was up to 500bots scanning within the network . This takes a lsit of given ips and scans ports on port 23 a 500 packets per second . Run the server on a single node and connect to it with multiple client . This is done using the following :

```
sudo bonesi --ips 500bots.txt -p 23 --send_rate 500 --max_bots 500 --url http://<host_ips that server is on> -d eth1
```

# Pcaps
A collection of pcaps have been gathered to test againist the algorithm . The most useful testfile is the Mirai command and control pcap. This pcap was captured using tcpdump againist a live botnet attack ran in a test system. To run these files use 

```
tcpreplay --intf1=h1-eth1 <pcap_file.pcap>
```

# Physical demo
These files have been supplied by tyadian SDN DDOS botnet detection and mitigation file. This use emulates a botnet attack through porzt 8080 , this is not tailored towards mirai but can be used aganist the DIPA algorithm.
Similarly these scripts should be run on each of the nodes like the manual testing files. Please Refer to mnaul testing 

# Scripts 
These are additional script that can be used for background traffic or to perform a basic DDoS attack

