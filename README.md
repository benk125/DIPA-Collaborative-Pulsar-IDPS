# DIPA-Collaborative-Pulsar-IDPS
Collaborative intrusion detection and prevention system using apache pulsar ( pub sub ) framework . Distributed architecture used in the cloud (AWS). This project investigates recent evolution in the mirai botnet attacks . The proposed architecture utilizes a deployed AWS distributed series of clusters with apache pulsar installed . Classified attacks are pushed to the pub sub framework , this results in neighbouring domains consuming alerts.

# NOTE
This project is part of ELE4001 FInal year project
This project s experimental and a proof of concept to detail Pulsar's Viability in collaborative IDPS

## Getting Started
This project takes results from a a series of deployed instances , however there are a variety of experimental and developmental test files used for local experimentation. 

## Prerequisites
please install the requirements.txt fiel on each our your source domains before further installation.

```
sudo pip install -r requirements.tx
```

For the pulsar management points ( be this on your local machine or on another VM) , make sure the requirements_pulsar.txt is installed in the local enviroment. NOTE this is required as you may  experience ansible issues regarding shell commands with incompatiable versioning

```
sudo pip install -r requirements_pulsat.txt
``` 

### Virtual Machine Testbeds
The aim of this project is to protect a series of destination domains upon receviving a malcious information event from a enighbouring source domain. For this a collection of virtual machines were used to emulate isolated Testbeds. 

For Quick testbed deployment , download the mininet ISO at :
http://mininet.org/download

Alernatively:
install mininet from source 

### VM Isolation:
To isolate the VMS use Quagga. Quagga is a network routing simulator. Each VM should contain two interfaces. THe first interface is a NAT to allow hosts to access the internet. The second interfaces is a Host-only , this will receive an IP to allow each domain to receive an IP.

Follow this guide to setup quagga on each domain. The pulsar proxy should contain 6 interfaces , each on the same subnet of one of the host-only adapter on the LAN. To prevent interface cross link run the following commands: 

``` 
iptables -A FOWARD -i eth0 -o eth1 -J DROP
iptables -A FOWARD -i eth0 -o eth2 -J DROP
iptables -A FOWARD -i eth1 -o eth0 -J DROP
iptables -A FOWARD -i eth1 -o eth2 -J DROP
iptables -A FOWARD -i eth2 -o eth0 -J DROP
iptables -A FOWARD -i eth2 -o eth1 -J DROP
```
Useful Quagga link : https://www.brianlinkletter.com/how-to-build-a-network-of-linux-routers-using-quagga

### Ryu Installation
Install the Ryu controller onto the testBeds

```
pip install ryu
```
This contains example files such as simpleSwitch13 which this project was based off. For further examples check knetsolutions.

### Pulsar Local Deployment
To deploy pulsar on a local cluster Download the pulsar binary at:
https://pulsar.apache.org/docs/fr/standalone

To run a Standalone cluster on the VM use :

```
bin/pulsar standalone 
```

to access this IP / service url use :

```
pulsar://<vm-host-only-adpater-ip>:6650
```

For TLS use port 6651

### Pulsar AWS Deployment
in order to deploy on AWS you will need :
1) An AWS account
2) aws-cli system package
3) python and pip
4) terraform-inventory tool ( this enables ansible to use terraform artifacts)

#### Aws Configure
Once these are set , run :
```
aws confiure
```

ensure the crednetials match those set on your aws account
** NOTE watch out for regions used

Next Install Ansible :
```
pip install ansible`
```

setup your ssh keys if not created already :
```
ssh-keygen -t rsa
```

#### Terraform : Infrastructure as Code
cd into the pulsar/terraform-ansible directory and execute the following :
```
terraform init
```

Change your instance sizes , regions and zones within:
```
terraform.tfvars
```

Apply these Chnages using :
```
terraform apply
```

This will setup a series of bookie, broker,zookeeper and proxy nodes that were specified in the terraform.tfvars. All that needs done is to run the ansible playbook to install the respective services on each node 

#### Install the ansible playbook
```
ansible-playbook \
 --user='ec2-user' \
 --inventory='whcih terraform-inventory' \
 pulsar/deploy-pulsar.yaml
```

## System execution 
To tes the system functionality after full completeion of the above task run thefollowing commands.

### Pulsar level
Before starting the DIPA client , the pulsar pub sub service will need to be running. If deployed on aws , the service_url is accessible 24/7 and you don't needstart the service

Run the following on local Deployment:

```
bin/pulsar standalone 
```





### Domain level
To run the DIPA client on each the setup VMS use the follwing dependent on your enviroment.

#### Deployed on cloud
```bash
ryu run src/ryu/deployed_controller/DIPA_Controller.py
```
or
```bash
ryu-manager src/ryu/deployed_controller/DIPA_Controller.py
```

#### Local deployment
Notes this deployment type is only experimental and not used for test results
```bash
ryu run src/ryu/local_controller/DIPA_Controller.py
```
or
```bash
ryu-manager src/ryu/local_controller/DIPA_Controller.py
```


This will Run the DIPA CLient to classify and collaboratively alert neighbouring domains

## Authors
Ben Kelly - Edge based Network attack protection using Apache Pulsar

## Contact
If installing or testing the configuration setup,feel free to contact me with questions or help needed. 

## Acknowledgements
Apache Pulsar / Streamlio for deployment help on aws

tyagian - https://github.com/tyagian/SDN-DDOS-BOTNET-DETECTION-MITIGATION (For attack simulation files)

mishra14- https://github.com/mishra14/DDoSAttackMitigationSystem (For ingress policy rate help)
