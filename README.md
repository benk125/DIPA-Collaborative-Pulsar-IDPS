# DIPA-Collaborative-Pulsar-IDPS
Collaborative intrusion detection and prevention system using apache pulsar ( pub sub ) framework . Distributed architecture used in the cloud (AWS). This project investigates recent evolution in the mirai botnet attacks . The proposed architecture utilizes a deployed AWS distributed series of clusters with apache pulsar installed . Classified attacks are pushed to the pub sub framework , this results in neighbouring domains consuming alerts.

## Getting Started
This project takes results from a a series of deployed instances , however there are a variety of experimental and developmental test files used for local experimentation. 

### Local Deployment


### AWS Deployment
in order to deploy on AWS you will need :
1) An AWS account
2) aws-cli system package
3) python and pip
4) terraform-inventory tool ( this enables ansible to use terraform artifacts)

#### Aws Configure
Once these are set , run :
`aws confiure`

ensure the crednetials match those set on your aws account
** NOTE watch out for regions used

Next Install Ansible :
`pip install ansible`

setup your ssh keys if not created already :
`ssh-keygen -t rsa

#### Terraform : Infrastrcuture as Code
cd into the pulsar/terraform-ansible directory and execute the following :
`terraform init`

Change your instance sizes , regions and zones within:
`terraform.tfvars`

Apply these Chnages using :
`terraform apply`

This will setup a series of bookie, broker,zookeeper and proxy nodes that were specified in the terraform.tfvars. All that needs done is to run the ansible playbook to install the respective services on each node 

#### Install the ansible playbook
`ansible-playbook \
 --user='ec2-user' \
 --inventory='whcih terraform-inventory' \
 pulsar/deploy-pulsar.yaml`
