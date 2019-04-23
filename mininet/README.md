The following File Contains a 3 layer canonical fattree. A common enterpise Topology.

The files is configurations and can specifiy the density of the tree

To run this file use

Sudo python fattree.py




If you want to change the density of the topology use:

Sudo mn --topo=fattree,depth=3,fanout=<density> --custom fattree.py --controller=remote --switch=ovsk,protocols=OpenFlow13
