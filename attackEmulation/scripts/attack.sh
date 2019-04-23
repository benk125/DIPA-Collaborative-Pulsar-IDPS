file=/home/mininet/Downloads/output.pcap
for i in {1..5}
do
    echo $file
    interface=`ls -1 /sys/class/net | grep eth`
    echo $interface
    tcpreplay --loop 3 -K --mbps 100 --intf1=$interface $file &
    outfile="outfile$i.pcap"
    tcprewrite --seed=423 --infile=$file --outfile=$outfile &
    file=$outfile
done
