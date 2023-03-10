wget http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
echo "/ip firewall address-list remove [/ip firewall address-list find list=CN]" > cnip.rsc
echo "/ip firewall address-list" >> cnip.rsc
grep "|CN|ipv4" delegated-apnic-latest | awk -F'|' '{print "add address="$4"/"32-int(log(int($5))/log(2))" disabled=no list=CN"}' >> cnip.rsc
echo "add address=10.10.0.0/16 disabled=no list=CN" >> cnip.rsc
rm delegated-apnic-latest
