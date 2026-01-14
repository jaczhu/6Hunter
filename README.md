# 6Hunter: An Efficient IPv6 Router Interface Discovery Tool
6Hunter is an efficient IPv6 router interface discovery scanner based on prefix prediction, which runs on GNU/Linux operating system. By sending ICMPv6 Echo Request messages and receiving ICMPv6 error messages, 6Hunter achieves the discovery of IPv6 router interface addresses.

## Building 6Hunter
To run 6Hunter, you need to first configure Go environment. Then, 6Hunter can be compiled by running:

`go build`

## Using 6Hunter
6Hunter is developed in Go. Below is a usage example:

`./6Hunter -i 2 -s 2408:400a:e:8b00:363:45cc:b494:dfc -m 00:16:3e:3a:aa:85 -g ee:ff:ff:ff:ff:ff -a address_file -b 5000000 -min-wildcard 4 -min-cluster 50 -r 10000 -c 20`

Parameter Description:
-i	The index of the network interface used for sending packets
-s	The source IPv6 address of the scanning packets
-m	The MAC address of the network interface used for sending packets
-g	The gateway MAC address
-a	The path to the IPv6 address file
-b	The scanning budget
-min-wildcard	The minimum number of wildcards allowed for prefix clustering
-min-cluster	The maximum size of the prefix cluster for prefix clustering
-r	The packet sending rate
-c	The number of scanning iterations
