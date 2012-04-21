
This repository contains a collection of network tools written in PHP.

All these tools require raw sockets and will either require to be run as root or require your PHP binary to have the `cap_net_raw` capability. This capability can be set using:

`sudo setcap cap_net_raw=eip /usr/bin/php5`


icmpdump.php
============

Print information about incoming ICMP packets.

<pre>
erik@localhost:~$ sudo ./icmpdump.php
icmpdump started
12:05:18 90.213.62.21 > 80.94.76.6 protocol=ICMP type=[Destination Unreachable] code=[Destination host unreachable]
        data:  80.94.76.6 > 90.213.62.21 protocol=UDP sourceport=6881 destinationport=49840
12:05:19 121.129.32.124 > 80.94.76.6 protocol=ICMP type=[Destination Unreachable] code=[Destination host unreachable]
        data:  80.94.76.6 > 121.129.32.124 protocol=TCP
12:05:20 77.28.53.220 > 80.94.76.6 protocol=ICMP type=[Destination Unreachable] code=[Communication administratively prohibited]
        data:  80.94.76.6 > 77.28.53.220 protocol=UDP sourceport=6881 destinationport=40703
</pre>


ping.php
========

Test the reachability of a host.

`php ping.php [-n] destination`


traceroute.php
==============

Display the route to a host.

`php traceroute.php [-n] destination`

