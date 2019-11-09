# Network Intrusion Analysis Pastable

##### Most of these came during my time in SANS SEC503.  Much credit to their material and to David Hoelzer.

## tcpdump

To locate the absolute date and time of the packets:

`tcpdump -n -r dmz.cap -tttt -c 1`

### Common tcpdump Macros

1. host - IP Address of host
2. net - designate a subnet; even partial works 'net 192.168'
3. port - source OR destination port
4. src host
5. dst host
6. src net
7. dst net
8. src port
9. dst port
10. icmp - proto field ip[9] = 1
11. tcp - proto field ip[9] = 6
12. udp - proto field ip[9] = 17

### tcpdump BPF filters levels

Straight from the 503 Course.

1. Most Exlusive - Select packets where *ONLY* (No others) these flags (ex. SYN/FIN) are set:

    `tcpdump -r pcap.pcap -nt 'tcp[13] = 0x03'`

2. Less Exclusive - Select packets where *BOTH* SYN/FIN are set and CAN have any other flag set:

    `tcpdump -r pcap.pcap -nt 'tcp[13] & 0x03 = 0x03'`

3. Least Exclusive - Select packets where *EITHER* SYN *OR* FIN are set; and an other flag can be set:

    `tcpdump -r pcap.pcap -nt 'tcp[13] & 0x03 !=0'`

### Flags Table
|2<sup>3</sup>|2<sup>2</sup>|2<sup>1</sup>|2<sup>0</sup>|-|2<sup>3</sup>|2<sup>2</sup>|2<sup>1</sup>|2<sup>0</sup>|
|---|---|---|---|---|---|---|---|---|
|CWR|ECE|URG|ACK|---|PSH|RST|SYN|FIN
|8|4|2|1|-|8|4|2|1|

### Isolatinng Hosts and Networks

src net; dst net

`src net 192.168.0.0/16 and not dst net 192.168.0.0/16`

### Isolating Packets with Specific Flags

To find SYN packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13]=0x02'`

To find SYN/ACK packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13] = 0x12'`

To find  SYN ACK along with any other flags:

`tcpdump -nt -r int-server.pcap 'tcp[13] & 0x02 = 0x02'|awk '{print $4}'|cut -d '.' -f5|sort -un`

To find SYN/ACK packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13] = 0x12'`

To find SYN/ACK packets with ENC Bits ignored (allowing for ENC Enabled Systems)

`tcpdump -r dmz.cap -n 'tcp[13]&0x3f=0x12'`

Find ECN enabled hosts in a home network

`tcpdump -r backbone.cap -nt 'tcp[13]&0xc0 = 0x40 and tcp[13]&0x3f=0x12'`

Find a host from 192.168.0.0/16 that has port 111 open:

`tcpdump -r backbone.cap -n 'src net 192.168.0.0/16 and tcp[13] & 0x3f = 0x12 and tcp src port 111'`

Finding Fast Open or Data on the SYN packets

`tcpdump -r backbone.cap -nt 'tcp[13]&2=2 && ip[2:2]-((ip[0]&0x0f)*4)-(tcp[12]>>4)*4>0'`

Find hosts who support ECN and have ports listening
`tcpdump -r backbone.cap -n 'tcp[13]&0xc0 = 0x40 and tcp[13]&0x3f=0x12'`

### DNS Flag Isolation

All DNS Queries

`tcpdump -r dns.pcap -nt 'dst port 53 and udp[10] & 0x80 = 0'`

All Responses

`tcpdump -r dns.pcap -nt 'src port 53 and udp[10] & 0x80 = 0x80'`

Responses with TC (Truncated)

`tcpdump -r dns.pcap -nt 'src port 53 and udp[10] & 0x82 = 0x82'`

Query with RD (Recursion Desired)

`tcpdump -r dns.pcap -nt 'dst port 53 and udp[10] & 0x81 = 0x01'`

Response with RD and RA (Recursion Available)

`tcpdump -r dns.pcap -nt 'src port 53 and udp[10:2] & 0x8180 = 0x8180'`

### Bringing it all together

Identify which listening TCP port receives the greatest number of connection attempts from external systems

`tcpdump -r dmz.cap -n 'tcp[13]&0x3f=0x12 and src net 192.168.0.0/16 and not dst net 192.168.0.0/16' | cut -d ' ' -f 3 | cut -d . -f 5 | sort -n | uniq -c | sort -n`

## Wireshark

### Wireshark Filters

Find Executables in Traffic
`tcp contains "DOS mode"`

More extensive search for executables
`frame contains "DOS mode" or tcp contains "DOS mode"`

Port 80 Traffic with Executables
`tcp.port == 80 and tcp contains "DOS mode"`

Find GIFs in exported OBJs Dir
`grep '^GIF89a' *`

Find PEs in exported OBJs Dir
`grep 'DOS mode' *`

Find Executables in exported OBJs Dir
`grep '^MZ' *`

## Hunting the Network

### Snort

Run Snort to discover if any alters triggered.

`snort -A console -q -K none -c ./snort.conf -r the.pcap`

### SiLK for Hunting

Note:  SiLK by default will search its /data repository if not given another source to read from.

To search all protos in a given date range and get the number of flows:

`rwfilter --type=all --start-date 2018/10/01 --end-date 2018/10/15 --proto=0-255 --print-stat`

To see how many TCP flows occurred in a certain date range (the 'read' count is number of flows):

`rwfilter --type=all --start-date=2018/10/01 --end-date=2018/10/15 --proto=6 --print-stat`

To find all of the TCP ports that were connected to in a certaing time range in repo:

`rwfilter --type=all --start-date 2018/10/1 --end-date 2018/10/31 --proto=6 --flags-initial S/SA --pass stdout | rwstats --count=20 --field dport`

To find the top talker

`rwfilter --type=all --proto=0-255 --start-date=2018/11/06T21 --end-date=2018/11/06T21 --pass=stdout | rwstats --fields=sip --values=bytes --count=10`

