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
13. ether src
14. ether dst

### Useful tcpdump Switches

|Switch|Function|
|---|---|
|-S|Show absolute sequence numbers|

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

`src net 10.0.0.0/16 and not dst net 10.0.0.0/16`

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

Find a host from 10.0.0.0/16 that has port 111 open:

`tcpdump -r backbone.cap -n 'src net 10.0.0.0/16 and tcp[13] & 0x3f = 0x12 and tcp src port 111'`

Finding Fast Open or Data on the SYN packets

`tcpdump -r backbone.cap -nt 'tcp[13]&2=2 && ip[2:2]-((ip[0]&0x0f)*4)-(tcp[12]>>4)*4>0'`

Find hosts who support ECN and have ports listening

`tcpdump -r backbone.cap -n 'tcp[13]&0xc0 = 0x40 and tcp[13]&0x3f=0x12'`

Build a BPF Filter file for snort alerts triggering on portable executable downloads:

`grep "FILE-EXECUTABLE" alert.dmz |awk -F"{TCP}" '{print $2}' | awk -F"->" '{print $1":"$2}' | awk -F: '{print "(host "$1" and tcp port "$2" and host "$3" and tcp port "$4") or"}'|uniq > /tmp/filter-pe-alert`

Now edit the file and remove the last "or" then run tcpdump against that file to extract all related packets:

`tcpdump -r dmz.cap -F /tmp/filter-pe-alert -w /tmp/filter-pe-alert.cap`

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

`tcpdump -r dmz.cap -n 'tcp[13]&0x3f=0x12 and src net 10.0.0.0/16 and not dst net 10.0.0.0/16' | cut -d ' ' -f 3 | cut -d . -f 5 | sort -n | uniq -c | sort -n`

### Advanced tcpdump methods

#### Finding which NAT'd host sent a packet.  Note the Seq number and destination ip:

`tcpdump -n -r external.cap 'tcp port 445' -tttt -S | grep '22:37:01' | head -1`

Then:

`tcpdump -n -r dmz.cap 'dst host <destination ip> and dst port 445 and tcp[4:4] = <noted seq number>' -tttt -c 1`

#### Finding a host spoofing ip addresses:

Find the ethernet address of a host responsible (look at a pcap from internal side of egress sensor):

`tcpdump -n -e -r dmz.cap 'ip and not net 224.0.0.0/24 and not src net <home net cidr> and not dst net <home net cidr>' -c 1`

Now find the internal ip matching any ethernet address noted above:

`tcpdump -n -e -r dmz.cap 'ether src <noted ether address> and src net <home net cidr>' -c 1`

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

Quickly find amount of payload in a conversation:

`Follow the stream. Look at the lower left corner and the bytes in the pulldown is the total payload txfr`

## Snort

### Snort rules numbers

|GID:|SID:|VER|
|---|---|---|
|Generator ID|Snort ID|Revision Number|

SID is either a *rule* or a *signature*.

GID 1 is for alerts generated from rules (rules file)

### Snort from the command line
Run Snort to discover if any alters triggered.

`snort -A console -q -K none -c ./snort.conf -r the.pcap`

Review a rule for certain SID (example: 252)

`grep sid:252\; latest.rules`

**Note**: GID 1 is for rules.  Any other GID will **not** exist in the rules file.

Extract and sort alerts by SID by frequency in ascending order

`cat alert.dmz |awk '{print $3}'|tr -d '[]'|cut -d ':' -f 2|sort|uniq -c|sort -n`

### SiLK for Hunting

Note:  SiLK by default will search its /data repository if not given another source to read from.

#### Quick Reference for SiLK Options
|Tool or Switch|Summary|
|---|---|
|**rwfilter**||
|--start-date|Date YYYY/MM/DD or YYYY/MM/DD**T***hour* 2019/09/31T14|
|--end-date||
|--proto|0-255 (1 for ICMP,6 for TCP, 17 for UDP)|
|--dport|Destination Port|
|--sport|Source Port|
|--scidr|Source CIDR. Can be a list: 10.5.0.48.0/24,10.5.50.0/24|
|--dcidr|Destination CIDR|
|--flags-initial|Flag You Want Select / Flags Masked ON. Exemple: SYN's only would be S/SA|
|--ip-version|Select the IP Version (4\|6)|
|--not-daddress|Not destination address|
|--print-stat|Print statistics of the selected repo's. **Note: the PASS value is the qty of files in your selection**|
|||
|**rwstats**||
|--fields--|Select fields to display:|
|dport|Destionation Port|
|sip|Source IP|
|stime|Start Time|
|--values--|Sort by values:|
|bytes|Sort by bytes|
|||
|**rwcut**|--fields=field1,field2,field3 . . . or -f 9|
|sip|Source IP|
|dip|Destination IP|
|sport|Source Port|
|dport|Destination Port|
|stime|Start Time|
|etime|End Time|
|bytes|Bye Count|
|--no-titles|Remove titles... great for when piping to wc -l for a line count|
|||
|**rwuniq**||
|--fields|Select field to order by unique-ness|
|Example Fields|sip,dip,sport,dport. Useful when combined with pre-filter in rwfilter|

To search all protos in a given date range and get the number of flows:

`rwfilter --type=all --start-date 2019/09/01 --end-date 2019/09/15 --proto=0-255 --print-stat`

To see how many TCP flows occurred in a certain date range (the 'read' count is number of flows):

`rwfilter --type=all --start-date=2019/09/01 --end-date=2019/09/15 --proto=6 --print-stat`

To find all of the TCP ports that were connected to in a certaing time range in repo:

`rwfilter --type=all --start-date 2018/10/1 --end-date 2019/09/31 --proto=6 --flags-initial S/SA --pass stdout | rwstats --count=20 --field dport`

To find the top talker

`rwfilter --type=all --proto=0-255 --start-date=2019/09/31T14 --end-date=2019/09/31T14 --pass=stdout | rwstats --fields=sip --values=bytes --count=10`

Example of finding the time that a flow of large bytes began

`rwfilter --type=all --proto=0-255 --start-date=2019/09/31T14 --end-date=2019/09/31T23 --pass=stdout | rwstats --fields=sip,stime --value=bytes --count=10`

Filter on services listening inside of the local network (example 172.16/16)

`rwfilter backbone.silk --pass=stdout --flags-initial=SA/SA --proto=6 --scidr="172.16.0.0/16" --dcidr="172.16.0.0/16" |rwuniq --fields=sip --values=flows`

rwfilter against a file

`rwfilter incident.silk`


## Bro/Zeek

|Bro Switches||
|---|---|
|**Bro**||
|-r|Read a pcap into bro logs|
|**Bro-cut**|Common ones between diff logs|
|-F '*n*'|Set field delimiter *n*; example -F ':'|
|id.resp_h or id.orig_h|"Destination" IP (resp_h=responding host) or "Source IP"|
|id.resp_p or id.orig_p|Destination or Source Port|

Bro normalized time (Note: Connections are NOT sorted in chronological order in conn.log etc)

`bro-cut -d ts`

Bro readback from a pcap.  Make and change into a dir where you want the logs generated.

`bro -r ../thepcap.cap`

### Bro Analytical Tricks/Tips/Examples

Find the a particular user's mail client location.  Use from field combined with source IP. Example: find tuser's internal IP of where they are using their mail client.

`cat backbone/smtp.log |bro-cut ts -d from reply_to id.orig_h id.resp_h|grep "tuser"|head -3`

