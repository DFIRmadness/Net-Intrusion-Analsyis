# Network Intrusion Analysis Pastable

##### Most of these came during my time in SANS SEC503.  Much credit to their material and to David Hoelzer.

## tcpdump

To locate the absolute date and time of the packets:

`tcpdump -n -r dmz.cap -tttt -c 1`

#### Isolatinng Hosts and Networks

src net; dst net

`src net 192.168.0.0/16 and not dst net 192.168.0.0/16`

#### To find SYN packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13]=0x02'`

#### To find SYN/ACK packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13] = 0x12'`

#### To find SYN/ACK packets in a pcap

`tcpdump -r pcap.pcap -n 'tcp[13] = 0x12'`

#### To find SYN/ACK packets with ENC Bits ignored (allowing for ENC Enabled Systems)

`tcpdump -r dmz.cap -n 'tcp[13]&0x3f=0x12'`

#### Bringing it all together

Identify which listening TCP port receives the greatest number of connection attempts from external systems

`tcpdump -r dmz.cap -n 'tcp[13]&0x3f=0x12 and src net 192.168.0.0/16 and not dst net 192.168.0.0/16' | cut -d ' ' -f 3 | cut -d . -f 5 | sort -n | uniq -c | sort -n`

#### Find ECN enabled hosts in a home network

`tcpdump -r backbone.cap -nt 'tcp[13]&0xc0 = 0x40 and tcp[13]&0x3f=0x12'`

#### Find a host from 192.168.0.0/16 that has port 111 open:

`tcpdump -r backbone.cap -n 'src net 192.168.0.0/16 and tcp[13] & 0x3f = 0x12 and tcp src port 111'`

#### Finding Fast Open or Data on the SYN packets

`tcpdump -r backbone.cap -nt 'tcp[13]&2=2 && ip[2:2]-((ip[0]&0x0f)*4)-(tcp[12]>>4)*4>0'`

## Hunting the Network

### Snort

Run Snort to discover if any alters triggered.

`snort -A console -q -K none -c ./snort.conf -r the.pcap`

## SiLK for Hunting

Note:  SiLK by default will search its /data repository if not given another source to read from.

#### To search all protos in a given date range and get the number of flows:

`rwfilter --type=all --start-date 2018/10/01 --end-date 2018/10/15 --proto=0-255 --print-stat`

#### To see how many TCP flows occurred in a certain date range:

`rwfilter --type=all --start-date=2018/10/01 --end-date=2018/10/15 --proto=6 --print-stat`

#### To find all of the TCP ports that were connected to in a certaing time range in repo:

`rwfilter --type=all --start-date 2018/10/1 --end-date 2018/10/31 --proto=6 --flags-initial S/SA --pass stdout | rwstats --count=20 --field dport`

#### To find the top talker

`rwfilter --type=all --proto=0-255 --start-date=2018/11/06T21 --end-date=2018/11/06T21 --pass=stdout | rwstats --fields=sip --values=bytes --count=10`

