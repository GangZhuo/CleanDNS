# CleanDNS

Clean DNS, like [ChinaDNS].

[![Build status](https://ci.appveyor.com/api/projects/status/v7bvx6hp4b3vedx1?svg=true)](https://ci.appveyor.com/project/GangZhuo/cleandns)

### Install

    git clone https://github.com/GangZhuo/CleanDNS.git
    cd CleanDNS
    make clean
    make

### Install (OpenWRT)

    cd OpenWrt-SDK-***
    git clone https://github.com/GangZhuo/CleanDNS.git package/CleanDNS
    make menuconfig # Select Network/CleanDNS
    make V=99 package/CleanDNS/openwrt/compile

	
### Usage
    usage: cleandns [-h] [-l CHINA_IP] [-f FOREIGN_IP] [-b BIND_ADDR]
        [-p BIND_PORT] [-c CHNROUTE_FILE] [-s DNS] [-m] [-v] [-V]
    Forward DNS requests.
    
    -l CHINA_IP         china ip address, e.g. 114.114.114.114/24
    -f FOREIGN_IP       foreign ip address, e.g. 8.8.8.8/24
    -c CHNROUTE_FILE    path to china route file, default: chnroute.txt
    -b BIND_ADDR        address that listens, default: 0.0.0.0
    -p BIND_PORT        port that listens, default: 53
    -s DNS              DNS server to use, default: 8.8.8.8:53
    -m                  use DNS compression pointer mutation
    -t                  timeout, default: 6
    -v                  verbose logging
    -h                  show this help message and exit
    -V                  print version and exit

### Example

    cleandns -m -s 8.8.8.8 -l 202.108.22.5/24
    
    or
    
    cleandns -m -s 8.8.8.8 -l 202.108.22.5/24 -f 172.217.24.4/24

Remove "-l" and "-f" to disable "edns-client-subnet".

Test if it works:

    $ dig @127.0.0.1 www.youtube.com
    ; <<>> DiG 9.11.1 <<>> www.youtube.com
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14225
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 8, AUTHORITY: 0, ADDITIONAL: 1
    
    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ; CLIENT-SUBNET: xxx.xxx.xxx.0/24/0
    ;; QUESTION SECTION:
    ;www.youtube.com.		IN	A
    
    ;; ANSWER SECTION:
    www.youtube.com.	86315	IN	CNAME	youtube-ui.l.google.com.
    youtube-ui.l.google.com. 815	IN	CNAME	youtube-ui-china.l.google.com.
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.102
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.100
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.139
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.113
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.138
    youtube-ui-china.l.google.com. 95 IN	A	74.125.203.101

    ;; Query time: 177 msec
    ;; SERVER: 127.0.0.1#53(127.0.0.1)
    ;; WHEN: Tue May 23 07:07:51 2017
    ;; MSG SIZE  rcvd: 443

### Update chnroute

See [About chnroute] on [ChinaDNS].

### Ref:

* [ChinaDNS]
* [RFC 1035]
* [RFC 2671]
* [RFC 6891]
* [RFC 7871]
    

[ChinaDNS]:  https://github.com/shadowsocks/ChinaDNS
[About chnroute]:  https://github.com/shadowsocks/ChinaDNS#about-chnroute
[RFC 1035]:  https://www.ietf.org/rfc/rfc1035.txt	
[RFC 2671]:  https://tools.ietf.org/rfc/rfc2671.txt
[RFC 6891]:  https://tools.ietf.org/rfc/rfc6891.txt
[RFC 7871]:  https://tools.ietf.org/rfc/rfc7871.txt
