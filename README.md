# CleanDNS

Non-polluting DNS. Forward DNS requests with ECS (edns-client-subnet) support.

#### Appveyor

  [![Build status](https://ci.appveyor.com/api/projects/status/v7bvx6hp4b3vedx1?svg=true)](https://ci.appveyor.com/project/GangZhuo/cleandns)

#### Travis CI

  [![Travis CI](https://travis-ci.org/GangZhuo/CleanDNS.svg?branch=master)](https://travis-ci.org/GangZhuo/CleanDNS)

### Install

    git clone https://github.com/GangZhuo/CleanDNS.git
	
    cd CleanDNS
	
    make clean
	
    make

### Install (OpenWRT)

    cd OpenWrt-SDK-***
	
    git clone https://github.com/GangZhuo/CleanDNS.git package/CleanDNS
	
    make menuconfig                            # Select Network/CleanDNS
	
    make V=99 package/CleanDNS/openwrt/compile # Output file at OpenWrt-SDK-***/bin/packages/<arch>/base/CleanDNS-*.ipk
    
	# Install on OpenWrt
    opkg install CleanDNS_*.ipk
	
	# Change your config file '/etc/config/cleandns', then restart '/etc/init.d/cleandns restart'.
	vim /etc/config/cleandns
	
	# Start|Stop|Restart|Enable|Disable
	/etc/init.d/cleandns [start|stop|restart|enable|disable]

### Install (Windows)

    1) Download source code from https://github.com/GangZhuo/CleanDNS.
    
    2) Open CleanDNS/windows/cleandns.sln with visual studio 2019, build project.
    
    3) Copy build result (cleandns.exe) with CleanDNS/windows/install_service.bat and CleanDNS/windows/uninstall_service.bat to target directory (e.g. D:\CleanDNS\).
    
    4) Right click D:\CleanDNS\install_service.bat, and click Run as administrator to install CleanDNS as service.
    
    5) Edit your config file D:\CleanDNS\cleandns.config， which should be generate automatic after installed service.
    
    6) Press WIN+R, type 'services.msc', and press <Enter>， Start/Restart CleanDNS on right panel.
    
    7) Right click D:\CleanDNS\uninstall_service.bat, and click Run as administrator to uninstall.	
	
### Usage

    $>cleandns.exe -h
    
    CleanDNS 0.3.1
    
    Usage:
    
    cleandns [-l CHINA_IP] [-f FOREIGN_IP] [-b BIND_ADDR]
             [-p BIND_PORT] [-c CHNROUTE_FILE] [-s DNS] [-t TIMEOUT]
             [--log=LOG_FILE_PATH] [--log_level=LOG_LEVEL]
             [--config=CONFIG_PATH] [--pid=PID_FILE_PATH]
             [--daemon] [-m] [-v] [-V] [-h]
    
    Forward DNS requests with ECS (edns-client-subnet) support.
    
    Options:
    
      -l CHINA_IP           china ip address, e.g. 114.114.114.114/24.
      -f FOREIGN_IP         foreign ip address, e.g. 8.8.8.8/24.
      -c CHNROUTE_FILE      path to china route file, default: chnroute.txt.
      -b BIND_ADDR          address that listens, default: 0.0.0.0.
      -p BIND_PORT          port that listens, default: 5354.
      -s DNS                DNS server to use, default: 8.8.8.8:53,114.114.114.114:53.
                            tcp://IP[:PORT] means forward request to upstream by TCP protocol,
                            [udp://]IP[:PORT] means forward request to upstream by UDP protocol,
                            default forward by UDP protocol, and default port of upstream is 53.
      -m                    use DNS compression pointer mutation, only avalidate on foreign dns server.
      -t TIMEOUT            timeout, default: 5.
      --daemon              daemonize.
      --pid=PID_FILE_PATH   pid file, default: /var/run/cleandns.pid, only avalidate on daemonize.
      --log=LOG_FILE_PATH   log file, only avalidate on daemonize.
      --log_level=LOG_LEVEL log level, range: [0, 7], default: 5.
      --config=CONFIG_PATH  config file, find sample at https://github.com/GangZhuo/CleanDNS.
      -v                    verbose logging.
      -h                    show this help message and exit.
      -V                    print version and exit.
    
    Online help: <https://github.com/GangZhuo/CleanDNS>

### Example

    cleandns -m -s 8.8.8.8 -l 202.108.22.5/24 -vvv
    
    or
    
    cleandns -m -s 8.8.8.8 -l 202.108.22.5/24 -f 172.217.24.4/24 -vvv

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
* [RFC 1035 DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION]
* [RFC 6891 Extension Mechanisms for DNS (EDNS(0))]
* [RFC 7871 Client Subnet in DNS Queries]
* [RFC 7873 Domain Name System (DNS) Cookies]
* [Domain Name System (DNS) Parameters]

[ChinaDNS]:  https://github.com/shadowsocks/ChinaDNS
[About chnroute]:  https://github.com/shadowsocks/ChinaDNS#about-chnroute
[RFC 1035 DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION]:  https://www.ietf.org/rfc/rfc1035.txt	
[RFC 2671 Extension Mechanisms for DNS (EDNS0)]:  https://tools.ietf.org/rfc/rfc2671.txt
[RFC 6891 Extension Mechanisms for DNS (EDNS(0))]:  https://tools.ietf.org/rfc/rfc6891.txt
[RFC 7871 Client Subnet in DNS Queries]:  https://tools.ietf.org/rfc/rfc7871.txt
[RFC 7873 Domain Name System (DNS) Cookies]: https://tools.ietf.org/rfc/rfc7873.txt
[Domain Name System (DNS) Parameters]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
