# CleanDNS

Non-polluting DNS. Forward DNS requests with ECS (edns-client-subnet) support.

#### Appveyor

[![Build status](https://ci.appveyor.com/api/projects/status/v7bvx6hp4b3vedx1?svg=true)](https://ci.appveyor.com/project/GangZhuo/cleandns)

#### Travis CI

[![Travis CI](https://travis-ci.org/GangZhuo/CleanDNS.svg?branch=master)](https://travis-ci.org/GangZhuo/CleanDNS)

## Install

### Linux

```bash
git clone https://github.com/GangZhuo/CleanDNS.git

cd CleanDNS

make clean

make
```

### OpenWRT

```bash
cd OpenWrt-SDK-***

git clone https://github.com/GangZhuo/CleanDNS.git package/CleanDNS

# Select Network/CleanDNS
make menuconfig

# Output file should be at OpenWrt-SDK-***/bin/packages/<arch>/base/CleanDNS-*.ipk
make V=99 package/CleanDNS/openwrt/{clean,compile}

# Install on OpenWrt
opkg install CleanDNS_*.ipk

# Edit your config file '/etc/config/cleandns', then restart '/etc/init.d/cleandns restart'.
vim /etc/config/cleandns

# Start|Stop|Restart|Enable|Disable
/etc/init.d/cleandns [start|stop|restart|enable|disable]
```

### Android (Termux)

```bash
git clone https://github.com/GangZhuo/CleanDNS.git

cd CleanDNS

make clean

make LDFLAGS=-llog
```

### Windows

```
1) Download source code from https://github.com/GangZhuo/CleanDNS.

2) Open CleanDNS/windows/cleandns.sln with visual studio 2019, build project.

3) Copy build result (cleandns.exe) with CleanDNS/windows/install_service.bat,
   CleanDNS/windows/uninstall_service.bat and chnroute.txt to target directory
   (e.g. D:\CleanDNS\).

4) Right click D:\CleanDNS\install_service.bat, and click Run as administrator
   to install CleanDNS as service.

5) Edit your config file D:\CleanDNS\cleandns.config， which should be generate
   automatic after installed service.

6) Press WIN+R, type 'services.msc', and press <Enter>， Start/Restart CleanDNS on right panel.

7) Right click D:\CleanDNS\uninstall_service.bat, and click Run as administrator to uninstall.
```

## Usage

```
$>cleandns.exe -h

CleanDNS 0.4.2

Usage:

cleandns [-c CHNROUTE_FILE] [-l CHINA_IP] [-f FOREIGN_IP]
         [-b BIND_ADDR] [-p BIND_PORT] [-s DNS] [-t TIMEOUT] [-m]
         [--config=CONFIG_PATH] [--daemon] [--pid=PID_FILE_PATH]
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]
         [--proxy=PROXY_URL] [-v] [-V] [-h]

Forward DNS requests with ECS (edns-client-subnet) support.

Options:

  -l CHINA_IP           China ip address, e.g. 114.114.114.114/24.
                        Use comma to separate IPv4 and IPv6,
                        e.g. 114.114.114.114/24,2405:2d80::/32.
  -f FOREIGN_IP         Foreign ip address, e.g. 8.8.8.8/24.
                        Use comma to separate IPv4 and IPv6,
                        e.g. 8.8.8.8/24,2001:df2:8300::/48.
  -c CHNROUTE_FILE      Path to china route file, default: chnroute.txt.
                        Use comma to separate multi files, e.g. chnroute_ipv4.txt,chnroute_ipv6.txt.
  -b BIND_ADDR          Address that listens, default: 0.0.0.0.
                        Use comma to separate multi addresses, e.g. 127.0.0.1:5354,[::1]:5354.
  -p BIND_PORT          Port that listen on, default: 5354.
                        The port specified in "-b" is priority .
  -s DNS                DNS server to use, default: 8.8.8.8:53,114.114.114.114:53.
                        tcp://IP[:PORT] means forward request to upstream by TCP protocol,
                        [udp://]IP[:PORT] means forward request to upstream by UDP protocol.
                        Forward by UDP protocol default, and default port of upstream is 53.
  -m                    Use DNS compression pointer mutation, only available on foreign dns server.
  -t TIMEOUT            Timeout, default: 5.
  --daemon              Daemonize.
  --pid=PID_FILE_PATH   pid file, default: /var/run/cleandns.pid, only available on daemonize.
  --log=LOG_FILE_PATH   Write log to a file.
  --log-level=LOG_LEVEL Log level, range: [0, 7], default: 5.
  --config=CONFIG_PATH  Config file, find sample at https://github.com/GangZhuo/CleanDNS.
  --lazy                Disable pollution detection.
  --proxy=PROXY_URL     Proxy server, e.g. socks5://127.0.0.1:1080, only available on foreign dns server.
                        Now, only socks5 with no authentication is supported.
  -v                    Verbose logging.
  -h                    Show this help message and exit.
  -V                    Print version and then exit.

Online help: <https://github.com/GangZhuo/CleanDNS>
```

### Configuration Examples

#### IPv4

```
config cfg
	option bind_addr '0.0.0.0'
	option bind_port '5354'
	option chnroute '/etc/cleandns_chnroute.txt'
	option china_ip '203.208.32.0/24'
	option foreign_ip '172.217.12.0/24'
	option dns_server '8.8.8.8:53'
	option compression '1'
	option timeout '5'
	#option log_file '/var/log/cleandns.log'
	option log_level '5'
	option lazy '0'
	#option proxy 'socks5://127.0.0.1:1080'
```

#### IPv6

```
config cfg
	option bind_addr '[::1]'
	option bind_port '5354'
	option chnroute '/etc/cleandns_chnroute.txt,/etc/cleandns_chnroute6.txt'
	option china_ip '240e:3a1:4a51::/35'
	option foreign_ip '2607:8700:112:e65e::/35'
	option dns_server '[2001:4860:4860::8888]:53'
	option compression '1'
	option timeout '5'
	#option log_file '/var/log/cleandns.log'
	option log_level '5'
	option lazy '0'
	#option proxy 'socks5://[::1]:1080'
```

#### Dual Stacks

```
config cfg
	option bind_addr '0.0.0.0,[::1]'
	option bind_port '5354'
	option chnroute '/etc/cleandns_chnroute.txt,/etc/cleandns_chnroute6.txt'
	option china_ip '203.208.32.0/24,240e:3a1:4a51::/35'
	option foreign_ip '172.217.12.0/24,2607:8700:112:e65e::/35'
	option dns_server '8.8.8.8:53,[2001:4860:4860::8888]:53'
	option compression '1'
	option timeout '5'
	#option log_file '/var/log/cleandns.log'
	option log_level '5'
	option lazy '0'
	#option proxy 'socks5://127.0.0.1:1080'
```

### Example

```bash
cleandns -m -s 8.8.8.8 -l 202.108.22.5/24 -vvv

or

cleandns -m -s 8.8.8.8 -l 202.108.22.5/24 -f 172.217.24.4/24 -vvv

or

cleandns --config=/etc/config/cleandns
```

Remove `-l` and `-f` to disable "edns-client-subnet".

Test if it works:

```bash
$ dig @127.0.0.1 -p 5354 www.youtube.com
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
```

### Update chnroute (IPv4)

See [About chnroute] on [ChinaDNS].

### Update chnroute (IPv6)

You can generate latest chnroute6.txt using this command:

    curl 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | \
	grep ipv6 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, $5) }' > chnroute6.txt

## References

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

## License

```
Copyright (C) 2017-2019, Gang Zhuo <gang.zhuo@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
