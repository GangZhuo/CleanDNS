#!/usr/bin/env bash

command -v bc > /dev/null || { echo "bc was not found. Please install bc."; exit 1; }
{ command -v drill > /dev/null && dig=drill; } || { command -v dig > /dev/null && dig=dig; } || { echo "dig was not found. Please install dnsutils."; exit 1; }

NAME_SERVER="@127.0.0.1 -p 5354"
TIMES_PER_DOMAIN=10
DOMAINS="
www.google.com
amazon.com
facebook.com
www.youtube.com
www.reddit.com
wikipedia.org
twitter.com
gmail.com
www.google.com
whatsapp.com
www.163.com
www.qq.com
www.baidu.com
www.jd.com
www.taobao.com
www.tmall.com
"


printf "%-18s" ""
for i in $(seq 1 $TIMES_PER_DOMAIN); do
    printf "%-8s" "test$i"
done
printf "%-8s" "Average"
echo ""


for domain in $DOMAINS; do
    ftime=0

    printf "%-18s" "$domain"
    for i in $(seq 1 $TIMES_PER_DOMAIN); do
        ttime=`$dig +tries=1 +time=2 +stats $NAME_SERVER $domain |grep "Query time:" | cut -d : -f 2- | cut -d " " -f 2`
        if [ -z "$ttime" ]; then
	        #let's have time out be 1s = 1000ms
	        ttime=1000
        elif [ "x$ttime" = "x0" ]; then
	        ttime=1
	    fi

        printf "%-8s" "$ttime ms"
        ftime=$((ftime + ttime))
    done
    avg=`bc -lq <<< "scale=2; $ftime/$TIMES_PER_DOMAIN"`

    echo "  $avg"
done


exit 0;
