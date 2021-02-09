#!/bin/sh

source /usr/local/etc/collectBlackList.conf

etag=`wget -S http://data.phishtank.com/data/$ptkey/online-valid.csv.bz2 -O $workdir/tmp.csv.bz2 2>&1 | sed -n 's/ETag: "\([^"]*\)"/\1/p'`
if [ -z "$etag" ]; then
    echo "Can't get phishtank url list"
    exit 1
fi

bunzip2 $workdir/tmp.csv.bz2
sed -e '1d' $workdir/tmp.csv | awk -F, '{print $2}' | sed -n '/^https:/p' | sed /$exclude/d | sed 's/^https:\/\/\([^\/]*\).*$/\1/g' | sort | uniq > $workdir/domain.list
mv $workdir/domain.list /etc/squid/blacklist_domain

sed -e '1d' $workdir/tmp.csv | awk -F, '{print $2}' | sed -n '/^https:/p' | sed -n /$exclude/p | sort | uniq > $workdir/domain.list
mv $workdir/domain.list /etc/squid/blacklist_bump

sed -e '1d' $workdir/tmp.csv | awk -F, '{print $2}' | sed -n '/^http:/p' | sed 's/\([.*+?\(){}\[|\^\$\\]\)/\\\1/g' | sed "s/\]/\\\]/g" | sed "s/^/^/" > $workdir/url.list
rm -f $workdir/tmp.csv*
mv $workdir/url.list /etc/squid/blacklist_url

wget -O $workdir/tmp.txt https://feodotracker.abuse.ch/downloads/ipblocklist.txt
sed -n /^[0-9]/p $workdir/tmp.txt > /etc/squid/blacklist_ip
rm -f $workdir/tmp.txt
