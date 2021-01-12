# SquidSCAS
SquidSCASは、オープンソースのICAPサーバーc-icap用のモジュールで、フォワードプロキシー型CASBとして以下の機能を提供します。
* サービス単位のアクセス制限
* 更新、共有、ダウンロード、アップロードの制限
* ダウンロード、またはアップロードしたファイルのサンドボックス解析

## 環境
* OS：CentOS7
* ミドルウェア：squid
## インストール
### rpmパッケージ
~~~ text
# yum install gcc
# yum install memcached
# yum install libmemcached
# yum install libmemcached-devel
# yum install file-devel
# yum install openssl-devel
# yum install squid
# yum install perl-Digest-SHA
# yum install perl-Digest-SHA1
# yum install perl-Sys-Syslog
# yum install perl-Config-General
# yum install perl-JSON
# yum install perl-LDAP
# yum install perl-Cache-Memcached
~~~

### c-icap
~~~ text
# tar zxvf c_icap-0.5.6.tar.gz
# cd c_icap-0.5.6
# ./configure
# make
# make install
~~~

### squidscas
~~~ text
# cd squidscas
# ./configure --with-c-icap
# make
# make install
~~~

### SWG
~~~ text
# cp swg/sbin/*.sh /usr/local/sbin
# cp swg/sbin/*.conf /usr/local/etc
# chmod +x /usr/loca/sbin/*.sh
# cp swg/squid/* /etc/squid
# cp swg/squidscas/scripts/* /usr/local/sbin
# cp swg/systemd/c-icap.service /usr/lib/systemd/system
~~~

## 設定
## squid
以下のコマンドを実行して下さい。

~~~ text
# openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 -extensions v3_ca -keyout squidCA.pem -out squidCA.pem -subj "/C=JP/ST=Tokyo/L=Toshima/O=SECIOSS,Inc./CN=slink-swg.secioss.com"
# cp squidCA.pem /etc/squid/
# openssl x509 -in squidCA.pem -outform DER -out squidCA.der
# mkdir -p /var/lib/squid
# /usr/lib64/squid/ssl_crtd -c -s /var/lib/squid/ssl_db
# chown -R squid:squid /var/lib/squid
~~~
※ squidCA.derはブラウザにCA証明書としてインポートして下さい。

/etc/squid/squid.confのLDAPの設定を環境に合わせて変更して下さい。

~~~ text
...

auth_param basic program /usr/lib64/squid/basic_ldap_auth -b 'dc=secioss,dc=co,dc=jp' -D 'cn=replicator,dc=secioss,dc=co,dc=jp' -w xxxxx -f '(&(uid=%s)(&(objectClass=inetOrgPerson)(objectClass=seciossIamAccount)))' localhost
...
~~~

/usr/local/etc/collectBlackList.confのptkeyにphishtankのキーを設定してから、以下のコマンドを実行して下さい。

~~~ text
# /usr/local/sbin/collectBlackList.sh
~~~

## squidscas
/usr/local/etc/c-icap.confの以下の設定を追加して下さい。

~~~ text
...
Module logger sys_logger.so
Logger sys_logger
...
sys_logger.Facility local6
...
Service squidscas squidscas.so
~~~

/usr/local/etc/squidscas.confを環境に合わせて変更して下さい。

~~~ text
scanpath /usr/local/var/scan
memcached_servers localhost
servicelist /etc/squid/scas_service.conf
viruslist /etc/squid/virus
~~~

以下のディレクトリを作成して下さい。
* /var/log/c-icap


## rsyslog
/etc/rsyslog.d/scas.confに以下の設定を行って下さい。

~~~ text
local6.*                                                /var/log/c-icap/c-icap.log

$ModLoad omprog
$template scas_logformat, "%timegenerated:::date-rf3339% %msg%\n"

if $programname == 'c-icap' and $msg contains 'LOG ' then {
    action(
        type="omprog"
        binary="/usr/local/sbin/scas_scan.pl"
        template="scas_logformat"
   )
}
~~~

ログローテーションの設定/etc/logrotate.d/squidを以下のように変更して下さい。

~~~ text
/var/log/squid/*.log {
    daily
    rotate 7
    ...
~~~

ログローテーションの設定/etc/logrotate.d/c-icapを以下のように作成して下さい。

~~~ text
/var/log/c-icap/*.log {
    daily
    rotate 7
    compress
    notifempty
    missingok
    nocreate
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
~~~
