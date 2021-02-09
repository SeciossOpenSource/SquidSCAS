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
# yum install wget
# yum install bzip2
~~~

### c-icap
c-icapを http://c-icap.sourceforge.net/download.html からダウンロードしてインストールします。
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

### 管理コンソール
管理コンソールとして、LISM(https://github.com/SeciossOpenSource/LISM)をインストールして下さい。

### その他
~~~ text
# cp scripts/*.sh /usr/local/sbin
# cp scripts/*.conf /usr/local/etc
# cp squid/* /etc/squid
# cp squidscas/scripts/* /usr/local/sbin
# cp squidscas/etc/* /usr/local/etc/
~~~

## 設定
## SELinux
/etc/selinux/configの以下の個所を変更して、SELinuxを無効に設定して下さい。

~~~ text
SELINUX=permissive
~~~

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

/etc/squid/squid.confを以下のように変更して下さい。

~~~ text
...
# Example rule allowing access from your local networks.
# Adapt localnet in the ACL section to list your (internal) IP networks
# from where browsing should be allowed
acl blacklist_domain dstdomain "/etc/squid/blacklist_domain"
acl blacklist_url url_regex "/etc/squid/blacklist_url"
acl blacklist_ip dst "/etc/squid/blacklist_ip"
http_access deny blacklist_domain
http_access deny blacklist_url
http_access deny blacklist_ip

auth_param basic program /usr/lib64/squid/basic_ldap_auth -b 'dc=example,dc=com' -D 'cn=Manager,dc=example,dc=com' -w xxxxx -f '(&(uid=%s)(&(objectClass=inetOrgPerson)(objectClass=seciossIamAccount)))' localhost
auth_param basic children 20
auth_param basic realm Authentication
auth_param basic credentialsttl 2 hours
acl ldap-auth proxy_auth REQUIRED
http_access allow ldap-auth
...
# Squid normally listens to port 3128
http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/squidCA.pem

sslcrtd_program /usr/lib64/squid/ssl_crtd -s /var/lib/squid/ssl_db -M 4MB
acl no_bump_sites dstdomain "/etc/squid/no_bump_sites"
ssl_bump none no_bump_sites
ssl_bump server-first all
sslproxy_cert_error deny all
...

icap_enable on
icap_send_client_username on
icap_send_client_ip on
icap_client_username_header X-Authenticated-User
icap_service service_req reqmod_precache bypass=0 icap://127.0.0.1:1344/squidscas
adaptation_access service_req deny no_bump_sites
adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=0 icap://127.0.0.1:1344/squidscas
adaptation_access service_resp deny no_bump_sites
adaptation_access service_resp allow all

logformat scas %{%Y/%m/%d %H:%M:%S}tl %ts.%03tu %6tr %>a %Ss/%03Hs %>st %<st %rm %ru %[un %Sh/%<a %mt
access_log /var/log/squid/access.log scas
~~~

/etc/squid/no_bump_sitesに、SSL Bumpの対象から外すサイトを以下の例のように設定して下さい。

~~~ text
www.google.com
adservice.google.com
chat.google.com
~~~

/usr/local/etc/collectBlackList.confのptkeyにphishtankのアプリケーションキーを設定してから、以下のコマンドを実行して下さい。
アプリケーションキーはphishtankにアカウントを作成して、https://www.phishtank.com/api_register.php から作成して下さい。

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

/usr/local/etc/scas_scan.confを以下のように設定して下さい。

~~~ text
workdir = /usr/local/var/scan
cuckoo_url = http://<Cuckooのサーバー>:8090
cuckoo_token = xxxxxxxxxx
hardlimit = 7.0
viruslist = /etc/squid/virus
log_server = <LISMのサーバー>
~~~

以下のディレクトリを作成して下さい。
* /var/log/c-icap
* /usr/local/var/scan

LISMのサーバー上で、以下のコマンドを実行して、作成されたscas_service.confを/etc/squidに置いて下さい。
~~~ text
/usr/local/sbin/scas_service.pl > scas_service.conf
~~~


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

## 起動
以下のコマンドを実行して、squidを起動して下さい。

~~~ text
# /usr/local/bin/c-icap
# systemctl start squid
~~~
