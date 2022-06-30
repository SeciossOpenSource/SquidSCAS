# SquidSCAS
SquidSCASは、オープンソースのICAPサーバーc-icap用のモジュールで、セキュアWebゲートウェイとして以下のCASB機能を提供します。
* Google Workspace等のサービス単位だけでなく、GMail、Google Calendar等の機能単位でのアクセス制御
* 参照、更新、共有、ダウンロード、アップロードといった操作レベルでのアクセス制御
* Box、Dropbox等のサービスに対する個人アカウントによるログインの禁止
* ユーザー、グループ単位でのアクセス制御の設定
* フィッシングサイト等の不正なサイトのURLへのアクセスを禁止
* ダウンロード、アップロードしたファイルのサンドボックス解析ツールとの連携

ICAPサーバーとして動作するので、ICAPに対応した既存のプロキシサーバーにセキュアWebゲートウェイの機能を追加することができます。
本サイトでは、オープンソースのプロキシサーバーSquidを使用して、セキュアWebゲートウェイを構築する手順について、説明しています。

## 環境
* OS：AlmaLinux8
* ミドルウェア：squid、memcached


## インストール
### rpmパッケージ
~~~ text
# dnf config-manager --set-enabled powertools
# dnf install epel-release
# dnf install gcc
# dnf install memcached
# dnf install libmemcached
# dnf install libmemcached-devel
# dnf install file-devel
# dnf install openssl-devel
# dnf install libcurl-devel
# dnf install squid
# dnf install perl-Digest-SHA
# dnf install perl-Digest-SHA1
# dnf install perl-Sys-Syslog
# dnf install perl-Config-General
# dnf install perl-JSON
# dnf install perl-LDAP
# dnf install perl-Cache-Memcached
# dnf install wget
# dnf install bzip2
~~~

### c-icap
c-icapを http://c-icap.sourceforge.net/download.html からダウンロードしてインストールします。
~~~ text
# tar zxvf c_icap-0.5.8.tar.gz
# cd c_icap-0.5.8
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
管理コンソールとして、LISM( https://github.com/SeciossOpenSource/LISM )を別サーバーにインストールして下さい。

### その他
~~~ text
# cp scripts/*.sh /usr/local/sbin
# cp scripts/*.pl /usr/local/sbin
# cp scripts/*.conf /usr/local/etc
# cp squidscas/scripts/* /usr/local/sbin
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
# /usr/lib64/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 20MB
# chown -R squid:squid /var/lib/squid
~~~
※ squidCA.derはブラウザにCA証明書としてインポートして下さい。

/etc/squid/squid.confを以下のように変更して下さい。
LDAP認証の設定では、LISMのLDAPサーバーを指定して下さい。

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

auth_param basic program /usr/lib64/squid/basic_ldap_auth -b 'dc=example,dc=com' -D 'cn=Manager,dc=example,dc=com' -w xxxxx -f '(&(uid=%s)(&(objectClass=inetOrgPerson)(objectClass=seciossIamAccount)))' -H ldaps://<LISMのLDAPサーバー>
auth_param basic children 20
auth_param basic realm Authentication
auth_param basic credentialsttl 2 hours
acl ldap-auth proxy_auth REQUIRED
http_access allow ldap-auth
...
# Squid normally listens to port 3128
http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/squidCA.pem

sslcrtd_program /usr/lib64/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
acl no_bump_sites dstdomain "/etc/squid/no_bump_sites"
ssl_bump none no_bump_sites
ssl_bump server-first all
sslproxy_cert_error deny all
...

icap_enable on
icap_send_client_username on
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

/usr/local/etc/collectBlackList.confのptkeyにphishtankのアプリケーションキーを設定してから、以下のコマンドを実行すると、アクセスを禁止するサイトのリストが以下の設定ファイルとして生成されます。
* /etc/squid/blacklist_domain
* /etc/squid/blacklist_bump
* /etc/squid/blacklist_url
* /etc/squid/blacklist_ip

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
redirect <エラー時にリダイレクトするURL>
...
scanpath /usr/local/var/scan
memcached_servers localhost   # アクセス制御情報を保持するmemcachedサーバー
blacklist /etc/squid/blacklist_bump   # アクセスを禁止するサイトのURLのリスト
servicelist /etc/squid/scas_service.conf
viruslist /etc/squid/virus
~~~

/usr/local/etc/scas_scan.confを以下のように設定して下さい。  
サンドボックス解析ツールのCuckoo Sandboxと連携しない場合は、cuckoo_url、cuckoo_token、hardlimitの設定は不要です。

~~~ text
workdir = /usr/local/var/scan
cuckoo_url = http://<Cuckoo Sandboxのサーバー>:8090
cuckoo_token = xxxxxxxxxx
hardlimit = 7.0
viruslist = /etc/squid/virus
log_server = <LISMのサーバー>
~~~

以下のディレクトリを作成して下さい。
* /var/log/c-icap
* /usr/local/var/scan

以下のファイルを作成して下さい。
~~~ text
# touch /etc/squid/virus
~~~

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
# systemctl start memcached
# /usr/local/bin/c-icap
# systemctl start squid
~~~


## アクセス制限
### 管理コンソール
LISMの管理コンソールにログインして、「CASB」-「アクセスポリシー」からアクセス制限を行いたいサービスに対して、アクセスポリシーを設定します。
アクセスポリシーの設定項目は、以下になります。
|項目|説明|
|---|---|
|ID|アクセスポリシーのID|
|カテゴリ|対象サービスのカテゴリ|
|サービス|対象サービス|
|許可する操作|サービスに対して、ユーザーに許可する操作|
|許可するファイル拡張子|ダウンロード、アップロードを許可するファイルの拡張子|
|説明|アクセスポリシーの説明|
|状態|アクセスポリシーの有効・無効|

アクセス対象のユーザーは、「許可するユーザー」、「許可するグループ」から設定可能です。
|項目|説明|
|---|---|
|ユーザー|許可するユーザー|
|組織|許可するユーザーの組織|
|ログインを許可するユーザー|サービスにログインするユーザーの制限（LDAPに登録されているユーザーやログインするユーザーのドメインを制限して、個人アカウントでのログインを禁止します。）|
|共有を許可するユーザー|クラウドストレージで共有を許可するユーザー|
|グループ|アクセスを許可するグループ|

### squidscas
プロキシサーバー上で以下のコマンドを実行すると、管理コンソールで設定したアクセスポリシーに従ってユーザーのアクセス制御情報ががmemcachedに登録され、squidscasにアクセスポリシーが反映されます。
~~~ text
# /usr/local/sbin/scas_accesspolicy.pl
~~~
