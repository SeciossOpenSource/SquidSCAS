#! /usr/bin/perl

use strict;
use warnings;
use Cache::Memcached;
use Config::General;
use Net::LDAP;
use Digest::SHA qw(sha1_hex);
use Sys::Syslog;
use Sys::Syslog qw(:macros);
use Data::Dumper;

my $LOG_FACILITY = 'local5';
my $LOG_LEVEL = LOG_DEBUG;

my $ldap_uri;
my $ldap_binddn;
my $ldap_bindpw;
my $ldap_basedn;

my $config = Config::General->new('/usr/local/etc/scas_scan.conf');
my %param = $config->getall;
foreach my $key ('ldap_uri', 'ldap_binddn', 'ldap_bindpw', 'ldap_basedn') {
    if (!defined($param{$key})) {
        print "set $key in scas_scan.conf\n";
        exit 1;
    }
}
$ldap_uri = $param{ldap_uri};
$ldap_binddn = $param{ldap_binddn};
$ldap_bindpw = $param{ldap_bindpw};
$ldap_basedn = $param{ldap_basedn};
$ldap_uri = 'ldap://192.168.158.34';
$ldap_binddn = 'cn=Manager,dc=secioss,dc=co,dc=jp';
$ldap_bindpw = 'secret';

openlog('scas_accesspolicy', 'pid', $LOG_FACILITY);
setlogmask(Sys::Syslog::LOG_UPTO($LOG_LEVEL));

my $ldap = Net::LDAP->new($ldap_uri);
if (!defined($ldap)) {
    syslog(LOG_ERR, "Can't contact $ldap_uri");
    exit 1;
}
my $msg = $ldap->bind($ldap_binddn, password => $ldap_bindpw);
if ($msg->code) {
    syslog(LOG_ERR, "Can't bind to $ldap_uri");
    exit 1;
}

my @hosts;
if (defined($param{'memcache_host'})) {
    @hosts = split(/ +/, $param{'memcache_host'});
} else {
    @hosts = ('127.0.0.1:11211');
}
my $m = new Cache::Memcached({servers => \@hosts,
                                    namespace => 'secioss_cas:',
                                });

my %policies;
my $filter = "(&(objectClass=seciossAccessPolicy)(seciossRuleEnabled=TRUE))";
$msg = $ldap->search(base => "ou=AccessPolicies,$ldap_basedn", filter => $filter);
if ($msg->code) {
    syslog(LOG_ERR, "Can't search access policies: ".$msg->error);
    exit 1;
}
for (my $i = 0; $i < $msg->count; $i++) {
    my $entry = $msg->entry($i);
    my ($id) = $entry->get_value('cn');
    my ($service) = $entry->get_value('seciossaccessresource');
    my @users = $entry->get_value('seciossaccessalloweduser');
    my @orgs = $entry->get_value('seciossaccessalloweduser;x-org');
    my @groups = $entry->get_value('seciossaccessallowedrole');
    my @roles = $entry->get_value('seciossaccessrole');
    $policies{$id} = {service => $service, roles => \@roles};
    if (@users && $users[0] !~ /^ *$/) {
        ${$policies{$id}}{users} = \@users;
    }
    if (@orgs && $orgs[0] !~ /^ *$/) {
        ${$policies{$id}}{orgs} = \@orgs;
    }
    if (@groups && $groups[0] !~ /^ *$/) {
        ${$policies{$id}}{groups} = \@groups;
    }
}

$msg = $ldap->search(base => "ou=People,$ldap_basedn", filter => "(&(objectClass=inetOrgPerson)(objectClass=seciossIamAccount))", attrs => ['uid', 'mail', 'ou', 'memberof']);
if ($msg->code) {
    syslog(LOG_ERR, "Can't search users: ".$msg->error);
    exit 1;
}
for (my $i = 0; $i < $msg->count; $i++) {
    my $entry = $msg->entry($i);
    my ($userid) = $entry->get_value('uid');
    my ($mail) = $entry->get_value('mail');
    my ($org) = $entry->get_value('ou');
    my @groups = $entry->get_value('memberof');

    my $key = uc(sha1_hex($userid));
    my $tokens = '';
    foreach my $id (keys(%policies)) {
        if (defined(${$policies{$id}}{users}) || defined(${$policies{$id}}{orgs}) || defined(${$policies{$id}}{groups})) {
            my $match = 0;
            if (defined(${$policies{$id}}{users}) && grep(/^$userid$/i, @{${$policies{$id}}{users}})) {
                $match = 1;
            }
            if (defined(${$policies{$id}}{orgs}) && grep(/^$org$/i, @{${$policies{$id}}{orgs}})) {
                $match = 1;
            }
            if (defined(${$policies{$id}}{groups})) {
                foreach my $group (@groups) {
                    if (grep(/^$group$/i, @{${$policies{$id}}{groups}})) {
                        $match = 1;
                        last;
                    }
                }
            }
            if (!$match) {
                next;
            }
        }
        $tokens .= ($tokens ? ',' : '').${$policies{$id}}{service}.'=+'.join('+', @{${$policies{$id}}{roles}}).'+';
    }
    $m->set($key, "0#$tokens#$userid,$mail");
}

$ldap->unbind();
