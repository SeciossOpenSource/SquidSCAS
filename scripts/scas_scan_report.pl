#! /usr/bin/perl

use strict;
use warnings;
use Config::General;
use File::Basename;
use HTTP::Request::Common qw(GET POST);
use HTTP::Cookies;
use LWP::UserAgent;
use JSON qw(decode_json);
use Net::LDAP;
use Secioss::Auth::Util qw(sendMail getFileContents);
use Sys::Syslog;
use Sys::Syslog qw(:macros);
use Data::Dumper;

my $tplfile = '/usr/local/etc/alert.mail';
my $LOG_FACILITY = 'local5';
my $LOG_LEVEL = LOG_DEBUG;

my $workdir;
my $cuckoo_url;
my $cuckoo_token;
my $hardlimit;
my $viruslist;
my $ldap_uri;
my $ldap_binddn;
my $ldap_bindpw;
my $ldap_basedn;
my $smtp;
my $postmaster;
my $ua;
my $req;
my $res;

my $config = Config::General->new('/usr/local/etc/scas_scan.conf');
my %param = $config->getall;
foreach my $key ('workdir', 'cuckoo_url', 'cuckoo_token', 'hardlimit', 'viruslist', 'ldap_uri', 'ldap_binddn', 'ldap_bindpw', 'ldap_basedn', 'smtp', 'postmaster') {
    if (!defined($param{$key})) {
        print "set $key in scas_scan.conf\n";
        exit 1;
    }
}
$workdir = $param{workdir};
$cuckoo_url = $param{cuckoo_url};
$cuckoo_token = $param{cuckoo_token};
$hardlimit = $param{hardlimit};
$viruslist = $param{viruslist};
$ldap_uri = $param{ldap_uri};
$ldap_binddn = $param{ldap_binddn};
$ldap_bindpw = $param{ldap_bindpw};
$ldap_basedn = $param{ldap_basedn};
$smtp = $param{smtp};
$postmaster = $param{postmaster};

$ua = LWP::UserAgent->new;

if (!-d "$workdir/work") {
    mkdir "$workdir/work";
}
if (!-d "$workdir/failed") {
    mkdir "$workdir/failed";
}

openlog('scas_scan_report', 'pid', $LOG_FACILITY);
setlogmask(Sys::Syslog::LOG_UPTO($LOG_LEVEL));

if (!opendir(DIR, "$workdir/work")) {
    syslog(LOG_ERR, "Can't open $workdir/work");
    exit 1;
}

foreach my $file (readdir(DIR)) {
    if ($file !~ /\.info$/) {
        next;
    }

    $file = "$workdir/work/$file";
    my $virus_file = $file;
    $virus_file =~ s/\.info$//;
    if (!open(FD, "< $file")) {
        syslog(LOG_ERR, "Can't open $file");
        next;
    }
    my $line = <FD>;
    my ($task_id, $username, $url) = split(/,/, $line);
    close(FD);

    $req = GET("$cuckoo_url/tasks/report/$task_id");
    $req->header('Authorization' => 'Bearer '.$cuckoo_token);
    $res = $ua->request($req);
    if (!$res->is_success) {
        syslog(LOG_ERR, "Failed to view task $task_id in cuckoo sandobx: status code[".$res->code."]");
        next;
    }
    eval "\$res = decode_json(\$res->content)";
    if ($@) {
        syslog(LOG_ERR, "Failed to view task $task_id in cuckoo sandobx: invaild content[".$res->content."]");
        next;
    }
    if (!defined($res->{info})) {
        syslog(LOG_ERR, "Failed to view task $task_id in cuckoo sandobx");
        next;
    }

    my $score = $res->{info}->{score};
    if ($score >= $hardlimit) {
        my $virus_id = "cuckoo_$task_id";
        my $mail = $postmaster;
        my $tenant;
        if ($username =~ /@([^@]+)$/) {
            $tenant = $1;
            my $ldap = Net::LDAP->new($ldap_uri);
            if (!defined($ldap)) {
                syslog(LOG_ERR, "Can't contact $ldap_uri");
                next;
            }
            my $msg = $ldap->bind($ldap_binddn, password => $ldap_bindpw);
            if ($msg->code) {
                syslog(LOG_ERR, "Can't bind to $ldap_uri");
                next;
            }
            my $filter = "(&(&(objectClass=seciossTenant)(seciossTenantStatus=active))(o=$tenant))";
            $msg = $ldap->search(base => $ldap_basedn, filter => $filter, attrs => ['o', 'mail;x-type--admin']);
            if ($msg->code) {
                syslog(LOG_ERR, "Can't search tenant: ".$msg->error);
                next;
            }
            if ($msg->count) {
                my $entry = msg->entry(0);
                my ($val) = $entry->get_value('mail;x-type-admin');
                if ($val) {
                    $mail = $val;
                }
            }
        }

        my $mail_msg = getFileContents($tplfile);
        my ($subject) = ($mail_msg =~ /^Subject: *(.*)\n/i);
        $mail_msg =~ s/^Subject:.*\n//;
        $mail_msg =~ s/\${id}/$username/gi;
        $mail_msg =~ s/\${url}/$url/gi;
        my $rc = sendMail($smtp, $postmaster, $mail, $subject, $mail_msg);
        if ($rc) {
             syslog(LOG_INFO, "Succeeded to send alert mail to $mail: $username $virus_id");
        } else {
             syslog(LOG_ERR, "Failed to send alert mail to $mail: $username $virus_id");
        }
    }
    unlink($file);
    unlink($virus_file);
}
close(DIR);

my $checked_id = 0;
if (open(FD, "< $workdir/checked")) {
    $checked_id = <FD>;
}
close(FD);

if (!open(LIST, ">> $viruslist")) {
    syslog(LOG_ERR, "Can't write $viruslist");
    exit 1;
}

$req = GET("$cuckoo_url/tasks/list");
$req->header('Authorization' => 'Bearer '.$cuckoo_token);
$res = $ua->request($req);
$res = decode_json($res->content);
if (!$res || !defined($res->{tasks})) {
    syslog(LOG_ERR, "Failed to get task list from cuckoo sandobx");
    next;
}
my @tasks = @{$res->{tasks}};

foreach my $task (@tasks) {
    if ($task->{id} <= $checked_id) {
        next;
    }
    if ($task->{status} eq 'running') {
        last;
    } elsif ($task->{status} ne 'reported') {
        next;
    }

    $req = GET("$cuckoo_url/tasks/report/$task->{id}");
    $req->header('Authorization' => 'Bearer '.$cuckoo_token);
    $res = $ua->request($req);
    my ($score) = ($res->content =~ /"score": ([^,]+),/);
    if ($score && $score >= $hardlimit) {
        my $checksum = ${$task->{sample}}{sha1};
        print LIST "cuckoo_$task->{id},$checksum\n";
    }
    if (open(FD, ">", "$workdir/checked")) {
        print FD $task->{id};
        close(FD);
    }
}
close(LIST);
