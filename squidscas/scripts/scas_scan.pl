#! /usr/bin/perl

use strict;
use warnings;
use IO::Handle;
use IO::Select;
use Config::General;
use File::Basename;
use HTTP::Request::Common qw(GET POST);
use HTTP::Cookies;
use LWP::UserAgent;
use JSON qw(decode_json);
use Sys::Syslog;
use Sys::Syslog qw(:macros);
use Data::Dumper;

my $pollPeriod = 10;	#timeout
my $LOG_FACILITY = 'local5';
my $LOG_LEVEL = LOG_DEBUG;

my $workdir;
my $cuckoo_url;
my $cuckoo_token;
my $ua;
my $req;
my $res;

sub onInit {
    my $config = Config::General->new('/usr/local/etc/scas_scan.conf');
    my %param = $config->getall;
    foreach my $key ('workdir', 'cuckoo_url', 'cuckoo_token') {
        if (!defined($param{$key})) {
            print "set $key in scas_scan.conf\n";
            exit 1;
        }
    }
    $workdir = $param{workdir};
    $cuckoo_url = $param{cuckoo_url};
    $cuckoo_token = $param{cuckoo_token};

    $ua = LWP::UserAgent->new;

    if (!-d "$workdir/work") {
        mkdir "$workdir/work";
    }
    if (!-d "$workdir/failed") {
        mkdir "$workdir/failed";
    }

    openlog('scas_scan', 'pid', $LOG_FACILITY);
    setlogmask(Sys::Syslog::LOG_UPTO($LOG_LEVEL));
}

sub onReceive {
    my ($msg) = @_;
    my $url;

    if ($msg =~ /LOG Copied \[(.+)\] to \[(.+)\] with exit code \[0\]/) {
        $url = $1;
        my $file = $2;
        if (!-f $file) {
            syslog(LOG_ERR, "Can't find $file");
            return;
        }
        my $filename = basename($file);
        my ($username) = ($filename =~ /^scan_(.+)_[0-9.]+_[0-9]+_/);
        my %data = (file => [$file]);
        $req = POST("$cuckoo_url/tasks/create/file", Content_Type => 'form-data', Content => \%data);
        $req->header('Authorization' => 'Bearer '.$cuckoo_token);
        $res = $ua->request($req);
        if ($res->is_success) { 
            eval "\$res = decode_json(\$res->content)";
            if ($@) {
                syslog(LOG_ERR, "Failed to upload $file to cuckoo sandobx: invalid content[".$res->content."]");
                rename($file, "$workdir/failed/$filename");
            } elsif (defined($res->{task_id})) {
                rename($file, "$workdir/work/$filename");
                if (open(FD, "> $workdir/work/$filename.info")) {
                    print FD "$res->{task_id},$username,$url";
                    close FD;
                } else {
                    syslog(LOG_ERR, "Can't write \"$res->{task_id},$url\" to $filename.info");
                }
            } else {
                syslog(LOG_ERR, "Failed to upload $file to cuckoo sandobx");
                rename($file, "$workdir/failed/$filename");
            }
        } else {
            syslog(LOG_ERR, "Failed to upload $file to cuckoo sandobx: status code[".$res->code."]");
            rename($file, "$workdir/failed/$filename");
        }
    } elsif ($msg =~ /LOG Virus found in ([^ ]+) ending download to ([^ ]+) \[(.+)\]/) {
        $url = $1;
        my $username = $2;
        my $virus = $3;
        syslog(LOG_INFO, "Virus is found in $url: $username $virus");
    }
}

sub onExit {
}

onInit(); 

# Read from STDIN
$STDIN = IO::Select->new();
$STDIN->add(\*STDIN);

# Enter main Loop
my $keepRunning = 1; 
my $stdInLine; 
while ($keepRunning) {
    #sleep(1);
    # We seem to have not timeout for select - or do we?
    if ($STDIN->can_read($pollPeriod)) {
        $stdInLine = <STDIN>;
        if (length($stdInLine) > 0) {
            onReceive($stdInLine);
        }
    }
}

onExit(); 
