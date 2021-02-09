#!/usr/bin/perl

use strict;
use Config::General;
use Text::CSV_XS;
use Encode;
use DBI;
use Data::Dumper;

my $cloud_db = '/usr/local/etc/cloud_discovery.db';
if (!-f $cloud_db) {
    print STDERR "No such file: $cloud_db\n";
    exit 1;
}

my %conf;
my $conf_file = '/opt/secioss/etc/report_crawler.conf';
if (-f $conf_file) {
    my $conf = Config::General->new($conf_file);
    %conf = $conf->getall;
}

my $type = 'scas';
if (@ARGV) {
    $type = $ARGV[0];
}

my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1});

my $fd;
if (!open($fd, "< $cloud_db")) {
    print STDERR "Can't open $cloud_db\n";
    exit 1;
}

my %domains;
while (my $row = $csv->getline($fd)) {
    my @data = @$row;
    if ($data[5]) {
        if ($type eq 'squid') {
            foreach my $url (split(/;/, $data[4])) {
                $url =~ s/^https?:\/\///;
                $url =~ s/\/.*$//;

                my $match = 0;
                foreach my $key (keys(%domains)) {
                    my $regex_url = $url;
                    $regex_url =~ s/\./\\./g;
                    if ($key =~ /.+$regex_url$/) {
                        $domains{$key} = 0;
                    }
                    $key =~ s/\./\\./g;
                    if ($url =~ /$key$/) {
                        $match = 1;
                    }
                }
                if (!$match) {
                    $domains{$url} = 1;
                }
            }
        } else {
            if (!$data[7]) {
                $data[7] = " ";
            }
            if (!$data[8]) {
                $data[8] = " ";
            }
            print "$data[6]/$data[5]\t$data[4]\t$data[7]\t$data[8]\t$data[9]\n";
        }
    }
}
close $fd;

if (%conf) {
    my $db = DBI->connect("DBI:mysql:casb:$conf{db_report_host}", $conf{db_report_user}, $conf{db_report_password});
    if (!$db) {
        print STDERR "Can't connect database: ".$DBI::errstr."\n";
        exit 1;
    }

    my $sth = $db->prepare("set names utf8");
    $sth->execute();
    $sth = $db->prepare("select id,category,domain from cloud_service");
    if (!$sth || !$sth->execute()) {
        print STDERR "Failed to get services\n";
        exit 1;
    }
    while (my @row = $sth->fetchrow_array) {
        my $domain = $row[2];
        $domain =~ s/,/;/g;
        if ($type eq 'squid') {
            foreach my $url (split(/;/, $domain)) {
                $url =~ s/^https?:\/\///;
                $url =~ s/\/.*$//;

                my $match = 0;
                foreach my $key (keys(%domains)) {
                    my $regex_url = $url;
                    $regex_url =~ s/\./\\./g;
                    if ($key =~ /.+$regex_url$/) {
                        $domains{$key} = 0;
                    }
                    $key =~ s/\./\\./g;
                    if ($url =~ /$key$/) {
                        $match = 1;
                    }
                }
                if (!$match) {
                    $domains{$url} = 1;
                }
            }
        } else {
            print "$row[1]/$row[0]\t$domain\t\t\t\n";
        }
    }
}

if ($type eq 'squid') {
    if (-f '/var/www/conf/swglogin.conf') {
        my $swgconf = Config::General->new('/var/www/conf/swglogin.conf');
        my %swgconf = $swgconf->getall;
        if (defined($swgconf{servername})) {
            print "$swgconf{servername}\n";
        }
    }
    foreach my $key (keys(%domains)) {
        if ($domains{$key}) {
            print "$key\n";
        }
    }
}

exit 0;
