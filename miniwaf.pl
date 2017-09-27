#! /usr/bin/env perl
use strict;
use warnings;
use File::Tail;

use constant {
    NGINX_ERROR_LOG => '/usr/local/nginx/logs/error.log',
    NGINX_DENY_CONF => '/usr/local/nginx/conf/deny.conf',
};

unless (-r NGINX_DENY_CONF) {
    open my $ndc_fp, '>'.NGINX_DENY_CONF;
    print $ndc_fp "# miniwaf\n";
    close $ndc_fp;
}

# preload denied ips into hashref
my $map_of_ips = {};
open my $fp, '< '.NGINX_DENY_CONF;
#my @arr = <$fp>;
map { if (/^deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});/) { $map_of_ips->{$1}=1; }; } <$fp>;
close $fp;

my $file = File::Tail->new(
  name        => NGINX_ERROR_LOG,
  interval    => 1,
  maxinterval => 5,
);

my $realtime_ips = {};
while (my $line=$file->read) {
    if (($line =~ /phpmyadmin/i || $line =~ /Primary script unknown/i) && $line =~ /client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
        my $ip = $1;
        next if ($map_of_ips->{$ip});
        unless ($realtime_ips->{$ip}) {
            $realtime_ips->{$ip} = 1;
            open my $fp2, '>> ' . NGINX_DENY_CONF;
            print $fp2 sprintf 'deny %s;'."\n", $ip;
            close $fp2;
            `/usr/local/nginx/sbin/nginx -s reload`;
        }
    }
}
