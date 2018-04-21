#! /usr/bin/env perl
use strict;
use warnings;
use File::Tail;

use constant {
    NGINX_ERROR_LOG => '/usr/local/nginx/logs/error.log',
    NGINX_DENY_CONF => '/usr/local/nginx/conf/deny.conf',
    NGINX_RELOAD => '/usr/local/nginx/sbin/nginx -s reload',
    ILLEGALS => [qw/phpmyadmin wp-login\.php CoordinatorPortType azenv\.php/],
};

unless (-r NGINX_DENY_CONF) {
    open my $ndc_fp, '>'.NGINX_DENY_CONF;
    print $ndc_fp "# miniwaf\n";
    close $ndc_fp;
}

my $opt = $ARGV[0] // '';
my $dry_run = $opt eq 'dry_run' ? 1 : 0;

print "start dry_run\n" if $dry_run;

my $illegals = ILLEGALS;

# preload denied ips into hashref
my $map_of_ips = {};
open my $fp, '< '.NGINX_DENY_CONF;
map { if (/^deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});/) { $map_of_ips->{$1}=1; }; } <$fp>;
close $fp;

sub append_deny {
    my $_ip = shift or return;
    $map_of_ips->{$_ip} = 1;
    unless ($dry_run) {
        open my $_fp, '>> ' . NGINX_DENY_CONF;
        print $_fp sprintf 'deny %s;'."\n", $_ip;
        close $_fp;
    } else {
        print $_ip."\n";
    }
}

sub judge {
    my ($log, $callback) = @_;
    ($log || '') =~ /client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ or return;
    my $ip = $1;
    return if $map_of_ips->{$ip};
    my $found = 0;
    for my $il (@$illegals) {
        if ($log =~ /$il/i) {
            print "block reason: $il\n" if $dry_run;
            $found = 1;
            append_deny($ip);
            &$callback($ip) if $callback && !$dry_run;
        }
    }
    $found;
}

#precheck error.log
print "scan error.log ... \n" if $dry_run;
my $new_in_precheck = 0;
for my $err_filename (NGINX_ERROR_LOG, NGINX_ERROR_LOG.".1") {
    if (open my $fp2, "<".$err_filename) {
        while (<$fp2>) {
            $new_in_precheck = 1 if judge($_);
        }
        close $fp2;
    }
}
print "finished\n" if $dry_run;

system NGINX_RELOAD if $new_in_precheck && !$dry_run;

#listen error.log
my $file = File::Tail->new(
  name        => NGINX_ERROR_LOG,
  interval    => 1,
  maxinterval => 5,
);

if ($dry_run) {
    print "dry_run finished\n";
    exit(0);
}

while (my $log = $file->read) {
    judge($log, sub {
        system NGINX_RELOAD;
    });
}
