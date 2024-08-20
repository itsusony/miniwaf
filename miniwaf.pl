#!/usr/bin/env perl
use strict;
use warnings;
use File::Tail;
use Fcntl qw(:flock SEEK_END);
use Try::Tiny;

# Configuration
my $NGINX_ERROR_LOG = $ENV{NGINX_ERROR_LOG} || '/var/log/nginx/error.log';
my $NGINX_DENY_CONF = $ENV{NGINX_DENY_CONF} || '/etc/nginx/conf.d/deny.conf';
my $NGINX_RELOAD = $ENV{NGINX_RELOAD} || 'nginx -s reload';
my $UFW_ADD_RULE = $ENV{UFW_ADD_RULE} || 'ufw deny from %s to any';
my @ILLEGALS = qw/phpmyadmin wp-login\.php CoordinatorPortType azenv\.php \.vscode \.git \.env/;

my $opt = $ARGV[0] // '';
my $dry_run = $opt eq 'dry_run' ? 1 : 0;
print "Starting in dry run mode\n" if $dry_run;

# Ensure NGINX_DENY_CONF exists
unless (-e $NGINX_DENY_CONF) {
    open my $ndc_fp, '>', $NGINX_DENY_CONF or die "Cannot create $NGINX_DENY_CONF: $!";
    print $ndc_fp "# miniwaf\n";
    close $ndc_fp;
}

# Load existing denied IPs
my %map_of_ips;
try {
    open my $fp, '<', $NGINX_DENY_CONF or die "Cannot open $NGINX_DENY_CONF: $!";
    while (<$fp>) {
        if (/^deny (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});/) {
            $map_of_ips{$1} = 1;
        }
    }
    close $fp;
} catch {
    warn "Error reading $NGINX_DENY_CONF: $_";
};

sub append_deny {
    my $ip = shift or return;
    return if $map_of_ips{$ip};
    $map_of_ips{$ip} = 1;

    unless ($dry_run) {
        try {
            open my $fp, '>>', $NGINX_DENY_CONF or die "Cannot open $NGINX_DENY_CONF for appending: $!";
            flock($fp, LOCK_EX) or die "Cannot lock $NGINX_DENY_CONF: $!";
            seek($fp, 0, SEEK_END) or die "Cannot seek to end of $NGINX_DENY_CONF: $!";
            print $fp "deny $ip;\n";
            flock($fp, LOCK_UN) or die "Cannot unlock $NGINX_DENY_CONF: $!";
            close $fp;

            my $ufw_command = sprintf $UFW_ADD_RULE, $ip;
            system($ufw_command) == 0 or die "UFW command failed: $?";
        } catch {
            warn "Error updating rules for IP $ip: $_";
        };
    } else {
        print "Would block IP: $ip\n";
    }
}

sub judge {
    my ($log, $callback) = @_;
    return unless $log =~ /client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
    my $ip = $1;
    return if $map_of_ips{$ip};

    for my $pattern (@ILLEGALS) {
        if ($log =~ /$pattern/i) {
            print "Block reason: $pattern\n" if $dry_run;
            append_deny($ip);
            $callback->($ip) if $callback && !$dry_run;
            return 1;
        }
    }
    return 0;
}

# Precheck error log
print "Scanning error log...\n" if $dry_run;
my $new_in_precheck = 0;
for my $log_file ($NGINX_ERROR_LOG, "$NGINX_ERROR_LOG.1") {
    try {
        open my $fp, '<', $log_file or die "Cannot open $log_file: $!";
        while (<$fp>) {
            $new_in_precheck = 1 if judge($_);
        }
        close $fp;
    } catch {
        warn "Error processing $log_file: $_";
    };
}
print "Scan finished\n" if $dry_run;

system($NGINX_RELOAD) if $new_in_precheck && !$dry_run;

if ($dry_run) {
    print "Dry run finished\n";
    exit 0;
}

# Monitor error log
try {
    my $file = File::Tail->new(
        name        => $NGINX_ERROR_LOG,
        interval    => 1,
        maxinterval => 5,
        resetafter  => 60,
    ) or die "Cannot tail $NGINX_ERROR_LOG: $!";

    while (defined(my $log = $file->read)) {
        judge($log, sub { system($NGINX_RELOAD) == 0 or die "Nginx reload failed: $?" });
    }
} catch {
    die "Error monitoring $NGINX_ERROR_LOG: $_";
};
