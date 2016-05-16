#! /usr/bin/perl 

# Usage: nmap_util.pl -s 10.10.10.* -p 22 -f file
# Stores to file open hosts
#
# author: imuntean@redhat.com

use strict;
use warnings;

#-----------------------------------

use Nmap::Scanner;
use Nmap::Scanner::Host;
use Getopt::Long;
use Data::Dumper qw(Dumper);

#-----------------------------------
# init ip
my @ip;

my $byte1 = 0;
my $byte2 = 0;
my $byte3 = 0;
my $byte4 = 0;

# Variable to hold all the hosts up;
my @hosts_up;

my @hosts_with_port_open;

#Default 80
my $segment = '';
my $verbose = 1;

my $file = "";
my $help;

#-----------------------------------

my $scanner = new Nmap::Scanner;

#default
my $port_to_scan = 80;
my $max_rtt_timeout = "200ms";
my $max_retries = 1;
my $host_timeout = "5m";

#-----------------------------------

init();

#-----------------------------------

$scanner->register_scan_started_event(\&scan_started);
$scanner->register_port_found_event(\&port_found);

scan();

#-----------------------------------

sub init {
	handle_args();
}

sub handle_args {

# If no arguments print help message;
	my $arg = $#ARGV + 1;

	if ($arg == 0){	
		print_help();
		exit;
	}	

	GetOptions ("port|p=i" => \$port_to_scan,
			"segment|s=s" => \$segment,
			"file|f=s" => \$file,
			"help" => \$help );

	if ($segment eq ""){

		print "Segment not specified\n";
		print_help();
		exit;
	}

	split_ip();
}

sub split_ip {

	@ip = split (/\./, $segment);

	$byte1 = $ip[0];
	$byte2 = $ip[1];
	$byte3 = $ip[2];
	$byte4 = $ip[3];	
}


sub get_seg_type {

	my $type = 4;

	for my $byte (@ip)	{

		if  ($byte =~ /^\d+?$/) {
			$type = $type - 1;	

		}

	}
	return $type;

}

sub scan {

	my $seg_type = get_seg_type();

	if ($seg_type == 0 || $seg_type == 1) {

		$scanner->scan("-sS -n -T4 ".
				"--max-retries $max_retries ".
				"--max-rtt-timeout $max_rtt_timeout " .
				"--host-timeout $host_timeout ".
				"-p $port_to_scan --open $segment ") ;


	} elsif ($seg_type == 2) {
		for ($byte3 = 0; $byte3<255; $byte3++){
			$scanner->scan("-sS -n -T4 ".
					"--max-retries $max_retries ".
					"--max-rtt-timeout $max_rtt_timeout ".
					"--host-timeout $host_timeout ".
					"-p $port_to_scan --open $byte1.$byte2.$byte3.*");

		}
	} elsif ($seg_type == 3) {

		for ($byte2 = 0; $byte2<255; $byte2++){
			for ($byte3 = 0; $byte3<255; $byte3++){
				$scanner->scan("-sS -n -T4 --max-rtt-timeout 200ms --host-timeout 6s -p $port_to_scan --open $byte1.$byte2.*.*");

			}

		}


	}

}
sub print_help {

	print "\n";
	print "PORT :\n"."--port: Choose port which you want to scan\n\n"
		."SEGMENT :\n".
		"--segment: Choosse segment to scan\n\n".
		"HELP:\n".
		"--help\n\n";

}

#-----------------------------------

sub scan_started {

	my $self     = shift;
	my $host     = shift;

	my $addresses = join(', ', map {$_->addr()} $host->addresses());
	my $status = $host->status();

	push(@hosts_up, $addresses);

}

sub port_found {

	my $self     = shift;
	my $host     = shift;
	my $port     = shift;

#my $name = $host->hostname();
	my $addresses = join(', ', map {$_->addr()} $host->addresses());
	push(@hosts_with_port_open, $addresses);

	if ($verbose == 1) {
		print "$addresses\n"; }


}

#-----------------------------------

sub print_result {

	if ($port_to_scan eq ""){
		foreach my $host (@hosts_up){
			print " Here:$host\n";

		}
	} else {

		print "-------- $port_to_scan --------\n";
		foreach my $host(@hosts_with_port_open){
			print "$host\n";
			shift(@hosts_with_port_open);

		}
	}
}

#-----------------------------------


