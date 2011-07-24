#!/usr/bin/perl -I./SnortUnified

use lib './lib';
use Modern::Perl;
use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use POSIX qw(strftime);
use Switch;
use Net::DNS;

use Data::Dumper;

$debug = 0;

my $dir = '/home/mschuett/tmp/snort/etc';
my $sids = get_snort_sids("$dir/sid-msg.map","$dir/gen-msg.map");
my $class = get_snort_classifications("$dir/classification.config");

my $printpkt = 0;
my $resolveDNS = 0;
my $DNSres;

my $file = shift;
my $openfile;
my $uf_file = undef;
my $old_uf_file = undef;
my $record = undef;
my $i = 0;

# taken from FreeBSD's /tcpdump/master/libpcap/pcap/bpf.h,v 1.19.2.8 2008-09-22 20:16:01
my %linktype = (
	  0 => "BSD loopback",
	  1 => "Ethernet",
	  2 => "Experimental Ethernet",
	  3 => "AX.25",
	  4 => "ProNET",
	  5 => "Chaos",
	  6 => "802.5 Token ring",
	  7 => "ARCNET",
	  8 => "SLIP",
	  9 => "PPP",
	 10 => "FDDI",
	 11 => "LLC-encapsulated ATM",
	 12 => "raw IP",
	 51 => "PPPoE",
	104 => "Cisco HDLC",
	105 => "802.11 wireless",
	109 => "IPsec",
	117 => "pflog"
);

sub prettyprint {
	my ($field, $value) = @_;
	#our %linktype;

	if (!defined $field) { return "(undef field)"; }	
	if (!defined $value) { return "(undef value)"; }	

	switch($field) {
		case "linktype" {
			my $lt = defined($linktype{$value}) ? $linktype{$value} : 'unknown';
			return "linktype=$value($lt)";
		}
		case "pkt" {
			if ($printpkt) {
				return sprintf("data=\"%*v02x\" ", " ", $value);
			}
		}
		case "tv_sec" {
			return "tv_sec=$value(".strftime("%FT%T", localtime($value)).")";
		}
		case "protocol" {
			my ($name,$aliases,$proto) = getprotobynumber($value);
			return "protocol=$value($name)";
		}
		case "class" {
			my $name = $class->{$value}->{'name'};
			return "class=$value". (defined($name) ? "($name)" : "");
		}
		case /^sp$|^dp$/ {
			my ($name,$aliases,$port,$proto) = getservbyport($value, '');
			if (defined $name) {
			  return "$field=$value($name)";
		  } else {
			  return "$field=$value";
		  }
		}
		case /^sip$|^dip$/ {
			if (!$resolveDNS) { return "$field=$value"; }
			if (!defined $DNSres) { $DNSres = Net::DNS::Resolver->new; }

			my $name;
			my $query = $DNSres->query($value);
			if (!$query) { return "$field=$value"; }
			else {
				foreach my $rr ($query->answer) {
					#print Dumper($rr);
					next unless $rr->type eq "PTR";
					$name = $rr->ptrdname;
				}
				return "$field=$value($name)";
			}
		}
		# default:
		else {
			return "$field=$value";
		}
	}
	if (!defined $field) { return "(undef field, post)"; }	
	if (!defined $value) { return "(undef value, post)"; }	
}

$uf_file = get_latest_file() || die "no files to get";

$openfile = openSnortUnified($uf_file) || die "cannot open $uf_file";
read_records();

sub prettysigID {
	my ($id, $gen, $rev) = @_;
	my $msg = $sids->{$gen}->{$id}->{'msg'};
	return "sig=[$gen:$id:$rev]" . (defined($msg) ? "($msg)" : "");
}

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
	  print($UNIFIED2_TYPES->{$record->{'TYPE'}}.": ");
	  foreach my $field (@{$record->{'FIELDS'}}) {
		  print prettyprint($field, $record->{$field})." ";
		  # make sure to catch sigID at least once:
		  if ($field eq 'sig_rev') {
			  print prettysigID($record->{'sig_id'},
				  $record->{'sig_gen'},
				  $record->{'sig_rev'})." ";
		  }
	  }
	  print("\n");
#	print($i++);
#    foreach $field ( @{$record->{'FIELDS'}} ) {
#        if ( $field ne 'pkt' ) {
#            print("," . $record->{$field});
#        }
#    }
#    print("\n");
  }
  return 0;
}

sub get_latest_file() {
  my @ls = <$file*>;
  my $len = @ls;
  my $uf_file = "";

  if ($len) {
  # Get the most recent file
    my @tmparray = sort{$b cmp $a}(@ls);
    $uf_file = shift(@tmparray);
  } else {
    $uf_file = undef;
  }
  return $uf_file;
}
