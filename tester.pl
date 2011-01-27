#!/usr/bin/perl

use strict;
use warnings "all";
use autodie;

use Term::ANSIColor;
use File::Temp;
use File::Copy;
use File::Path qw(remove_tree);

# SnortUnified is probably not in your standard INC -- so tell me where it is:
use lib '/home/mschuett/NetBeansProjects/svn.haiti.cs/tools/SnortUnified';
use SnortUnified(qw(:ALL));
#use SnortUnified::MetaData(qw(:ALL));
#use Data::Dumper;

my $debug = 0;
my $snort = "/home/mschuett/tmp/snort/bin/snort";
my $frompath = "/home/mschuett/tmp/tcpdumps/tests";
my $fromconfig = "/home/mschuett/tmp/snort/etc/snort.conf";

sub make_basedir {
        my ($frompath, $pcapfile, $specfile) = @_;
        
        # create and populate temp. dir
        my $tmpdir = File::Temp->newdir("snort-test.XXXXX", CLEANUP => 0, TMPDIR => 1);
        my $base = $tmpdir->dirname;
        print "tmp dir is \"$base\"\n" if $debug;

        copy("$frompath/$pcapfile", "$base/$pcapfile")
                or die "copy failed: $!";
        copy("$frompath/$specfile", "$base/$specfile")
                or die "copy failed: $!";
        # does not work -- config file path implies path to classification.config etc.
        # TODO: copy all required config files into $base
        # copy("$fromconfig", "$base/snort.conf")
                # or die "copy failed: $!";

        return $base;
}

sub run_snort {
        my ($snort, $fromconfig, $base, $pcap) = @_;
        my $cmdline = "$snort -q -c $fromconfig -l $base -r $base/$pcap";
        print "cmdline is \"$cmdline\"\n" if $debug;

        # execute snort
        my $pid = open(my $cmd, "-|", $cmdline);
        my $output = "";
        while (<$cmd>) {
            $output .= $_;
        }
        close($cmd);
                #or die "Snort command failed: $!\nOutput was:\n".$output;
}

sub read_spec {
        my ($base, $spec) = @_;

        my @lines;
        open my $file, '<', "$base/$spec";
        while (<$file>) {
                chomp;
                push(@lines, $_) if $_;  # ignores empty lines
        };
        close $file;
        
        my $count = @lines;
        print "spec    has $count events\n" if $debug;
        return @lines;
}

sub read_uf2 {
        my ($base) = @_;
        my $template= "snort.log";
        my @filelist = glob("$base/$template.*");
        my @lines;
        
        my $file = openSnortUnified($filelist[0])
                or die "cannot open ".$filelist[0];

        while ( my $record = readSnortUnifiedRecord() ) {
                next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6;
                
                my ($gen, $id, $rev) =
                        ($record->{'sig_gen'}, $record->{'sig_id'}, $record->{'sig_rev'});
                push(@lines, "[$gen:$id:$rev]");
        }
        closeSnortUnified();
        
        my $count = @lines;
        print "logfile has $count events\n" if $debug;
        return @lines;
}

sub eq_array {
        my (@a, @b) = @_;
        
        if (@a != @b) { return 0; }
        
        for (my $i = @a-1; $i >=0; $i--) {
                unless ($a[$i] == $b[$i]) {
                        return 0;
                }
        }

        return 1;
}

sub run_testcase {
        my ($pcapfile, $specfile) = @_;
        my $base = make_basedir($frompath, $pcapfile, $specfile);
        run_snort($snort, $fromconfig, $base, $pcapfile);

        my @result = read_uf2($base);
        my @spec = read_spec($base, $specfile);

        if (@spec ~~ @result) {
                print "Test $pcapfile: ", colored ( "OK", 'green'), "\n";
                remove_tree($base);
                return 0;
        } else {
                print "Test $pcapfile: ", colored ( "Failed!", 'red'), "\n";
                print "\tspec was:  " . (@spec   == 0 ? "-" : join(",", @spec)) . "\n";
                print "\tresult is: " . (@result == 0 ? "-" : join(",", @result)) . "\n";
                return 1;
        }
}

sub get_testcases {
        my @filelist = glob("*.spec");
        my @testlist;

        foreach my $specfile (@filelist) {
                my ($pcapfile) = ($specfile =~ /(.*)\.spec/);
                
                if ( -f $pcapfile ) {
                        push(@testlist, $pcapfile);
                        print "found test files for: \"$pcapfile\"\n" if $debug;
                } else {
                        print "Warning: found specification \"$specfile\" without expected PCAP \"$pcapfile\"\n";
                }
        }
        return @testlist;
}

# my %testcase = {
        # pcap => "pcap_rh_icmp",
        # spec => "pcap_rh_icmp.spec",
        # #config => ""
        # };
# TODO: loop for multiple test cases
# TODO: collect all .spec files to get test cases automagically
#my $pcapfile = "pcap_rh_icmp";
#my $specfile = "${pcapfile}.spec";
#run_testcase($pcapfile, $specfile);

foreach my $pcapfile (get_testcases) {
        run_testcase($pcapfile, "$pcapfile.spec");
}

