#!/usr/bin/perl

#
# Notes:
#  - needs perl module SnortUnified, cf. 'use lib' statement below
#  - setting $copy_config causes every test to run with a new copy of the
#    snort/etc directory. This only works if snort.conf uses absolute paths
#    for rule directories.
#    i.e. "include reference.config" is OK, but "include ../rules/local.rules" is not!
#  - if a test has a .config file, then its contest is written into snort.conf
#    for this all lines between "### tester.pl begin" and "### tester.pl end"
#    are replaced
#

use strict;
use warnings "all";
use autodie;

use Term::ANSIColor;
use File::Temp;
use File::Copy;
use File::Copy::Recursive qw/dircopy/;
use File::Path qw(remove_tree);
use File::Basename;

# SnortUnified is probably not in your standard INC -- so tell me where it is:
use lib '/home/mschuett/NetBeansProjects/svn.haiti.cs/tools/SnortUnified';
use SnortUnified(qw(:ALL));
#use SnortUnified::MetaData(qw(:ALL));
#use Data::Dumper;

my $copy_config = 1;
my $debug = 1;
my $snort = "/home/mschuett/tmp/snort/bin/snort";
my $frompath = "/home/mschuett/NetBeansProjects/svn.haiti.cs/tools/tests";
my $fromconfig = "/home/mschuett/tmp/snort/etc";

sub edit_config {
        my ($configdir, $testname) = @_;
        my $testconf = "$configdir/${testname}.conf";
        my $snortconf = "$configdir/snort.conf";
        my $tmpfile = "$configdir/${snortconf}.tmp";
        my @testlines;

        if (! -e $testconf) {
                # nothing to do here
                return;
        }

        open my $file, '<', "$testconf";
        while (<$file>) {
                push(@testlines, $_);
        };
        close $file;

        open my $newfile, '>', $tmpfile;
        open $file, '<', "$snortconf";
        while (<$file>) {
                print $newfile $_;
                if (/### tester\.pl begin/) {
                        last;
                }
        };
        print $newfile join("", @testlines);
        while (<$file>) {
                if (/### tester\.pl end/) {
                        print $newfile $_;
                        last;
                }
        };
        while (<$file>) {
                print $newfile $_;
        };
        close $file;
        close $newfile;
        rename $tmpfile, $snortconf;
        print "rewrote snort.conf\n" if $debug;
}

sub make_basedir {
        my ($src_dir, $testname) = @_;
        #$frompath, $pcapfile, $specfile, $copy_config
        
        # create and populate temp. dir
        my $tmpdir = File::Temp->newdir("snort-test.XXXXX", CLEANUP => 0, TMPDIR => 1);
        my $base = $tmpdir->dirname;
        my $configdir;
        
        print "source dir is \"$src_dir\"\n" if $debug;
        print "tmp dir is \"$base\"\n" if $debug;

        print "copy \"$src_dir/${testname}.pcap\" ... " if $debug;
        copy("$src_dir/${testname}.pcap", "$base/${testname}.pcap")
                or die "copy failed: $!";
        print "copy \"$src_dir/${testname}.spec\" ... " if $debug;
        copy("$src_dir/${testname}.spec", "$base/${testname}.spec")
                or die "copy failed: $!";

        # check if config file exists:
        if ( -e "$src_dir/${testname}.conf" ) {
                print "copy \"$src_dir/${testname}.conf\" ... " if $debug;
                copy("$src_dir/${testname}.conf", "$base/${testname}.conf")
                        or die "copy failed: $!";
        }
        
        if ($copy_config) {
                $configdir = "$base/etc";
                dircopy($fromconfig, $configdir);
                print "copied config dir is \"$configdir\"\n" if $debug;
        } else {
                $configdir = $fromconfig;
        }

        return ($base, $configdir);
}

sub run_snort {
        my ($snort, $testname, $basedir, $configdir) = @_;

        my $pcapname = "$basedir/${testname}.pcap";
        my $snortconf = "$configdir/snort.conf";
        my $cmdline = "$snort -q -c $snortconf -l $basedir -r $pcapname";
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
        my ($base, $testname) = @_;

        my $spec = "$base/${testname}.spec";
        my @lines;
        open my $file, '<', $spec;
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
        my ($src_dir, $testname) = @_;
        #$pcapfile, $specfile, $configfile
        
        my ($basedir, $configdir) = make_basedir($src_dir, $testname);
        
        if ( -e "$src_dir/${testname}.conf") {
                edit_config($configdir, $testname);
        }
        
        run_snort($snort, $testname, $basedir, $configdir);

        my @result = read_uf2($basedir);
        my @spec = read_spec($basedir, $testname);

        if (@spec ~~ @result) {
                print "Test $testname: ", colored ( "OK", 'green'), "\n";
                remove_tree($basedir);
                return 0;
        } else {
                print "Test $testname: ", colored ( "Failed!", 'red'), "\n";
                print "\tspec was:  " . (@spec   == 0 ? "-" : join(",", @spec)) . "\n";
                print "\tresult is: " . (@result == 0 ? "-" : join(",", @result)) . "\n";
                return 1;
        }
}

=head2

Find all C<.spec> files in C<$frompath>.
Return a list of testcases (i.e. only the base name of the pcap file).

=cut

sub get_testcases {
        my $frompath = shift;
        
        my @filelist = glob("$frompath/*.spec");
        my @testlist;

        foreach my $specfile (@filelist) {
                my ($name,$path,$suffix) = fileparse($specfile, ".spec");
                my $pcapfile = "${path}/${name}.pcap";
                
                if ( -f $pcapfile ) {
                        push(@testlist, $name);
                        print "found test files for: \"$name\"\n" if $debug;
                } else {
                        print "Warning: found specification \"${name}.spec\" without expected PCAP \"${name}.pcap\"\n";
                }
        }
        return @testlist;
}

foreach my $testname (get_testcases($frompath)) {
        run_testcase($frompath, $testname);
}

