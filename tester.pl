#!/usr/bin/perl

=head1 Snort Rule Tester

Test Snort preprocessors or rules by preparing a PCAP input and specifying an
expected SID-output.
Optionally add snort.conf options to use.

=head1 Notes

=over 1

=item *

needs perl module SnortUnified, cf. 'use lib' statement below

=item *

setting $copy_config causes every test to run with a new copy of the
      snort/etc directory. This only works if snort.conf uses absolute paths
      for rule directories.
      i.e. "include reference.config" is OK, but "include ../rules/local.rules" is not!

=item *

if a test has a .config file, then its contest is written into snort.conf
      for this all lines between "### tester.pl begin" and "### tester.pl end"
      are replaced

=item *

if a test is successful its temporary directory is cleared -- but if it
      fails its directory is kept for manual inspection and has to be removed later

=back

=cut

use autodie;

use Term::ANSIColor;
use File::Temp;
use File::Copy;
use File::Path qw(remove_tree);
use File::Basename;

# Modern::Perl and File::Copy::Recursive are non-Core modules, so we provide a copy in ./lib
# SnortUnified is probably not in your standard INC either:
use lib './lib';
use Modern::Perl;
use File::Copy::Recursive qw/dircopy/;
use SnortUnified(qw(:ALL));
#use SnortUnified::MetaData(qw(:ALL));
#use Data::Dumper;

# for module path debugging:
# print join "\n ", @INC;
# print "\n";
# print map {"$_ => $INC{$_}\n"} keys %INC;
# print "\n";

my $debug = 0;
my $keepfiles = 0;
my $snort = "/home/mschuett/tmp/snort/bin/snort";
my $fromconfig = "/home/mschuett/tmp/snort/etc";

=head1 Functions

=head2 C<edit_config>

If a C<.conf> file is provided, then its content is used for Snort's configuration.
If C<snort.conf> contains the lines C<### tester.pl begin> and C<### tester.pl end>
then everything between these lines is deleted and an "include" statement for
the test-specific config is inserted.

=cut

sub edit_config {
        my ($configdir, $testname) = @_;
        my $testconf = "$configdir/../${testname}.conf";
        my $snortconf = "$configdir/snort.conf";
        my $tmpfile = "${snortconf}.tmp";

        if (! -e $testconf) {
                # nothing to do here
                print "no $testconf --> skip edit_config\n" if $debug;
                return;
        }

        open my $newfile, '>', $tmpfile;
        open my $file, '<', "$snortconf";
        while (<$file>) {
                print $newfile $_;
                if (/### tester\.pl begin/) {
                        last;
                }
        };
        print $newfile "include $testconf\n";
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

=head2 C<make_basedir>

Creates a temporary directory for the test run. The test files and all files
in the C<snort.conf> directory are copied there.

=cut

sub make_basedir {
        my ($src_dir, $testname) = @_;
        
        # create and populate temp. dir
        my $tmpdir = File::Temp->newdir("snort-test.XXXXX", CLEANUP => 0, TMPDIR => 1);
        my $base = $tmpdir->dirname;
        
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
        
        my $configdir = "$base/etc";
		if (! -e "${fromconfig}/snort.conf") {
			print "Error: No snort.conf in \$fromconfig directory $fromconfig\n";
		} else {
			dircopy($fromconfig, $configdir);
			print "copied config dir is \"$configdir\"\n" if $debug;
		}

        return ($base, $configdir);
}

=head2 C<run_snort>

Actually executes Snort using the temporary configuration directory and
the test's PCAP.

=cut

sub run_snort {
        my ($snort, $testname, $basedir, $configdir) = @_;

        my $pcapname = "$basedir/${testname}.pcap";
        my $snortconf = "$configdir/snort.conf";
        my $snort_output = "$basedir/snort.output";
        my $cmdline = "$snort -q -c $snortconf -l $basedir -r $pcapname";
        print "cmdline is \"$cmdline\"\n" if $debug;

        # execute snort
        my $pid = open(my $cmd, "-|", $cmdline);
        my $output = "";
        while (<$cmd>) {
            $output .= $_;
        }
        close($cmd);

        open my $file, '>', $snort_output;
        print $file $output;
        close($file);
}

=head2 C<read_spec>

Read specification for curren test case.
Returns array of SIDs.

=cut

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

=head2 C<read_uf2>

Find the C<snort.log> from the test run and decode its content with SnortUnified.
Returns an array of SIDs.

=cut

sub read_uf2 {
        my ($base) = @_;
        my $template= "snort.log";
        my @filelist = glob("$base/$template.*");
        my @lines;
        
        my $file = openSnortUnified($filelist[0])
                or die "cannot open ".$filelist[0];

        while ( my $record = readSnortUnifiedRecord() ) {
                next unless ($record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6)
						  or ($record->{'TYPE'} eq $UNIFIED2_IDS_EVENT);
                
                my ($gen, $id, $rev) =
                        ($record->{'sig_gen'}, $record->{'sig_id'}, $record->{'sig_rev'});
                push(@lines, "[$gen:$id:$rev]");
        }
        closeSnortUnified();
        
        my $count = @lines;
        print "logfile has $count events\n" if $debug;
        return @lines;
}

=head2 C<run_testcase>

Run one testcase and print result.

=cut

sub run_testcase {
        my ($src_dir, $testname) = @_;
        my ($basedir, $configdir) = make_basedir($src_dir, $testname);
        edit_config($configdir, $testname);
        
        run_snort($snort, $testname, $basedir, $configdir);

        my @result = read_uf2($basedir);
		@result = sort @result;
        my @spec = read_spec($basedir, $testname);

        if (@spec ~~ @result) {
                #print "Test $testname: ", colored ( "OK", 'green'), "\n";
                printf "Test %-20s %s\n", "$testname:", colored ( "OK", 'green');
				if ($keepfiles) {
					print "keep files...\n" if $debug;
				} else {
					remove_tree($basedir);
					print "removed path $basedir...\n" if $debug;
				}
                return 0;
        } else {
                printf "Test %-20s %s\n", "$testname:", colored ( "Failed!", 'red');
                #print "Test $testname: ", colored ( "Failed!", 'red'), "\n";
                print "\tspec was:  " . (@spec   == 0 ? "-" : join(",", @spec)) . "\n";
                print "\tresult is: " . (@result == 0 ? "-" : join(",", @result)) . "\n";
				print "keep files...\n" if $debug;
                return 1;
        }
}

=head2 C<get_testcases>

Find all tests in a given path.

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

=head1 Command Line

=over 1

=item C<-d>

enable debugging output (shows paths and commandline)

=item C<-k>

keep temporary files (useful for debugging)

=item C<test> ...

run these test cases

=item C<directory> ...

run all tests in this directory

=back

=cut

foreach my $opt (@ARGV) {
        if ($opt =~ /-d/) {
                $debug++;
                next;
        }
        if ($opt =~ /-k/) {
                $keepfiles++;
                next;
        }
        my ($name,$path,$suffix) = fileparse($opt, (".spec", ".pcap", ".conf"));
        
        if ( -d $path.$name ) {
                foreach my $testname (get_testcases($path.$name)) {
                        run_testcase($path.$name, $testname);
                }
        } elsif ( -e $path.$name.$suffix || -e $path.$name.".spec" ) {
                run_testcase($path, $name);
        } else {
                print "Cannot handle argument \"$opt\"\n";
        }
}

