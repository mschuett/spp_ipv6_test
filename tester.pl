#!/usr/bin/perl

=head1 Snort Rule Tester

Test Snort preprocessors or rules by preparing a PCAP input, a snort.conf
with custom options and specifying an expected SID-output.

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

=head1 Licence

Copyright (c) 2011 Martin Schuette <info@mschuette.name>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
   
THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

=cut

use autodie;

use Term::ANSIColor;
use File::Temp;
use File::Copy;
use File::Path qw(remove_tree);
use File::Basename;
use Getopt::Long;

# Modern::Perl and File::Copy::Recursive are non-Core modules, so we provide a copy in ./lib
# SnortUnified is probably not in your standard INC either:
use lib './lib';
use Modern::Perl;
use File::Copy::Recursive qw/dircopy/;
use SnortUnified(qw(:ALL));
use IPC::Cmd qw(run);

my ($debug, $keepfiles, $snort, $fromconfig);

sub print_help {
    print "available options:\n";
    print "  --snort <file>\tthe Snort executable\n";
    print "  --config <dir>\tthe configuration to use\n";
    print "  --debug       \tprint debugging messages\n";
    print "  --keepfiles   \tdo not delete temporary directory\n";
    exit 0;
}

sub get_cl {
  my $debug = 0;
  my $keepfiles = 0;
  my $snort = "/home/mschuett/tmp/snort/bin/snort";
  my $fromconfig = "/home/mschuett/tmp/snort/etc";
  #my $fromconfig = "./etc";

  my $options = GetOptions(
      "debug"     => \$debug,
      "keepfiles" => \$keepfiles,
      "snort=s"   => \$snort,
      "config=s"  => \$fromconfig,
  );
  if (!$options) {
      print "unrecognized options...\n";
      print_help;
  }
  return ($debug, $keepfiles, $snort, $fromconfig);
}



=head1 Functions

=head2 C<edit_config>

If a C<.conf> file is provided, then its content is used for Snort's configuration.
If C<snort.conf> contains the lines C<### tester.pl begin> and C<### tester.pl end>
then everything between these lines is deleted and an "include" statement for
the test-specific config is inserted (without these lines the "include"
statement is appended at the end of the file).

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
                if ((/^config event_queue:/)
                  && ((/max_queue (\d+)/ && $1 < 8) or (/log (\d+)/ && $1 < 8))) {
                    print "Warning: configured event_queue might be too small.\n";
                }
                if (/### tester\.pl begin/) {
                        last;
                }
        };

        # include test config, also ensure we have a usable log output
        print $newfile "include $testconf\n";
        print $newfile "output unified2: filename snort.log, limit 128\n";
        # also set config to disable decoder alerts (many and changing)
        # and to log events without a matching preprocessor.rules
        print $newfile "config disable_decode_alerts\n";
        print $newfile "config autogenerate_preprocessor_decoder_rules\n";

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
            print "copied config dir from \"$fromconfig\" to \"$configdir\"\n" if $debug;
        }

        return ($base, $configdir);
}

=head2 C<run_snort>

Actually executes Snort using the temporary configuration directory and
the test's PCAP.
Return boolean indicating if the command executed without errors or not.

=cut

sub run_snort {
        my ($snort, $testname, $basedir, $configdir) = @_;

        my $pcapname   = "$basedir/${testname}.pcap";
        my $snortconf  = "$configdir/snort.conf";
        my $stdout_dst = "$basedir/snort.stdout";
        my $stderr_dst = "$basedir/snort.stderr";
        my $cmdline    = "$snort -q -c $snortconf -l $basedir -r $pcapname";
        print "cmdline is \"$cmdline\"\n" if $debug;

        # execute snort
        my($success, $error_message, $full_buf, $stdout_buf, $stderr_buf)
          = run(command => $cmdline, verbose => 0);

        if (!$success) {
            print "Warning: Snort call failed ($error_message)\n";
            #print "=== stdout: ===\n$$stdout_buf[0]\n";
            print "=== stderr from Snort: ===\n$$stderr_buf[0]\n";
        }

        my ($file, $line);
        open $file, '>', $stdout_dst;
        foreach $line (@$stdout_buf) {
            print $file $line;
        }
        close($file);
        open $file, '>', $stderr_dst;
        foreach $line (@$stderr_buf) {
            print $file $line;
        }
        close($file);
        return $success;
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
        
        my $rc = run_snort($snort, $testname, $basedir, $configdir);
        if (!$rc) {
            print "Bailing out after Snort error...\n";
            die();
        }

        my @result = read_uf2($basedir);
        @result = sort @result;
        my @spec = read_spec($basedir, $testname);

        if (@spec ~~ @result) {
                #print "Test $testname: ", colored ( "OK", 'green'), "\n";
                printf "Test %-30s %s\n", "$testname:", colored ( "OK", 'green');
                if ($keepfiles) {
                    print "keep files...\n" if $debug;
                } else {
                    remove_tree($basedir);
                    print "removed path $basedir...\n" if $debug;
                }
                return 0;
        } else {
                printf "Test %-30s %s\n", "$testname:", colored ( "Failed!", 'red');
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

($debug, $keepfiles, $snort, $fromconfig) = get_cl();
foreach my $opt (@ARGV) {
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

