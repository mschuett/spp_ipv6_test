#! /usr/bin/perl

=head1 Snort Test Collection Unpacker

Takes a YAML file containing the description of a test collection,
then uses the files in the given source directory to write all
test cases into the destination directory.

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

use lib "./lib";
use Modern::Perl;

use autodie;
use Data::Dumper;
use YAML::Tiny;
use Getopt::Long;
use File::Basename;
use File::Spec;
use File::Path qw(make_path remove_tree);
use Cwd 'abs_path';

my $verbose = 0;

### get command line options
sub print_help {
	print "available options:\n";
	print "  --srcdir <dir>\tdirectory with input files (.conf, .pcap)\n";
	print "  --dstdir <dir>\tdirectory to create\n";
	print "  --input <file>\tYAML file with testset description\n";
	print "  --force       \tif dstdir exists: remove and recreate it\n";
	print "  --latex       \texport testset as LaTeX table\n";
	print "  --verbose     \tprint verbose messages\n";
	exit 0;
}

sub get_cl {
  my $inputfile = undef;
  my $srcdir = '.';
  my $dstdir = undef;
  my $force = 0;
  my $latex = 0;
  my $options = GetOptions(
	  "srcdir=s" => \$srcdir,
	  "dstdir=s" => \$dstdir,
	  "input=s"  => \$inputfile,
	  "verbose"  => \$verbose,
	  "latex"    => \$latex,
	  "force"    => \$force,
	  "help"     => \&print_help,
  );
  
  if (!$options) {
	  print "unrecognized options...\n";
	  print_help;
  }
  
  if (not defined $inputfile) {
	  if ($ARGV[0]) {
		  $inputfile = $ARGV[0];
	  } else {
		  print "need inputfile...\n";
		  print_help;
	  }
  }
  
  if (!$dstdir) {
	  my ($name,$path,$suffix) = fileparse $inputfile, ".db", ".yml", ".yaml";
	  $dstdir = $name;
	  print "set dstdir to '$dstdir'\n" if $verbose;
  }
  return ($inputfile, $srcdir, $dstdir, $force, $latex);
}

sub yaml_read {
  my $file = shift;

  # read file into scalar:
  open( my $fh, '<', $file );
  my $yamltext = do { local( $/ ) ; <$fh> } ;
  close $fh;
  
  my $data = Load($yamltext);
  return $data;
}

sub export_latex {
	my $inputfile = shift;
	my $dataref = shift;
	print "\\begin{longtable}[l]{llll}\n";
	$inputfile =~ s/_/\\_/go;
	print "\\caption{Testset \\texttt{$inputfile}}\\\\\n";
	print "Test & .conf & pcap & SIDs\\tabularnewline\\hline\n\\endfirsthead\n";
	print "Test & .conf & pcap & SIDs\\tabularnewline\\hline\n\\endhead\n";
	foreach my $entry (@$dataref) {
		my @spec = split /,/, $entry->{spec};
		my $test = $entry->{test}; $test =~ s/_/\\_/go;
		my $conf = $entry->{conf}; $conf =~ s/_/\\_/go;
		my $pcap = $entry->{pcap}; $pcap =~ s/_/\\_/go;
		print
		  "\\texttt{$test} & ".
		  "\\texttt{$conf} & ".
		  "\\texttt{$pcap} & ".
		  @spec . " \\tabularnewline\n" ;
	}
	print "\\end{longtable}\n";
}

sub check_filenames {
	my $srcdir = shift;
	my $dataref = shift;

	my @missing_pcap;
	my @missing_conf;

	# check conf and pcap
	foreach my $entry (@$dataref) {
		my $f = File::Spec->catfile($srcdir, $entry->{conf});
		if ( ! -e $f ) {
			push @missing_conf, $f;
		}
		$f = File::Spec->catfile($srcdir, $entry->{pcap});
		if ( ! -e $f ) {
			push @missing_pcap, $f;
		}
	}
	print "Missing PCAP files:\n".(join "\n", @missing_pcap)."\n\n" if @missing_pcap;
	print "Missing conf files:\n".(join "\n", @missing_conf)."\n\n" if @missing_conf;

	if (@missing_pcap || @missing_conf) {
		print "missing files, exiting...\n" if $verbose;
		exit 1;
	} else {
		print "all files found\n" if $verbose;
	}
}

sub make_files {
	my $srcdir = shift;
	my $dstdir = shift;
	my $dataref = shift;

	make_path($dstdir, {verbose => $verbose});
	foreach my $entry (@$dataref) {
		my $old = abs_path(File::Spec->catfile($srcdir, $entry->{conf}));
		my $new = File::Spec->catfile($dstdir, $entry->{test}.".conf");
		symlink $old, $new;
		print "link $old --> $new\n" if $verbose;
		
		$old = abs_path(File::Spec->catfile($srcdir, $entry->{pcap}));
		$new = File::Spec->catfile($dstdir, $entry->{test}.".pcap");
		symlink $old, $new;
		print "link $old --> $new\n" if $verbose;

		$new = File::Spec->catfile($dstdir, $entry->{test}.".spec");
		my @spec = split /,/, $entry->{spec};
		foreach (@spec) { s/^\s+|\s+$//g; }
		my $specstr = join "\n", sort @spec;
		open my $specfile, ">", $new;
		print $specfile $specstr;
		close $specfile;
		print "wrote spec to $new\n" if $verbose;
	}
}

sub check_dstdir {
  my $dstdir = shift;
  my $force = shift;

  if ( -e $dstdir ) {
	  if ($force) {
		  print "Remove existing $dstdir\n" if $verbose;
		  remove_tree($dstdir, {verbose => $verbose});
	  } else {
		  print "$dstdir exists...\nuse -f option or remove it manually\n";
		  exit 1;
	  }
  }
}

sub main {
  my ($inputfile, $srcdir, $dstdir, $force, $latex) = get_cl;
  if ($verbose) {
	  print "using these options:\n";
	  print "inputfile: $inputfile\n";
	  print "srcdir:    $srcdir\n";
	  print "dstdir:    $dstdir\n";
	  print "force:     $force\n\n";
	  print "latex:     $latex\n\n";
  }
  
  my @data = @{yaml_read $inputfile};
  if ($latex) {
	  export_latex $inputfile, \@data;
  } else {
	  check_filenames $srcdir,\@data;
	  check_dstdir $dstdir, $force;
	  make_files $srcdir, $dstdir, \@data;
  }
}

main;
