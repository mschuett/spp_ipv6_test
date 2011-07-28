#! /usr/bin/perl

#use Modern::Perl;
use strict;
use warnings;

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
	print "  --verbose     \tprint verbose messages\n";
	exit 0;
}

sub get_cl {
  my $inputfile = undef;
  my $srcdir = '.';
  my $dstdir = undef;
  my $force = 0;
  my $options = GetOptions(
	  "srcdir=s" => \$srcdir,
	  "dstdir=s" => \$dstdir,
	  "input=s"  => \$inputfile,
	  "verbose"  => \$verbose,
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
  return ($inputfile, $srcdir, $dstdir, $force);
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
  my ($inputfile, $srcdir, $dstdir, $force) = get_cl;
  if ($verbose) {
	  print "using these options:\n";
	  print "inputfile: $inputfile\n";
	  print "srcdir:    $srcdir\n";
	  print "dstdir:    $dstdir\n";
	  print "force:     $force\n\n";
  }
  
  my @data = @{yaml_read $inputfile};
  check_filenames $srcdir,\@data;
  check_dstdir $dstdir, $force;
  make_files $srcdir, $dstdir, \@data;
}

main;