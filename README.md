Tests for the IPv6 Snort Plugin
===============================

A simple Perl-based test framework for Snort and three test collections to verify the IPv6 Snort Plugin.

Tool overview
-------------

Tests are described in yaml files, with every test case having a name, a
configuration file, a input pcap file, and a specification of expected snort
alerts.

The `unpack.pl` creates a test directory from a `.yaml` file and a directory
containing the `.pcap` and `.conf` files. Example: `/unpack.pl -f --srcdir
srcfiles_pp  --dstdir test_pp  --input testset-pp.yaml`

The `tester.pl` runs either a single test or all tests inside a given directory
(as created by `unpack.pl`). Example: `./tester.pl test_pp`

Test collections
----------------

The three test collections test different parts of the IPv6 Snort Plugin:
* preprocessor alerts (`testset-pp.yaml`),
* rule options (`testset-opt.yaml`),
* a combination of the above to detect the use of THC tools
* (`testset-thc.yaml`).


