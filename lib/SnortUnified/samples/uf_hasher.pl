#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use Digest::MD5 qw(md5 md5_base64);

$file = shift || die("Usage: $0 <unified file>\n");
$debug = 0;
$UF_Data = {};
$record = {};
$logdata = undef;
$signature = undef;

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

print("file,record");
foreach $field ( @{$record->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) { 
        print("," . $field);
    } else {
        print(",pktmd5,");
    }
}
print("recmd5\n");

$i = 1;
while ( $record = readSnortUnifiedRecord() ) {
    
    print($file . "," . $i++);;
    
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' ) {
            print("," . $record->{$field});
        } else {
            print md5_base64($record->{$field}) . ",";
        }
    }
    print md5_base64($record->{'raw_record'});
    print("\n");

}

closeSnortUnified();

