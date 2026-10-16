#!/usr/bin/perl
use strict;
use warnings;
use CGI qw(:standard);

print header('text/plain');

my $target = param('target');
~>system("traceroute -m 10 $target");
