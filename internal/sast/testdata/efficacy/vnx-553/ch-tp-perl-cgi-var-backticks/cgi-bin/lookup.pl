#!/usr/bin/perl
use strict;
use CGI;

my $q = CGI->new;
print $q->header('text/plain');
my $domain = $q->param('domain');
~>my $result = `whois $domain`;
print $result;
