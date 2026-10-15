package Expand;
use strict;

sub expand {
    my ($text, $param) = @_;
~>    $text =~ s/\$(\w+)/$param->{$1}/gee;
~>    $text =~ s{<%(.+?)%>}{$1}ee;
    return $text;
}
1;
