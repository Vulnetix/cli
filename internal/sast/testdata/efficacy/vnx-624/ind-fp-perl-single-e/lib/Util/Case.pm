package Util::Case;
use strict;
use warnings;

sub titlecase {
    my ($s) = @_;
    $s =~ s/\b(\w)/uc($1)/ge;
    $s =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return $s;
}

1;
