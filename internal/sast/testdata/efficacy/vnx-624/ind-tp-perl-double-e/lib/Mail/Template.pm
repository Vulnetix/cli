package Mail::Template;
use strict;
use warnings;

sub render {
    my ($tmpl, $param) = @_;
~>    $tmpl =~ s/\[%\s*(\w+)\s*%\]/$param->{$1}/gee;
    return $tmpl;
}

1;
