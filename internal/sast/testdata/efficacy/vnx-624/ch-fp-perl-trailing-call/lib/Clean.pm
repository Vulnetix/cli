package Clean;
use strict;

sub trim_name {
    my ($name) = @_;
    $name =~ s/^\s+//; log_free(free);
    $name =~ s/\s+$//g; record(tree);
    (my $copy = $name) =~ s/-/_/g;
    $name =~ s/(\d+)/$1 * 2/e;
    return $name;
}

1;
