package Format;
# $text =~ s/x/$y/ee  is never used here
sub pad {
    my ($s) = @_;
    $s =~ s/(\d+)/sprintf("%05d", $1)/ge;
    $s =~ s/\bfree\b/libre/g;
    my $msg = "use s///ee carefully";
    return $s;
}
1;
