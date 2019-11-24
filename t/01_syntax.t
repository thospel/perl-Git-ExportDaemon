#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 01_syntax.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use FindBin;

BEGIN {
    $^W = 1;
    require lib;
    "lib"->import($FindBin::Bin);
};

use TestDrive qw($tmp_dir $bin_dir $base_dir slurp work_area);

use Test::More tests => 1;

sub check {
    open(my $olderr, ">&", "STDERR") || die "Can't dup STDERR: $!";
    open(STDERR, ">", "$tmp_dir/stderr") ||
        die "Can't open $tmp_dir/stderr: $!";
    # diag("$^X -c @_");
    my $rc = system($^X, "-c", @_);
    open(STDERR, ">&", $olderr)        || die "Can't dup old STDERR: $!";
    my $errors = slurp("$tmp_dir/stderr");
    $errors =~ s/.* syntax OK\n//;
    if ($errors ne "") {
        diag($errors);
        return 1;
    }
    return $rc;
}

work_area();
for my $script (qw(git-exportd)) {
    ok(!check("-I", "$base_dir/blib/lib", "-I", "$base_dir/blib/arch",
              "$bin_dir/$script"),
       "Can compile $bin_dir/$script");
}
