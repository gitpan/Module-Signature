#!perl

use strict;
use Test::More;
use IPC::Run qw(run);
plan tests => 4;

$|=1;
for my $tdir (glob("t/test-dat*")) {
    chdir $tdir or die;
    my @system = ($^X, "-I../../lib/", "../../script/cpansign", "-v");
    my($in,$out,$err);
    run \@system, \$in, \$out, \$err;
    close $out;
    my $diff = join "\n", grep /^.SHA1/, split /\n/, $out;
    ok(0==$?) or diag "dir[$tdir]system[@system]diff[$diff]";
    chdir "../../" or die;
}
