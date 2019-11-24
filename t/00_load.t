#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 00_load.t'
#########################
# $Id: 00_load.t 4842 2011-11-28 17:31:33Z hospelt $
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Test::More tests => 7;
for my $module (qw(Git::ExportDaemon::Package)) {
    use_ok($module) || BAIL_OUT("Cannot even use $module");
}
my $released = Git::ExportDaemon::Package->release_time;
like($released, qr{^[0-9]+\z}, "release_time is a number");
is(Git::ExportDaemon::Package->release_time, $released,
   "Still the same release time");
is(Git::ExportDaemon::Package::released("Git::ExportDaemon::Package", "1.000"),
   "1.000", "Module released");
eval { Git::ExportDaemon::Package::released("Mumble", "1.000") };
like($@, qr{^Could not find a history for package 'Mumble' at },
     "Expected module not found");
eval { Git::ExportDaemon::Package::released("Git::ExportDaemon/Package", "9999") };
like($@,
     qr{^No known version '9999' of package 'Git::ExportDaemon/Package' at },
     "Expected version not found");
# The fact that this makes cond coverage 100% must be a Devel::Cover bug
eval { Git::ExportDaemon::Package::released("OogieBoogie", "1.000") };
like($@,
     qr{^Could not find a history for package 'OogieBoogie' at },
     "No history for unknown modules");
