package TestDrive;
# $Id: TestDrive.pm 5091 2012-05-15 15:09:26Z hospelt $
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
use FindBin qw($Bin $Script);
use Errno qw(ENOENT ESTALE);
use File::Spec;
use File::Temp qw(tempdir);
use File::Path qw(rmtree mkpath);
use File::Copy;
use Getopt::Long;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK =
    qw(ENOENT ESTALE
       $tmp_dir $t_dir $base_dir $bin_dir $me $cover $tar $zip $compress
       slurp spew rmtree mkpath cpr work_area perl_run diff);

# Allows executing programs under taint checking
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
# Let's hope tar and gzip are in this path
$ENV{PATH} = "/usr/local/bin:/usr/bin:/bin";

$Bin =~ s{/\z}{};
if ($^O eq "MSWin32") {
    tr{\\}{/} for $Bin, $^X;
}

$Bin =~ ($^O eq "MSWin32" ?
         qr{^(((?:[A-Z]:)?(?:/[a-zA-Z0-9_:.~ -]+)*)/[a-zA-Z0-9_.-]+)/*\z} :
         qr{^(((?:/[a-zA-Z0-9_:.-]+)*)/[a-zA-Z0-9_.-]+)/*\z}) ||
    croak "Could not parse bin directory '$Bin'";
# Use untainted version lib
$Bin = $1;		## no critic (UselessNoCritic CaptureWithoutTest)
our $base_dir = $2;	## no critic (UselessNoCritic CaptureWithoutTest)

our $t_dir = $Bin;
my $t_option_file = "$t_dir/options.$^O";
our $bin_dir = "$base_dir/bin";

our $me;
if ($^O eq "MSWin32") {
    require File::Spec;
    require Win32;
    $me = Win32::LoginName();
} else {
    if (my $user = $ENV{LOGNAME}) {
        if (defined(my $uid = getpwnam($user))) {
            $me = $user if $> == $uid;
        }
    }
    $me ||= getpwuid $>;
}
die "Can't determine who I am" if !$me;
# We can basically trust $me since it came from a real system request
# Still, let's filter some weird characters
die "Unacceptable userid '$me'" if $me eq "." || $me eq "..";
$me =~ /^([0-9A-Za-z_.-]+)\z/ || die "Weird characters in userid '$me'";
# Seems ok. Untaint
$me = $1;	## no critic (UselessNoCritic CaptureWithoutTest)

# State globals
our ($cover, $tmp_dir, $tar, $zip, $compress);
our $bsd_tar	= 'bsdtar';
our $gnuwin_zip	= 'zip';

my ($keep, $leave, $strace);

sub executable {
    my ($name) = @_;
    return -x $name ? $name : undef if
        File::Spec->file_name_is_absolute($name);
    my ($volume,$directories,$file) = File::Spec->splitpath($name);
    return -x $name ? $name : undef if $volume ne "" || $directories ne "";
    for my $dir (File::Spec->path()) {
        my $try = File::Spec->catfile($dir, $tar);
        return -x $try ? $try : undef if -e $try;
    }
    return undef;
}

{
    no warnings 'recursion';
    my (@lcs_cache, @old, @new);

    # Simple recursive memoized longest common subsequence
    # This code is a bit silly. It walks the diagonal as long as the ends are
    # the same. But as soon as they differ it will suddenly fill the whole
    # remaining square. Better would be to eleminate the common start and end
    # and then fill the complete square non-recursively
    sub lcs_length {
        my ($old_l, $new_l) = @_;
        return 1 if !$old_l-- || !$new_l--;
        return 1+($lcs_cache[$old_l]{$new_l} ||= lcs_length($old_l, $new_l)) if
            $old[$old_l] eq $new[$new_l];
        my $len1 =$lcs_cache[$old_l]{$new_l+1} ||= lcs_length($old_l, $new_l+1);
        my $len2 =$lcs_cache[$old_l+1]{$new_l} ||= lcs_length($old_l+1, $new_l);
        return $len1 > $len2 ? $len1 : $len2;
    }

    sub diff {
        my $got    = shift;
        my $expect = shift;
        goto &Test::More::pass if
            defined $expect && defined $got && $expect eq $got ||
            !defined $expect && !defined $got;

        @old = $got    =~ /(.*\n|.+)/g;
        @new = $expect =~ /(.*\n|.+)/g;
        my $old_l = @old;
        my $new_l = @new;
        # Flush cache
        @lcs_cache = ();
        lcs_length($old_l, $new_l);
        # Walk the cache to recover the actual LCS
        my (@old_lcs, @new_lcs);
        while ($old_l-- && $new_l--) {
            if ($old[$old_l] eq $new[$new_l]) {
                push @old_lcs, $old_l;
                push @new_lcs, $new_l;
            } elsif ($lcs_cache[$old_l]{$new_l+1} > $lcs_cache[$old_l+1]{$new_l}) {
                $new_l++;
            } else {
                $old_l++;
            }
        }
        # Finally output
        $old_l = $new_l = 0;
        my $str = "";
        while (@old_lcs) {
            my $ol = pop @old_lcs;
            for my $i ($old_l..$ol-1) {
                $str .= "- $old[$i]";
            }
            my $nl = pop @new_lcs;
            for my $i ($new_l..$nl-1) {
                $str .= "+ $new[$i]";
            }
            $str .= "  $new[$nl]";
            $old_l = $ol+1;
            $new_l = $nl+1;
        }
        for my $i ($old_l..$#old) {
            $str .= "- $old[$i]";
        }
        for my $i ($new_l..$#new) {
            $str .= "+ $new[$i]";
        }
        $str =~ s{(\A|(?:^ .*\n){2})(?:^ .*\n)+(\z|(?:^ .*\n){2})}{$1...\n$2}mg;
        $str = "\n--- got\n+++ expected\n$str";
        $str =~ s/\n\z//;
        Test::More::diag("$str");

        goto &Test::More::fail;
    }
}

# Import a complete file and return the contents as a single string
sub slurp {
    my $file = shift;
    my ($maybe_gone, $binmode);
    if (@_) {
        if (@_ == 1) {
            $maybe_gone = shift;
        } else {
            my %params = @_;
            $maybe_gone = delete $params{maybe_gone};
            $binmode	= delete $params{binmode};
            croak "Unknown parameter ", join(", ", map "'$_'", keys %params) if
                %params;
        }
    }
    croak "filename is undefined" if !defined $file;
    open(my $fh, "<", $file) or
        $maybe_gone && ($! == ENOENT || $! == ESTALE) ?
	return undef : croak "Could not open '$file': $!";
    binmode($fh) if $binmode;
    my $rc = read($fh, my $slurp, -s $fh);
    croak "File '$file' is still growing" if $rc &&= read($fh, my $more, 1);
    croak "Error reading from '$file': $!" if !defined $rc;
    close($fh) || croak "Error while closing '$file': $!";
    return $slurp;
}

# Write remaining arguments to the file named in the first argument
# File is deleted on failure
sub spew {
    my $file = shift;
    croak "filename is undefined" if !defined $file;
    defined || croak "undef value" for @_;

    my $fsync = 0;
    my $binmode = 0;
    if (ref $_[0]) {
        ref $_[0] eq "HASH" || croak "Invalid spew parameters";
        my %params = %{+shift};

        $fsync = delete $params{fsync} if exists $params{fsync};
        $binmode = delete $params{binmode};
        croak "Unknown parameter ", join(", ", map "'$_'", keys %params) if
            %params;

    }
    open(my $fh, ">", $file) || croak "Could not create '$file': $!";
    binmode $fh if $binmode;
    eval {
        print($fh @_)	|| croak "Error writing to '$file': $!";
        $fh->flush	|| croak "Error flushing '$file': $!";
        $^O eq "MSWin32" || $fh->sync || croak "Error syncing '$file': $!" if
            $fsync;
        close($fh)	|| croak "Error closing '$file': $!";
    };
    if ($@) {
        undef $fh;
        unlink($file) || die "Could not unlink '$file' after $@";
        die $@;
    }
}

sub cpr {
    my ($from_dir, $to_dir, $dir) = @_;
    my $fd = "$from_dir/$dir";
    my $td = "$to_dir/$dir";
    if (!mkdir($td)) {
        my $err = $!;
        die "Could not mkdir($td): $err" if !-d $td;
    }
    opendir(my $dh, $fd) || die "Could not opendir '$fd': $!";
    my @files = sort readdir $dh;
    closedir($dh) || die "Error closing '$fd': $!";
    for my $f (@files) {
        next if $f eq "." || $f eq "..";
        my $file = "$fd/$f";
        lstat($file) || die "Could not lstat '$file': $!";
        if (-d _) {
            cpr($fd, $td, $f);
        } elsif (-f _) {
            File::Copy::copy($file, "$td/$f") ||
                die "Could not copy '$file' to '$td/$f': $!";
        } else {
            die "Unhandled filetype for '$file'";
        }
    }
}

sub options() {
    open(my $fh, "<", $t_option_file) ||
        die "Could not open '$t_option_file': $!";
    local $_;
    my %options;
    while (<$fh>) {
        /^\s*(\w+)\s*=\s*(.*\S)\s*\z/ ||
            die "Could not parse line $. in '$t_option_file'";
        $options{$1} = $2;
    }
    return \%options;
}

sub option($ ) {
    my ($name) = @_;
    my $options = options();
    defined $options->{$name} || croak "Unknown option $name";
    return $options->{$name};
}

sub work_area(%) {
    my (%params) = @_;

    my $copy = delete $params{copy};
    my $programs = delete $params{programs};

    croak "Unknown parameter ", join(", ", keys %params) if %params;

    local @::ARGV = @::ARGV;
    $keep	= option("KEEP");
    $strace	= option("STRACE");
    # $cover	= option("COVER");
    croak "Could not parse your command line.\n" unless
        GetOptions("leave!"		=> \$leave,
                   "keep!"		=> \$keep,
                   "cover!"		=> \$cover,
                   "strace!"		=> \$strace,
                   "help!"		=> \my $help,
                   );
    if ($help) {
        ## no critic (InputOutput::RequireCheckedSyscalls)
        print STDERR "Usage: $0 [--leave] [--keep] [--cover] [--strace] [--help]\n";
        exit 0;
    }

    if ($strace) {
        $strace =
            $^O eq "linux" ? "strace" :
            # hp: tusc
            # solaris: truss
            croak "No strace on $^O";
        $keep = 1 if !$leave;
    }
    $cover = $INC{"Devel/Cover.pm"} if !defined $cover;
    #if ($cover) {
    #    # $keep = 1;
    #    $TIMEOUT   *= 6;
    #    $AUTO_QUIT *= 6;
    #}

    my $tmp;
    if ($keep) {
        $Script =~ /^([\w-]+\.t\z)/ || die "Weird script name '$Script'";
        $keep = $1;
        # $leave = 1;
        File::Spec->catfile(File::Spec->tmpdir(), $me, "PackageTools", $keep) =~ /(.*)/s;
        $tmp = $1;
        rmtree($tmp);
        mkpath($tmp);
    } else {
        $tmp = tempdir($leave ? () : (CLEANUP => 1));
    }
    # Bring into unix form
    $tmp =~ tr{\\}{/} if $^O eq "MSWin32";

    if ($copy) {
        my $from = $copy;
        $from =~ s{/([^/]+)\z}{} || die "Cannot get dir from '$from'";
        my $dir = $1;
        cpr($from, $tmp, $dir);
    }

    if ($programs) {
        my $makefile = slurp("$base_dir/Makefile");
        ($tar) = $makefile =~ /^TAR =\s*(.*\S)\s*\n/m or
            croak "Could not get TAR from $base_dir/Makefile";
        $tar = $bsd_tar if !executable($tar);
        ($zip) = $makefile =~ /^ZIP =\s*(.*\S)\s*\n/m or
            croak "Could not get ZIP from $base_dir/Makefile";
        $zip = $gnuwin_zip unless executable($zip);
        ($compress) = $makefile =~ /^COMPRESS =\s*(.*\S)\s*\n/m or
            croak "Could not get COMPRESS from $base_dir/Makefile";
    }
    # Run is the directory for private test stuff
    mkdir ("$tmp/run") || die "Could not mkdir '$tmp/run': $!";
    $tmp_dir = $tmp;
}

sub perl_run {
    $tmp_dir || croak "Assertion: No work_area";
    open(my $old_err, ">&", "STDERR") || die "Can't dup STDERR: $!";
    open(STDERR, ">", "$tmp_dir/run/stderr") ||
        die "Could not open '$tmp_dir/run/stderr' for writing: $!";
    my $program = shift;
    # Untaint $^X
    $^X =~ ($^O eq "MSWin32" ?
             qr{^((?:[A-Z]:)?(?:/[a-zA-Z0-9_:.~ -]+)*/[a-zA-Z0-9_.-]+)\z} :
             qr{^((?:/[a-zA-Z0-9_:.-]+)*/[a-zA-Z0-9_.-]+)\z}) ||
             croak "Could not parse perl executable '$^X'";
    # No --blib since we always run the scripts from the blib directory already
    my @run = ($1, $cover ? "-MDevel::Cover" : (), $program, @_);
    # Test::More::diag("run: @run");
    my $ec = eval { system(@run) };
    my $die = $@;	# Taint failure is the only way
    open(STDERR, ">&", $old_err) || die "Can't dup old STDERR: $!";
    if ($die) {
        require Scalar::Util;
        for my $r (@run) {
            Test::More::diag("tainted $r: " .
                             (Scalar::Util::tainted($r) ? 1 : 0));
        }
        die $die;
    }
    my $err = slurp("$tmp_dir/run/stderr");
    if ($ec) {
        $err =~ s/\s+\z//;
        Test::More::fail("Unexpected exit $ec code from '@run': $err");
        exit 1;
    }
    return $err;
}

1;
