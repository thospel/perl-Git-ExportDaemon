package Git::ExportDaemon;

use strict;
use warnings;

our $VERSION = "1.000";

use FindBin qw($Script);
use Carp;
use Cwd;
use Errno qw(EINTR EAGAIN EWOULDBLOCK EEXIST ESTALE ENOENT EDOM EACCES);
use POSIX qw(F_GETFL F_SETFL O_NONBLOCK _exit);
use Fcntl qw
    (O_RDWR O_CREAT LOCK_EX LOCK_NB S_ISLNK S_ISDIR);
use Socket qw(SO_PEERCRED SOL_SOCKET);
use Sys::Syslog;
use IO::Socket::UNIX;

# use Data::Dumper;

my (%all_clients, %all_listeners);

use constant {
    LISTEN_FDS_START		=> 3,
    BLOCK			=> 2**12,
    DEV				=> 0,
    INO				=> 1,
    MODE			=> 2,
    UID				=> 4,
    GID				=> 5,
    MTIME			=> 9,
    HOME			=> 7,

    NAME_SOCKET			=> "S.git-exportd",

    CODE_SHUTDOWN		=> 101,
    CODE_INTERNAL_PROBLEM	=> 199,
    CODE_LIST			=> 211,
    CODE_HELP			=> 214,
    CODE_GREETING		=> 220,
    CODE_QUIT			=> 221,
    CODE_OK			=> 222,
    CODE_EXPORTED		=> 251,
    CODE_INVALID_USER		=> 501,
    CODE_UNKNOWN_COMMAND	=> 502,
    CODE_INVALID_PID		=> 503,
    # Wrong number of arguments
    CODE_WRONG_ARGUMENTS	=> 504,
    # Wrong arguments syntax
    CODE_INVALID_ARGUMENT	=> 505,
    CODE_UNKNOWN_REVISION	=> 506,
    CODE_GIT_ERROR		=> 507,
    CODE_INVALID_REPO		=> 508,
    CODE_PERMISSION_DENIED	=> 509,
    CODE_INTERNAL_ERROR		=> 599,
};

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw
    (CODE_QUIT CODE_WRONG_ARGUMENTS CODE_UNKNOWN_REVISION CODE_GIT_ERROR
     CODE_EXPORTED CODE_UNKNOWN_COMMAND CODE_INVALID_REPO CODE_HELP CODE_OK
     CODE_LIST CODE_PERMISSION_DENIED CODE_INVALID_ARGUMENT
     NAME_SOCKET DEV INO MODE UID GID S_ISLNK S_ISDIR
     client_git_export client_response_parse git_rev_parse git git_dir path_stat
     run_piped is_systemd mkdirs rmtree permtree cwd_path lock_file blocking
     dir_force dir_ro dir_rw report report_start escape unescape trust_check);

sub report_start {
    my $ident    = shift // $Script;
    my $logopt   = shift // "cons,pid";
    my $facility = shift // "user";

    openlog($ident, $logopt, $facility);
}

sub report {
    my $level = shift;
    my $msg = shift // croak "Assertion: No message argument to report";
    $msg = sprintf($msg, @_) if @_;
    $msg =~ s/\s+\z//;
    $msg ne "" || croak "Assertion: Empty report message";

    if (-t STDERR) {
        print STDERR "Log($level): $msg\n";
    } else {
        syslog($level, $msg);
    }
}

my $read_mask  = "";
my $write_mask = "";
my (%read_refs, %write_refs);

sub add_read($*$) {
    defined(my $fd = fileno($_[1])) || croak "Not a filehandle";
    croak "Descriptor $fd already selected for read" if $read_refs{$fd};
    $read_refs{$fd} = $_[2];
    vec($read_mask, $fd, 1) = 1;
}

sub add_write($*$) {
    defined(my $fd = fileno($_[1])) || croak "Not a filehandle";
    croak "Descriptor $fd already selected for write" if $write_refs{$fd};
    $write_refs{$fd} = $_[2];
    vec($write_mask, $fd, 1) = 1;
}

sub delete_read($*) {
    defined(my $fd = fileno($_[1])) || croak "Not a filehandle";
    croak "Descriptor $fd wasn't selected for read" unless $read_refs{$fd};
    # This strange assign before delete is to poison the reference @work in
    # sub loop may still have
    $read_refs{$fd} = undef;
    delete $read_refs{$fd};
    vec($read_mask, $fd, 1) = 0;
    $read_mask =~ s/\x00+\z//;
}

sub delete_write($*) {
    defined(my $fd = fileno($_[1])) || croak "Not a filehandle";
    croak "Descriptor $fd wasn't selected for write " unless $write_refs{$fd};
    # This strange assign before delete is to poison the reference @work in
    # sub loop may still have
    $write_refs{$fd} = undef;
    delete $write_refs{$fd};
    vec($write_mask, $fd, 1) = 0;
    $write_mask =~ s/\x00+\z//;
}

my (@loops, @alarms, @immediate, %check_signals, $work, $idle, $now);

sub run_idle {
    # ($idle = $idle->[NEXT])->[CODE]->();
    die "Not supported\n";
}

my ($signal_pipe, $signal_rd);
sub init {
    $SIG{PIPE} = undef;
    $signal_pipe = 0;
}

sub loop {
    until (@loops) {
        # return if $read_mask eq "" && $write_mask eq "";
        if (@alarms > 1 || @immediate || $work) {
            run_now();
            return shift @loops if @loops;
        }
        (select(my $r = $read_mask, my $w = $write_mask, undef,
                $work || $idle ? 0 :
                @alarms > 1 ? $alarms[1][0]-$now > 0 ? $alarms[1][0]-$now : 0 :
                %write_refs || keys %read_refs > $signal_pipe || %check_signals ? undef : last) ||
         ($idle && !$work && (@alarms <= 1 || $alarms[1][0] > $now) && run_idle(), next)) >=0 or $! == EINTR() ? next : die "Select failed: $! (", $!+0, ")";
        $$_ && $$_->() for
            \@read_refs{ grep vec($r, $_, 1), keys %read_refs},
            \@write_refs{grep vec($w, $_, 1), keys %write_refs};
    }
    return shift @loops;
}

sub readable {
    return keys(%read_refs)-$signal_pipe unless wantarray;
    my $fd = fileno($signal_rd) . "";
    return grep $_ ne $fd, keys %read_refs;
}

sub writable {
    return keys %write_refs;
}

sub blocking(*;$) {
    my $handle = shift;
    no warnings;
    if ($^O eq 'MSWin32' || $^O eq 'VMS') {
	# There seems to be no way to query the state
	return undef unless @_;

	# FIONBIO enables non-blocking sockets on windows and vms.
	# FIONBIO is (0x80000000|(4<<16)|(ord('f')<<8)|126),
	# as per winsock.h, ioctl.h
	my $fionbio = 0x8004667e;
	my $val = pack("L!", shift() ? 0 : 1);
	ioctl($handle, $fionbio, $val) || croak "Can't set ioctl flags: $!";
    } else {
	my $flags = fcntl($handle, F_GETFL, 0) ||
	    croak "Can't get fcntl flags: $!\n";
	return $flags & O_NONBLOCK() ? 0 : 1 unless @_;
	fcntl($handle, F_SETFL,
	      shift() ?
	      $flags & O_NONBLOCK() ? $flags & ~O_NONBLOCK : return :
	      $flags & O_NONBLOCK() ? return : $flags | O_NONBLOCK) or
	      croak "Can't set fcntl flags: $!";
    }
}

sub is_systemd {
    my $pid = $ENV{LISTEN_PID} || return;
    if ($pid ne $$) {
        report("warning", "Unexpected LISTEN_PID=$pid (expected $$)");
        return;
    }
    my $fds = $ENV{LISTEN_FDS} || return;
    if ($fds !~ /^[1-9][0-9]*\z/) {
        report("warning", "Unexpected LISTEN_FDS=$fds (expected a number)");
        return;
    }

    my @fh;
    for my $fd (LISTEN_FDS_START .. LISTEN_FDS_START + $fds - 1) {
        open(my $fh, "+>&=", $fd) || die "Could not fdopen($fd): $!";
        push @fh, $fh;
    }
    return @fh;
}

sub output {
    my $client = shift;
    my $code   = shift;
    my $text   = "@_";

    # Ensure exactly one final newline
    $text =~ s/\n*\z/\n/;
    # Prefix multiline codes
    $text =~ s/^/$code-/mg;
    # But fixup the final code
    $text =~ s/-(.*)$/ $1/;
    # Communication is purely local, so no need for portable newlines
    # $text =~ s/\n/\x0d\x0a/g;

    my $was_empty = $client->{buffer_out} eq "";
    $client->{buffer_out} .= $text;
    if ($was_empty && $client->{buffer_out} ne "") {
        $client->add_write($client->{handle}, sub { $client->can_write() });
    }
    $client->{did_respond} ||= $code >= 200;
}

# Only marks that we want to finish.
# It doesn't pull the rug out from under you.
# The real finish happens when your callback returns
sub finish {
    my ($client, $code, $reason, $response) = @_;
    $reason || croak("Assertion: No finish reason given");
    return if $client->{finishing};

    $response //=
        $code == CODE_INTERNAL_ERROR || $code == CODE_INTERNAL_PROBLEM ?
        "Internal error" : $reason;
    $client->output($code, $response);
    $client->{finishing} = $reason;
    $client->{buffer_in} = "";
}

sub shutdown {
    my ($class, $reason) = @_;

    for my $client (values %all_clients) {
        $client->finish(CODE_SHUTDOWN, $reason);
    }
    for my $listener (values %all_listeners) {
        $class->delete_read($listener);
    }
    %all_listeners = ();
}

sub quit {
    my ($client, $reason) = @_;

    # Don't bother with close. The handle will go out of scope
    $client->delete_read($client->{handle});
    $client->delete_write($client->{handle}) if $client->{buffer_out} ne "";
    delete $all_clients{$client->id};

    eval { $client->{callbacks}{on_quit}->($client, $reason) };
    if (my $err = $@) {
        $err =~ s/\s+\z//;
        $err = "on_quit callback died: $err";
        report("err", $err);
    }
}

sub can_read {
    my ($client) = @_;

    my $rc = sysread($client->{handle}, my $buffer, BLOCK);
    if ($rc) {
        return if $client->{finishing};
        while ($buffer ne "") {
            my $pos = index($buffer, "\n");
            last if $pos < 0;
            my $line = $client->{buffer_in} . substr($buffer, 0, $pos+1, "");
            $client->{buffer_in} = "";
            $line =~ s/\s+\z//;
            $client->{did_respond} = 0;
            eval { $client->{callbacks}{on_line}->($client, $line) };
            if (my $err = $@) {
                $err =~ s/\s+\z//;
                $err = "on_line callback died: $err";
                report("err", $err);
                $client->output($client->{did_respond} ? CODE_INTERNAL_PROBLEM : CODE_INTERNAL_ERROR, $err);
            }
            last if $client->{finishing};
        }
        $client->{buffer_in} .= $buffer;
        return;
    }
    if (defined $rc) {
        # EOF
        if ($client->{finishing}) {
            $client->quit("The expected EOF ($client->{finishing})");
        } else {
            $client->quit("Unexpected EOF");
        }
    } else {
        return if $! == EINTR || $! == EAGAIN || $! == EWOULDBLOCK;
        $client->quit("Read error: $!");
    }
}

sub can_write {
    my ($client) = @_;
    my $len = length $client->{buffer_out} ||
        die "Assertion: Writable on length 0 output buffer";
    $len = BLOCK if $len > BLOCK;
    my $rc = syswrite($client->{handle}, $client->{buffer_out}, BLOCK);
    if ($rc) {
        substr($client->{buffer_out}, 0, $rc) = "";
        if ($client->{buffer_out} eq "") {
            $client->delete_write($client->{handle});
            $client->quit($client->{finishing}) if $client->{finishing};
        }
        return;
    }
    die "Unexpected size 0 write" if defined $rc;
    return if $! == EINTR || $! == EAGAIN || $! == EWOULDBLOCK;
    $client->quit("Write error: $!");
}

sub nop {
    # report("debug", "Nop @_");
}

sub id {
    return shift->{id};
}

sub pid {
    return shift->{pid};
}

sub uid {
    return shift->{uid};
}

sub user {
    my $uid = shift->{uid};
    return getpwuid($uid) // "$uid";
}

sub gid {
    return shift->{gid};
}

sub is_manager {
    my $uid = shift->uid;
    return $uid == $> || $uid == 0;
}

sub group {
    my $gid = shift->{gid};
    return getgrgid($gid) // "$gid";
}

my $client_id = "0";
sub acceptable {
    my ($class, $listen, $callbacks) = @_;
    my $addr = accept(my $fh, $listen);
    if (!$addr) {
        report("warning", "Could not accept incoming connection: $!");
        return;
    }
    blocking($fh, 0);
    my $packed = getsockopt($fh, SOL_SOCKET, SO_PEERCRED) ||
        croak "Could not get peer credentials: $!";
    my ($pid, $uid, $gid) = unpack("III", $packed);
    my $client = bless {
        id       => $client_id++,
        pid	 => $pid,
        uid	 => $uid,
        gid	 => $gid,
        buffer_in => "",
        buffer_out => "",
        handle	 => $fh,
        callbacks => $callbacks,
    }, $class;
    $all_clients{$client->id} = $client;
    $class->add_read($fh, sub { $client->can_read() });
    if ($uid != $> && $> != 0) {
        my $me = getpwuid($>) || "$>";
        my $user = $client->user;
        $client->finish(CODE_INVALID_USER,
                        "User '$user' connected to server '$me'",
                        "$Script only provides services to user '$me', but you are user '$user'");
    } elsif ($pid <= 1) {
        $client->finish(CODE_INVALID_PID, "Invalid pid '$pid'");
    } elsif (!kill(0, $pid)) {
        # This should be (almost) impossible
        # (can happen if the process died since making the connect)
        $client->finish(CODE_INVALID_PID, "Undetectable pid '$pid'");
    } else {
        $client->output(CODE_GREETING, "$Script ready")
    }

    eval { $client->{callbacks}{on_accept}->($client) };
    if (my $err = $@) {
        $err =~ s/\s+\z//;
        $err = "on_accept callback died: $err";
        report("err", $err);
        $client->finish(CODE_INTERNAL_ERROR, $err);
    }

    $client->quit($client->{finishing}) if
        $client->{finishing} && $client->{buffer_out} eq "";
}

sub listener {
    my ($class, $fh, %callbacks) = @_;

    -S $fh || croak "Handle is not a socket";

    my $callbacks = {
        on_quit   => delete $callbacks{on_quit}   || \&nop,
        on_line   => delete $callbacks{on_line}   || \&nop,
        on_accept => delete $callbacks{on_accept} || \&nop,
    };
    croak "Unknown callback:", join(", ", keys %callbacks) if %callbacks;

    my $fd = fileno($fh) // croak "Passed handle has no file descriptor";

    blocking($fh, 0);
    $class->add_read($fh, sub { $class->acceptable($fh, $callbacks) });
    $all_listeners{$fd} = $fh;
}

# Return full path WITHOUT normalizing
sub cwd_path {
    my ($path) = @_;

    return $path if $path =~ m{^/};

    my $cwd = getcwd() // die "Could not get current working directory: $!";
    $cwd =~ s{/*\z}{/$path};
    return $cwd;
}

# Try to lock the given file. Already locked is not fatal if $may_block
# $may_block negative means blocking lock
# Returns filehandle if locked, false if not, dies on error
# File will remain locked as long as the filehandle lives
sub lock_file {
    my $file = shift;
    my %params = @_ == 1 ? (may_block => shift) : @_;

    my $may_block = delete $params{may_block};

    croak("Unknown lock_file parameter ",
          join(", ", map "'$_'", keys %params)) if %params;

    sysopen(my $fh, $file, O_RDWR|O_CREAT) ||
        croak "Could not create/open $file: $!";
    if (!flock($fh, LOCK_EX | ($may_block && $may_block < 0 ? 0 : LOCK_NB))) {
        die "Could not flock '$file': $!" if
            ($may_block && $may_block < 0) ||
            !($! == EWOULDBLOCK || ($^O eq "MSWin32" ? $! == EDOM : $! == EACCES));
        return undef if $may_block;
        if (defined(my $line = <$fh>)) {
            if (my ($pid, $program) =
                    $line =~ /^(\d+)\s+(.*)$/) {
                croak "Could not flock '$file': already locked, possibly by program '$program' (pid $pid)";
            }
        }
        croak "Could not flock '$file' (already locked)";
    }
    seek($fh, 0, 0)  || die "Could not seek to 0 in '$file': $!";
    truncate($fh, 0) || die "Could not truncate '$file': $!";
    my $old_fh = select($fh);
    $| = 1;
    # The lock file contents are just advisory
    print("$$ $Script\n") || die "Could not write to '$file': $!\n";
    select($old_fh);
    return $fh;
}

sub mkdirs {
    my ($dirs) = @_;

    my @dirs = split m{/+}, $dirs;
    # Restore absolute
    if ($dirs[0] eq "") {
        if (@dirs == 1) {
            @dirs = "/";
        } else {
            shift @dirs;
            $dirs[0] = "/$dirs[0]";
        }
    }
    my $target = "";
    for my $dir (@dirs) {
        $target .= "$dir/";
        if (!mkdir($target)) {
            $! == EEXIST || croak "Could not mkdir($target): $!";
            -d $target || croak "'$target' exists but is not a directory";
        }
    }
}

# Force a directory with given mode to exist (but assume the parent exists)
sub dir_force {
    my ($dir, $mode) = @_;

    if (!mkdir($dir, 0700)) {
        $! == EEXIST || die "Could not mkdir($dir): $!";
        -d $dir || die "Path '$dir' exists but is not a directory";
        chmod(0700, $dir) || die "Could not chmod($dir): $!";
    }
}

sub _trust_check {
    my ($path, $trust_cache) = @_;
print STDERR "trust $path\n";

    $path =~ m{^/} ||
        croak "Assertion: _trust_check argument '$path' must be absolute";
    $path =~ m{^//(?:[^/]|\z)} &&
        die "Paths starting with // are not supported\n";
    $path =~ /\0/ && die "Path contains \\0\n";
    # Make sure path ends on /
    $path .= "/";
    # Collapse multiple /
    $path =~ tr{/}{}s;
    # . path component does nothing
    1 while $path =~ s{/\./}{/}g;
    # Remove leading / for processing
    $path =~ s{^/}{};

    # nominal will never end on /, real always will
    # This is because we want to do a (l)stat on nominal which should not follow
    # symlinks on the final component
    my $nominal = "";
    my $real    = "/";

    while ($path =~ s{^([^/]+)/}{}) {
        my $name = $1;
        my $nominal_old = $nominal;
        $nominal .= "/$name";
        if (exists $trust_cache->{$nominal}) {
            $real = $trust_cache->{$nominal} // die "Path lookup loop\n";
            next;
        }
        if ($name eq "..") {
            # .. on / will reamin /
            $real =~ s{[^/]+/}{};
        } else {
            my @lstat = lstat($nominal) or die "Could not lstat($nominal): $!";
            if (-d _) {
                my $mode = $lstat[MODE] & 07777;
                ($mode & 02)  == 0 || die "'$nominal' is world writable\n";
                ($mode & 020) == 0 || $lstat[GID] == 0 ||
                    die "'$nominal' is group writable by someone other than root/wheel\n";
                ($mode & 0200) == 0 || $lstat[UID] == 0 || $lstat[UID] == $> ||
                    die "'$nominal' is user writable by someone other than root or me\n";
                $real .= "$name/";
            } elsif (-l _) {
                # Permissions on symlinks are irrelevant
                my $link = readlink($nominal) //
                    croak "Could not readlink($nominal): $!";
                $trust_cache->{$nominal} = undef;
                if ($link =~ m{^/}) {
                    # Absolute path
                    $real = _trust_check($link);
                } else {
                    $real = _trust_check("$nominal_old/$link");
                }
            } else {
                die "Path '$nominal' is not a directory or symlink\n";
            }
        }
        $trust_cache->{$nominal} = $real;
    }
    $path eq "" || croak "Assertion: Path left is not empty: '$path'";
    return $real;
}

sub trust_check {
    my ($path) = @_;

    # Sanity check on /
    my @lstat = lstat("/") or croak "Assertion: Cannot lstat(/): $!";
    -d _ || croak "Assertion: / is not a directory";
    my $mode = $lstat[MODE] & 07777;
    ($mode & 02)  == 0 || die "/ is world writable\n";
    ($mode & 020) == 0 || $lstat[GID] == 0 ||
        die "/ is group writable by someone other than root/wheel\n";
    ($mode & 0200) == 0 || $lstat[UID] == 0 ||
        die "/ is user writable by someone other than root\n";

    $path = cwd_path($path);
    return _trust_check($path, {});
}

# You *MUST* trust all levels leading to path or this can be used to remove
# arbitrary paths. However no trust of path and what it contains is needed
# git-exportd indeed checks that the path upto BASE is trusted (see trust_check)
sub rmtree {
    my ($path, %params) = @_;

    if (!$params{silent}) {
        report("info", "removing $path");
        $params{silent} = 1;
    }

    # lstat so we don't follow symlinks
    my @lstat = lstat($path) or do {
        return if $! == ENOENT || $! == ESTALE;
        die "Could not lstat($path): $!";
    };
    my $mode = $lstat[MODE] & 07777;
    if (-d _) {
        if ($>) {
            # Directory must be writable to be able to remove things from it
            # Directory must be executable to access it
            # Directory must be readable to list it
            # Also avoid changes by other (rmtree remains racy though)
            my $mode_new = ($mode | 0700) & ~ 07022;
            $mode == $mode_new || chmod($mode_new, $path) ||
                die "Could not chmod($path): $!";
        }
        my $top_keep = delete $params{top_keep};
        opendir(my $dh, $path) || die "Could not opendir($path): $!";
        for my $f (readdir $dh) {
            next if $f eq "." || $f eq "..";

            if ($lstat[UID] != $> || $lstat[GID] != $)) {
                $params{untrusted_dir} ||
                    croak "Will not remove directory '$path/$f' (untrusted containing directory)";
                $params{untrusted_dir}->("$path/$f");
            } else {
                rmtree("$path/$f", %params);
            }
        }
        $top_keep || rmdir($path) || $! == ENOENT || $! == ESTALE ||
            die "Could not rmdir($path): $!";
    } else {
        unlink($path) || $! == ENOENT || $! == ESTALE ||
            die "Could not unlink '$path': $!";
    }
}

sub permtree {
    my ($path, $allow, %params) = @_;

    $> || croak "Refuse to run permtree as root";

    # lstat so we don't follow symlinks
    my @lstat = lstat($path) or do {
        return if $! == ENOENT || $! == ESTALE;
        die "Could not lstat($path): $!";
    };
    my $mode = $lstat[MODE] & 07777;
    if (-d _) {
        # Remove group and other write, add user read/write/execute
        my $mode_new = $mode & ~ 07022 | 0700;
        if ($mode_new != $mode) {
            chmod($mode_new, $path) || die "Could not chmod($path): $!";
            $mode = $mode_new;
        }
        my $top_keep = delete $params{top_keep};
        opendir(my $dh, $path) || die "Could not opendir($path): $!";
        for my $f (readdir $dh) {
            next if $f eq "." || $f eq "..";
            permtree("$path/$f", $allow, %params);
        }
        # If you make the top level directory read-only you cannot
        # move it to another directory since that needs permission to update ..
        return if $top_keep;
    }
    my $mode_new = $mode & $allow;
    $mode == $mode_new || S_ISLNK($lstat[MODE]) ||
        chmod($mode_new, $path) || die "Could not chmod($path): $!";
}

# Remove group and other write, Add user read, write, execute
# (Directory must be writable in order to move it)
sub dir_rw {
    my ($path, $allow) = @_;

    my @lstat = lstat($path) or do {
        next if $! == ESTALE || $! == ENOENT;
        die "Could not lstat($path): $!";
    };
    -d _ || return 0;
    my $mode = $lstat[MODE] & 07777;
    my $mode_new = ($mode | 0700) & ($allow // ~ 07022);
    $mode == $mode_new || chmod($mode_new, $path) ||
        die "Could not chmod($path): $!";
    return 1;
}

# Remove all write, add user read and execute
sub dir_ro {
    my ($path, $allow) = @_;

    $> || croak "Refuse to run dir_ro as root";

    my @lstat = lstat($path) or do {
        next if $! == ESTALE || $! == ENOENT;
        die "Could not lstat($path): $!";
    };
    -d _ || return 0;
    my $mode = $lstat[MODE] & 07777;
    my $mode_new = ($mode | 0500) & ($allow // ~ 07222);
    $mode == $mode_new || chmod($mode_new, $path) ||
        die "Could not chmod($path): $!";
    return 1;
}

sub path_expand {
    my ($client, $path) = @_;

    if (my ($user, $rest) = $path =~ m{^~([^/]*)(.*)\z}s) {
        if (my @info = $1 eq "" ? getpwuid($client->uid) : getpwnam($user)) {
            return $info[HOME] . $rest if $info[HOME] =~ m{^/};
        }
    }
    return cwd_path($path);
}

sub escape {
    my ($str) = @_;
    for ($str) {
        # utf8::encode($_);
        s{([%\s])}{sprintf("%%%02X", ord($1))}eg;
    }
    return $str;
}

sub unescape {
    my ($str) = @_;

    for ($str) {
        s{%([0-9a-f]{2})}{chr hex $1}eg;
        # utf8::decode($_);
    }
    return $str;
}

sub set_uidgid {
    my ($uid, $gid) = @_;

    if (defined $uid) {
        if (my @user_props = getpwuid($uid)) {
            $ENV{HOME}    = $user_props[7];
            $ENV{SHELL}   = $user_props[8];
            $ENV{LOGNAME} = $ENV{USER} = $user_props[0];
        } else {
            delete @ENV{qw(HOME LOGNAME USER)};
            $ENV{SHELL} = "/bin/sh";
        }
    }

    # Assign real first, effective second
    $) = $( = $gid if defined $gid;
    $> = $< = $uid if defined $uid;
    # The saved uid/gid may not be set, but we'll do an exec() immediately
    # afterward and that will copy from the effective uid

    # Check
    !defined $gid || $) == $gid && $( == $gid || die "Could not set gid";
    !defined $uid || $> == $uid && $< == $uid || die "Could not set uid";
}

sub run_piped {
    my ($in, @pids);

    for my $do (@_) {
        my ($args, $dir, $umask, $uid, $gid) =
            @$do{qw(command dir umask uid gid)};
        my $command = shift @$args || croak "No command";
        pipe(my $rd, my $wr) || die "Could not pipe(): $!\n";
        my $pid = fork() // die "Could not fork: $!\n";
        if ($pid == 0) {
            eval {
                $SIG{PIPE} = "DEFAULT";
                close($rd);
                if ($in) {
                    open(STDIN, "<&", $in) || die "Could not dup to STDIN: $!";
                    close($in);
                }
                open(STDOUT, ">&", $wr) || die "Could not dup to STDOUT: $!";
                close($wr);
                umask($umask) if defined $umask;
                set_uidgid($uid, $gid);
                if ($command eq "\0stat") {
                    defined $dir || die "No directory argument\n";
                    select(STDOUT);
                    $| = 1;
                    if (my @stat = stat($dir)) {
                        print "0 @stat\n";
                    } else {
                        print $!+0, "\n";
                    }
                    _exit(0);
                } else {
                    !defined $dir || chdir($dir) || die "Could not chdir($dir): $!";
                    exec($command, @$args) || die "Could not exec $command: $!";
            }
            };
            my $err = $@;
            $err =~ s/\s+\z//;
            eval { report("err", "Child $command: $err") };
            _exit(1);
        }
        push @pids, $pid;
        $in = $rd;
    }
    my $out = do { local $/; <$in> };
    # close($in);
    my $fail;
    for my $pid (@pids) {
        my $p = waitpid($pid, 0);
        $p == $pid || die "Assertion: Dude, where's my pid: $!";
        $fail ||= 1 if $?;
    }
    return undef if $fail;
    return $out;
}

sub run {
    return run_piped({@_});
}

sub git_rev_parse {
    my ($repo, $commit, $uid, $gid) = @_;

    my $out = run(command => ["git", "rev-parse", $commit],
                  dir => $repo,
                  uid => $uid,
                  gid => $gid) // return undef;
    $out =~ s/\s+\z//;
    $out =~ /^([0-9a-f]{40})\z/ || die "Unexpected rev-parse output '$out'";
    return $1;
}

sub git_dir {
    my ($repo, $uid, $gid) = @_;

    my $out = run(command => ["git", "rev-parse", "--git-dir"],
                  dir => $repo,
                  uid => $uid,
                  gid => $gid) // return undef;
    $out =~ s/\n\z//  || die "Unexpected rev-parse output '$out'";
    $out =~ /^(.+)\z/ || die "Unexpected rev-parse output '$out'";
    return $1;
}

sub path_stat {
    my ($path, $uid, $gid) = @_;

    my $out = run(command => ["\0stat"],
                  dir => $path,
                  uid => $uid,
                  gid => $gid) // return undef;
    $out =~ /^((?:\d+)(?:\s+\d+)*)\n\z/ ||
        croak "Assertion: Unexpected stat output '$out'";
    my ($err, @stat) = split " ", $out;
    # Convert back to dualvar
    $err = $! = $err;
    return $err, \@stat;
}

sub client_response_parse {
    my ($fh) = @_;

    my $response = "";
    my $code;
    local $_;
    while (1) {
        $_ = <$fh>;
        defined || die "Git-ExportDaemon closed the connection\n";
        s/\s+\z//;
        s/^([0-9]{3})([- ])// ||
            die "Invalid response from Git-ExportDaemon: $_\n";
        $code //= $1;
        $code eq $1 || die "Inconsistent response code from Git-ExportDaemon\n";
        $response .= "$_\n";
        last if $2 eq " ";
    }
    $response =~ s/\s+\z//;
    return $code, $response;
}

sub client_git_export {
    my ($repo, %params) = @_;

    $repo // croak "Assertion: No repository argument";
    $repo = escape(cwd_path($repo));
    my $socket =
        delete $params{socket} //
        ($ENV{XDG_RUNTIME_DIR} || "/run/user/$>") . "/Git-ExportDaemon/" . NAME_SOCKET;
    my $commit    = escape(delete $params{commit} // "HEAD");
    my $quit      = delete $params{quit} // 1;
    my $quit_wait = delete $params{quit_wait};

    my $fh = IO::Socket::UNIX->new(Peer => $socket) ||
        die "Could not connect to '$socket': $!";
    my ($code, $response) = client_response_parse($fh);
    $code == CODE_GREETING ||
        die "Unexpected greeting from Git-ExportDaemon: $code $response\n";
    print($fh "export $repo $commit\n") ||
        die "Error writing to Git-ExportDaemon: $!\n";
    ($code, $response) = client_response_parse($fh);
    $code == CODE_EXPORTED ||
        die "Unexpected export response from Git-ExportDaemon: $code $response\n";
    !$quit || print($fh "quit\n") ||
        die "Error writing to Git-ExportDaemon: $!\n";
    my ($uid, $revision, $path) = $response =~ /^([1-9][0-9]*|0)\s+([0-9a-f]{40})\s+(\S+)\z/ or
        die "Could not parse export response from Git-ExportDaemon: $response\n";
    if ($quit && $quit_wait) {
        ($code, $response) = client_response_parse($fh);
        $code == CODE_QUIT ||
            die "Unexpected quit response from Git-ExportDaemon: $code $response\n";
    }
    close($fh);
    return $uid, $revision, unescape($path);
}

1;
