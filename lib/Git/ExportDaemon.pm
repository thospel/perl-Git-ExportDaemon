package Git::ExportDaemon;

use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
use Errno qw(EINTR EAGAIN EWOULDBLOCK EEXIST ESTALE ENOENT);
use Sys::Syslog;
use FindBin qw($Script);
use POSIX qw(F_GETFL F_SETFL O_NONBLOCK _exit);
use Socket qw(SO_PEERCRED SOL_SOCKET);

# use Data::Dumper;

my (%all_clients, %all_listeners);

openlog($Script, 'cons,pid', 'user');

use constant {
    LISTEN_FDS_START	=> 3,
    BLOCK		=> 2**12,
    DEV			=> 0,
    INO			=> 1,
    MTIME		=> 9,
};

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(is_systemd report blocking mkdirs rmtree escape unescape
                    rev_parse ls_remote run_piped DEV INO);

sub report {
    if (-t STDERR) {
        my $level = shift;
        print STDERR "Log($level): @_\n";
    } else {
        syslog(@_);
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
    my $pid = $ENV{LISTEN_PID} || return undef;
    if ($pid ne $$) {
        report("warning", "Unexpected LISTEN_PID=$pid (expected $$)");
        return undef;
    }
    my $fds = $ENV{LISTEN_FDS} || return undef;
    if ($fds ne "1") {
        report("warning", "Unexpected LISTEN_FDS=$fds (expected 1)");
        return undef;
    }
    my $fd = LISTEN_FDS_START;
    open(my $fh, "+>&=", $fd) || die "Could not fdopen($fd): $!";
    return $fh;
}

sub output {
    my $client = shift;
    my $was_empty = $client->{buffer_out} eq "";
    $client->{buffer_out} .= join("", @_);
    if ($was_empty && $client->{buffer_out} ne "") {
        $client->add_write($client->{handle}, sub { $client->can_write() });
    }
}

# Only marks that we want to finish.
# It doesn't pull the rug out from under you.
# The real finish happens when your callback returns
sub finish {
    my ($client, $reason, $response) = @_;
    if (!$reason) {
        report("err", "No finish reason given");
        $reason = "No reason";
    }
    return if $client->{finishing};

    $response //= "";
    $response =~ s/\s+\z//;
    $response ||= "101 $reason";
    $client->output("$response\n");
    $client->{finishing} = $reason;
    $client->{buffer_in} = "";
}

sub shutdown {
    my ($class, $reason) = @_;

    for my $client (values %all_clients) {
        $client->finish($reason);
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
            eval {
                $client->{callbacks}{on_line}->($client, $line);
            };
            if (my $err = $@) {
                $err =~ s/\s+\z//;
                $err = "on_line callback died: $err";
                report("err", $err);
                $client->finish($err, "502 Internal error\n");
            }
            last if $client->{finishing};
        }
        $client->{buffer_in} .= $buffer;
        return;
    }
    if (defined $rc) {
        # EOF
        $client->quit("EOF");
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
    if ($uid != $> && $uid != 0) {
        my $me = getpwuid($>) || "$>";
        my $user = $client->user;
        $client->finish("User '$user' connected to server '$me'",
                       "501 $Script only provides services to user '$me', but you are user '$user'\n");
    } elsif ($pid <= 1) {
        $client->finish("Invalid pid '$pid'",
                       "501 Invalid pid '$pid'\n");
    } elsif (!kill(0, $pid)) {
        # This should be (almost) impossible
        # (can happen if the process died since making the connect)
        $client->finish("Undetectable pid '$pid'",
                       "501 Undetectable pid '$pid'\n");
    } else {
        $client->output("200 $Script ready\n")
    }

    eval { $client->{callbacks}{on_accept}->($client) };
    if (my $err = $@) {
        $err =~ s/\s+\z//;
        $err = "on_accept callback died: $err";
        report("err", $err);
        $client->finish($err, "502 Internal error\n");
    }

    $client->quit($client->{finishing}) if
        $client->{finishing} && $client->{buffer_out} eq "";
}

sub listener {
    my ($class, $fh, %callbacks) = @_;

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

sub rmtree {
    my ($path, $silent) = @_;

    # lstat so we don't follow symlinks
    lstat($path) or do {
        return if $! == ENOENT || $! == ESTALE;
        die "Could not lstat($path): $!";
    };
    report("info", "removing $path") if !$silent;
    if (-d _) {
        opendir(my $dh, $path) || die "Could not opendir($path): $!";
        for my $f (readdir $dh) {
            next if $f eq "." || $f eq "..";
            rmtree("$path/$f", 1);
        }
        rmdir($path) || $! == ENOENT || $! == ESTALE ||
            die "Could not rmdir($path): $!";
    } else {
        unlink($path) || $! == ENOENT || $! == ESTALE ||
            die "Could not unlink '$path': $!";
    }
}

sub run {
    my ($args, $dir) = @_;
    my $command = shift @$args || croak "No command";

    my $pid = open(my $fh, "-|") // die "Could not fork: $!";
    if ($pid == 0) {
        $SIG{PIPE} = "DEFAULT";
        # Child. Avoid being caught by parent
        eval {
            !defined $dir || chdir($dir) || die "Could not chdir($dir): $!";
            exec($command, @$args) || die "Could not exec $command: $!";
        };
        my $err = $@;
        $err =~ s/\s+\z//;
        eval { report("err", "Child $command: $err") };
        _exit(1);
    }
    my $out = do { local $/; <$fh> };
    close($fh);
    return undef if $?;
    return $out;
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

sub run_piped {
    my ($in, @pids);

    for my $do (@_) {
        my ($args, $dir) = @$do;
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
                !defined $dir || chdir($dir) || die "Could not chdir($dir): $!";
                exec($command, @$args) || die "Could not exec $command: $!";
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

sub ls_remote {
    my ($repo, $commit) = @_;

    my $out = run(["git", "ls-remote", $repo, $commit]) // return undef;
    $out =~ s/\s+\z//;
    $out =~ /^([0-9a-f]{40})\s.+\z/ || die "Unexpected ls-remote output '$out'";
    return $1;
}

sub rev_parse {
    my ($repo, $commit) = @_;

    my $out = run(["git", "rev-parse", $commit], $repo) // return undef;
    $out =~ s/\s+\z//;
    $out =~ /^([0-9a-f]{40})\z/ || die "Unexpected rev-parse output '$out'";
    return $1;
}

1;
