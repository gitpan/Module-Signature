# $File: //member/autrijus/Module-Signature/Signature.pm $ 
# $Revision: #15 $ $Change: 1329 $ $DateTime: 2002/10/11 19:00:33 $

package Module::Signature;
$Module::Signature::VERSION = '0.08';

use strict;
use vars qw($VERSION $SIGNATURE @ISA @EXPORT_OK);
use vars qw($BoilerPlate $Cipher $Debug $Quiet $KeyServer); 

use constant SIGNATURE_OK        => 0;
use constant SIGNATURE_MISSING   => -1;
use constant SIGNATURE_MALFORMED => -2;
use constant SIGNATURE_BAD       => -3;
use constant SIGNATURE_MISMATCH  => -4;
use constant MANIFEST_MISMATCH   => -5;

use Digest;
use ExtUtils::Manifest ();
use Exporter;

@EXPORT_OK	= (qw(sign verify),
		   grep /^[A-Z_]+_[A-Z_]+$/, keys %Module::Signature::);
@ISA		= 'Exporter';

$SIGNATURE	= 'SIGNATURE';
$KeyServer	= 'pgp.mit.edu';
$Cipher		= 'SHA1';
$BoilerPlate	= << ".";
This file contains message digests of all files listed in MANIFEST,
signed via the Module::Signature module, version $VERSION.

To verify the content in this distribution, first make sure you have
Module::Signature installed, then type:

    % cpansign -v

It would check each file's integrity, as well as the signature's
validity.  If "==> Signature verified OK! <==" is not displayed,
the distribution may already have been compromised, and you should
not run its Makefile.PL or Build.PL.

.

=head1 NAME

Module::Signature - Module signature file manipulation

=head1 VERSION

This document describes version 0.08 of B<Module::Signature>.

=head1 SYNOPSIS

As a shell command:

    % cpansign		# DWIM: verify an existing SIGNATURE, or
			        make a new one if none exists 

    % cpansign sign	# make signature; overwrites existing one
    % cpansign -s	# same thing

    % cpansign verify	# verify a signature
    % cpansign -v	# same thing

    % cpansign help     # display this documentation
    % cpansign -h       # same thing

In programs:

    use Module::Signature qw(sign verify SIGNATURE_OK);
    sign();
    sign(overwrite => 1);	# overwrites without asking

    # see the CONSTANTS section below
    (verify() == SIGNATURE_OK) or die "failed!";

CPAN authors may consider adding this code as C<t/0-signature.t>:

    use strict;
    use Test::More tests => 1;

    SKIP: {
	if (eval { require Module::Signature; 1 }) {
	    ok(Module::Signature::verify() == Module::Signature::SIGNATURE_OK()
		=> "Valid signature");
	}
	else {
	    diag("Next time around, consider install Module::Signature,\n".
		 "so you can verify the integrity of this distribution.\n");
	    skip("Module::Signature not installed", 1)
	}
    }

=head1 DESCRIPTION

B<Module::Signature> adds cryptographic authentications to
CPAN distribution files, via the special SIGNATURE file.

=head1 CONSTANTS

These constants are not exported by default.

=over 4

=item SIGNATURE_OK

Signature successfully verified.

=item SIGNATURE_MALFORMED

The signature file does not contains a valid OpenPGP message.

=item SIGNATURE_BAD

Invalid signature detected -- it might have been tampered.

=item SIGNATURE_MISMATCH

The signature is valid, but files in the distribution have changed
since its creation.

=item MANIFEST_MISMATCH

There are extra files in the current directory not specified by
the MANIFEST file.

=cut

sub verify {
    my $plaintext = _mkdigest();
    my $rv;

    (-r $SIGNATURE) or do {
	warn "==> MISSING Signature file! <==\n";
	return SIGNATURE_MISSING;
    };

    (my $sigtext = _read_sigfile($SIGNATURE)) or do {
	warn "==> MALFORMED Signature file! <==\n";
	return SIGNATURE_MALFORMED;
    };

    if (`gpg --version` =~ /GnuPG/) {
	$rv = _verify_gpg($sigtext, $plaintext);
    }
    elsif (eval {require Crypt::OpenPGP; 1}) {
	$rv = _verify_crypt_openpgp($sigtext, $plaintext);
    }
    else {
	die "Cannot use GnuPG or Crypt::OpenPGP, please install either one first!";
    }

    if ($rv == SIGNATURE_OK) {
	my ($mani, $file) = ExtUtils::Manifest::fullcheck();

	if (@{$mani} or @{$file}) {
	    warn "==> MISMATCHED content between MANIFEST and distribution files! <==\n";
	    return MANIFEST_MISMATCH;
	}
	else {
	    warn "==> Signature verified OK! <==\n";
	}
    }
    elsif ($rv == SIGNATURE_BAD) {
	warn "==> BAD/TAMPERED signature detected! <==\n";
    }
    elsif ($rv == SIGNATURE_MISMATCH) {
	warn "==> MISMATCHED content between SIGNATURE and distribution files! <==\n";
    }

    return $rv;
}

sub _verify_gpg {
    my ($sigtext, $plaintext) = @_;

    system(
	'gpg', "--verify", ($KeyServer ? (
	    "--keyserver=$KeyServer", "--keyserver-options=auto-key-retrieve",
	) : ()), $SIGNATURE,
    );

    return SIGNATURE_BAD if ($?);
    return _compare($sigtext, $plaintext);
}

sub _verify_crypt_openpgp {
    my ($sigtext, $plaintext) = @_;

    require Crypt::OpenPGP;
    my $pgp = Crypt::OpenPGP->new;
    my $rv = $pgp->handle( Filename => $SIGNATURE )
	or die $pgp->errstr;

    return SIGNATURE_BAD unless $rv->{Validity};

    warn "Signature made ", scalar localtime($rv->{Signature}->timestamp),
         " using key ID ", substr(uc(unpack("H*", $rv->{Signature}->key_id)), -8), "\n";
    warn "Good signature from \"$rv->{Validity}\"\n";

    return _compare($sigtext, $plaintext);
}

sub _read_sigfile {
    my $sigfile = shift;
    my $signature = '';
    my $well_formed;

    local *D;
    open D, $sigfile or die "Could not open $sigfile: $!";
    while (<D>) {
	next if (1 .. /^-----BEGIN PGP SIGNED MESSAGE-----/);
	next if (/^Hash: / .. /^$/);
	return $signature if /^-----BEGIN PGP SIGNATURE/;

	$signature .= $_;
    }

    return;
}

sub _compare {
    my ($str1, $str2) = @_;

    # normalize all linebreaks
    $str1 =~ s/[^\S ]+/\n/; $str2 =~ s/[^\S ]+/\n/;

    return SIGNATURE_OK if $str1 eq $str2;

    if (eval { require Text::Diff; 1 }) {
	warn "--- $SIGNATURE ".localtime((stat($SIGNATURE))[9])."\n";
	warn "+++ (current) ".localtime()."\n";
	warn Text::Diff::diff( \$str1, \$str2, { STYLE => "Unified" } );
    }
    elsif (`diff -version` =~ /diff/) {
	local (*D, *S);
	open S, $SIGNATURE or die "Could not open $SIGNATURE: $!";
	open D, "| diff -u $SIGNATURE -" or die "Could not call diff: $!";
	while (<S>) {
	    print D $_ if (1 .. /^-----BEGIN PGP SIGNED MESSAGE-----/);
	    print D if (/^Hash: / .. /^$/);
	    next if (1 .. /^-----BEGIN PGP SIGNATURE/);
	    print D $str2, "-----BEGIN PGP SIGNATURE-----\n", $_ and last;
	}
	print D <S>;
	close D;
    }

    return SIGNATURE_MISMATCH if ($str1 ne $str2);
}

sub sign {
    my %args = @_;
    my $overwrite = $args{overwrite};
    my $plaintext = _mkdigest();

    my ($mani, $file) = ExtUtils::Manifest::fullcheck();
    if (@{$mani} or @{$file}) {
	warn "==> MISMATCHED content between MANIFEST and the distribution! <==\n";
	warn "==> Please correct your MANIFEST file and/or delete extra files. <==\n";
    }

    if (!$overwrite and -e $SIGNATURE and -t STDIN) {
	print "$SIGNATURE already exists; overwrite [y/N]? ";
	return unless <STDIN> =~ /[Yy]/;
    }

    if (`gpg --version` =~ /GnuPG/) {
	_sign_gpg($SIGNATURE, $plaintext);
    }
    elsif (eval {require Crypt::OpenPGP; 1}) {
	_sign_crypt_openpgp($SIGNATURE, $plaintext);
    }
    else {
	die "Cannot use GnuPG or Crypt::OpenPGP, please install either one first!";
    }
}

sub _sign_gpg {
    my ($sigfile, $plaintext) = @_;

    local *D;
    open D, ">$sigfile" or die "Could not write to $sigfile: $!";
    print D $BoilerPlate;
    close D;
    open D, "| gpg --clearsign >> $sigfile" or die "Could not call gpg: $!";
    print D $plaintext;
    close D;
}

sub _sign_crypt_openpgp {
    my ($sigfile, $plaintext) = @_;

    require Crypt::OpenPGP;
    my $pgp = Crypt::OpenPGP->new;
    my $ring = Crypt::OpenPGP::KeyRing->new(
	Filename => $pgp->{cfg}->get('SecRing')
    ) or die $pgp->error(Crypt::OpenPGP::KeyRing->errstr);
    my $kb = $ring->find_keyblock_by_index(-1)
	or die $pgp->error("Can't find last keyblock: " . $ring->errstr);

    my $cert = $kb->signing_key;
    my $uid = $cert->uid($kb->primary_uid);
    warn "Debug: acquiring signature from $uid\n" if $Debug;

    my $signature = $pgp->sign(
	Data       => $plaintext,
	Detach     => 0,
	Clearsign  => 1,
	Armour     => 1,
	Key        => $cert,
	PassphraseCallback => \&Crypt::OpenPGP::_default_passphrase_cb,
    ) or die $pgp->errstr;


    local *D;
    open D, ">$sigfile" or die "Could not write to $sigfile: $!";
    print D $BoilerPlate;
    print D $signature;
    close D;

    return $signature;
}

sub _mkdigest {
    my $digest = _mkdigest_files(@_);
    my $plaintext = '';

    foreach my $file (sort keys %$digest) {
	next if $file eq $SIGNATURE;
	$plaintext .= "@{$digest->{$file}} $file\n";
    }

    return $plaintext;
}

sub _mkdigest_files {
    my $p = shift;
    my $algorithm = shift || $Cipher;
    my $dosnames = (defined(&Dos::UseLFN) && Dos::UseLFN()==0);
    my $read = ExtUtils::Manifest::maniread() || {};
    my $found = ExtUtils::Manifest::manifind($p);
    my(%digest) = ();
    my $obj = Digest->new($algorithm);

    foreach my $file (sort keys %$read){
        warn "Debug: collecting digest from $file\n" if $Debug;
        if ($dosnames){
            $file = lc $file;
            $file =~ s=(\.(\w|-)+)=substr ($1,0,4)=ge;
            $file =~ s=((\w|-)+)=substr ($1,0,8)=ge;
        }
        unless ( exists $found->{$file} ) {
            warn "No such file: $file\n" unless $Quiet;
        }
	else {
	    local *F;
	    open F, $file or die "Cannot open $file for reading: $!";
	    $obj->addfile(*F);
	    $digest{$file} = [$algorithm, $obj->hexdigest];
	    $obj->reset;
	}
    }

    return \%digest;
}

1;

__END__

=head1 SEE ALSO

L<ExtUtils::Manifest>, L<Crypt::OpenPGP>

=head1 AUTHORS

Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>

=head1 COPYRIGHT

Copyright 2002 by Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>.

This program is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

See L<http://www.perl.com/perl/misc/Artistic.html>

=cut
