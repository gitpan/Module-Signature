# $File: //member/autrijus/Module-Signature/Signature.pm $ 
# $Revision: #4 $ $Change: 609 $ $DateTime: 2002/08/13 08:34:31 $

package Module::Signature;
$Module::Signature::VERSION = '0.03';

use strict;
use vars qw($VERSION $SIGNATURE @ISA @EXPORT_OK);
use vars qw($BoilerPlate $Cipher $Debug $Quiet); 

use constant SIGNATURE_OK       => 0;
use constant SIGNATURE_MISSING  => -1;
use constant SIGNATURE_BAD      => -2;
use constant SIGNATURE_MISMATCH => -3;
use constant MANIFEST_MISMATCH  => -4;

use Digest;
use ExtUtils::Manifest ();
use Exporter;

@EXPORT_OK	= qw(sign verify);
@ISA		= 'Exporter';
$SIGNATURE	= 'SIGNATURE';
$Cipher		= 'SHA1';
$BoilerPlate	= << ".";
This file contains message digests of all files listed in MANIFEST,
signed via the Module::Signature module, version $VERSION.

To verify the content in this distribution, first make sure you have
Module::Signature installed, then type:

    % cpansign verify

It would check each file's integrity, as well as the signature's
validity.  If "==> Signature verified OK! <==" is not displayed,
the distribution may already have been compromised, and you should
not run it's Makefile.PL or Build.PL.

.

=head1 NAME

Module::Signature - Module signature file manipulation

=head1 VERSION

This document describes version 0.03 of B<Module::Signature>.

=head1 SYNOPSIS

As a shell command:

    % cpansign
    % cpansign sign	# ditto
    % cpansign verify	# verify a signature

In programs:

    use Module::Signature qw(sign verify);
    sign();
    verify();

=head1 DESCRIPTION

B<Module::Signature> adds cryptographic authentications to
CPAN distribution files, via the special SIGNATURE file.

=cut

sub verify {
    my $plaintext = _mkdigest();
    my $rv;

    if (!-r $SIGNATURE) {
	warn "==> MISSING Signature file! <==\n";
	return SIGNATURE_MISSING;
    }

    if (`gpg --version` =~ /GnuPG/) {
	$rv = _verify_gpg($SIGNATURE, $plaintext);
    }
    elsif (eval {require Crypt::OpenPGP; 1}) {
	$rv = _verify_crypt_openpgp($SIGNATURE, $plaintext);
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
    }
    elsif ($rv == SIGNATURE_MISMATCH) {
	warn "==> MISMATCHED content between SIGNATURE and distribution files! <==\n";
    }

    return $rv;
}

sub _verify_gpg {
    my ($sigfile, $plaintext) = @_;
    my $signature = `gpg --decrypt $sigfile`;

    return SIGNATURE_BAD if ($?);
    return _compare($signature, $plaintext);
}

sub _verify_crypt_openpgp {
    my ($sigfile, $plaintext) = @_;

    require Crypt::OpenPGP;
    my $pgp = Crypt::OpenPGP->new;

    my $rv = $pgp->handle(
	Filename	=> $sigfile
    ) or die $pgp->errstr;

    return SIGNATURE_BAD unless $rv->{Validity};

    warn "Signature made ", scalar localtime($rv->{Signature}->timestamp),
         " using key ID ", substr(uc(unpack("H*", $rv->{Signature}->key_id)), -8), "\n";
    warn "Good signature from \"$rv->{Validity}\"\n";

    my $signature = '';
    local *D;
    open D, $sigfile or die "Could not open $sigfile: $!";
    while (<D>) {
	next if (1 .. /^-----BEGIN PGP SIGNED MESSAGE-----/);
	next if (/^Hash: / .. /^$/);
	last if /^-----BEGIN PGP SIGNATURE/;
	$signature .= $_;
    }

    return _compare($signature, $plaintext);
}

sub _compare {
    my ($str1, $str2) = @_;

    # normalize all linebreaks
    $str1 =~ s/[^\S ]+/\n/; $str2 =~ s/[^\S ]+/\n/;

    return SIGNATURE_MISMATCH if ($str1 ne $str2);
    return SIGNATURE_OK;
}

sub sign {
    my $plaintext = _mkdigest();

    my ($mani, $file) = ExtUtils::Manifest::fullcheck();
    if (@{$mani} or @{$file}) {
	warn "==> MISMATCHED content between MANIFEST and the distribution! <==\n";
	warn "==> Please correct your MANIFEST file and/or delete extra files. <==\n";
    }

    if (`gpg --version` =~ /GnuPG/) {
	_sign_gpg($SIGNATURE, $plaintext);
    }
    elsif (eval {require Crypt::OpenPGP; 1}) {
	_sign_crypt_openpgp($SIGNATURE, $plaintext);
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
