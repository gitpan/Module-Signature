#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/Makefile.PL $ $Author: autrijus $
# $Revision: #16 $ $Change: 7735 $ $DateTime: 2003/08/27 07:04:34 $

use 5.005;
use inc::Module::Install;

name            ('Module-Signature');
abstract        ('Module signature file manipulation');
author          ('Autrijus Tang (autrijus@autrijus.org)');
version_from    ('lib/Module/Signature.pm');
license         ('perl');
install_script	('bin/cpansign');

check_nmake();
requires( 'Digest::SHA1' );
build_requires( 'Test::More' );
features(
    'Crypt::OpenPGP Support'	=> [
	-default    => 0,
        'MIME::Base64' => 0,
	'Compress::Zlib' => 0,
	'Crypt::CBC' => 0,
	'Crypt::DES' => 0,
	'Crypt::Blowfish' => 0,
	'Crypt::RIPEMD160' => 0,
	'Tie::EncryptedHash' => 0,
	'Class::Loader' => 0,
	'Convert::ASCII::Armour' => 0,
	'Data::Buffer' => 0.04,
	'Digest::MD2' => 0,
	'Math::Pari' => 0,
	'Crypt::Random' => 0,
	'Crypt::Primes' => 0,
	'Crypt::DES_EDE3' => 0,
	'Crypt::DSA' => 0,
	'Crypt::RSA' => 0,
	'Convert::ASN1' => 0,
	'Convert::PEM' => 0,
	'Crypt::OpenPGP' => 1.0,
    ],
) if want_openpgp();

features(
    'Display checksum differences' => [
	recommends( 'Algorithm::Diff' => 0 ),
	recommends( 'Text::Diff'      => 0 ),
    ],
) unless (can_run('diff'));

features(
    'Sign and verify PAR (Perl Archive) files' => [
	-default => 0,
	recommends( 'PAR::Dist'	=> 0 ),
    ],
);

include('ExtUtils/AutoInstall.pm');
auto_install();

&Meta->write;
&Makefile->write;

my $make = eval { require Config; $Config{make} } || 'make';
print "\nNow, please enter '$make test' to test, and '$make install' to install.\n";

sub locate_openpgp {
    print "*** Looking for Crypt::OpenPGP (Pure-Perl OpenPGP implementation)...\n";
    my $version = eval { require Crypt::OpenPGP; Crypt::OpenPGP->VERSION };
    if ($version) {
	print "Crypt::OpenPGP found (version $version), good.\n";
	return 1;
    }
}

sub locate_gpg {
    print "*** Looking for GnuPG (GNU Privacy Guard, a cryptographic signature tool)...\n";

    my $gpg = can_run('gpg');
    my $has_gpg = (
	$gpg and
	`gpg --version` =~ /GnuPG/ and
	defined `gpg --list-public-keys`
    );

    if ($has_gpg) {
	print "GnuPG found ($gpg).  Importing PAUSE and author keys to GnuPG... ";
	system('gpg', '--quiet', '--import', <*.pub>);
	print "done.\n";
	return 1;
    }

    print "GnugPG not found anywhere in your PATH, eek.\n";
    return;
}

sub want_openpgp {
    return if (locate_gpg() or locate_openpgp());

    print << '.';

What do you want me to do?
1) Let you install GnuPG manually while I'm waiting for your answer;
   it is available at http://www.gnupg.org/download/.
.

    my $punt = 2;
    if (can_cc()) {
	$punt++;
	print << '.';
2) Automatically install Crypt::OpenPGP and the 20 modules it requires
   from CPAN, which will give the same functionality as GnuPG.
.
    }

    print << ".";
$punt) Forget this cryptographic signature stuff for now. 
.

    my $choice;
    while (1) {
	$choice = prompt("Your choice:", 3) || 3;
	last if $choice =~ /^[123]$/;
	print "Sorry, I cannot understand '$choice'.\n"
    }

    goto &want_openpgp if $choice == 1;
    return if $choice == $punt;
    return 1;
}
