#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/Makefile.PL $ $Author: autrijus $
# $Revision: #11 $ $Change: 7465 $ $DateTime: 2003/08/12 03:57:14 $

use 5.005;
use inc::Module::Install;

name            ('Module-Signature');
abstract        ('Module signature file manipulation');
author          ('Autrijus Tang (autrijus@autrijus.org)');
version_from    ('lib/Module/Signature.pm');
license         ('perl');
install_script	('bin/cpansign');

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
) unless (can_run('gpg') and `gpg --version` =~ /GnuPG/ and defined `gpg --list-public-keys`);

features(
    'Show signature diffs'	=> [
	'Algorithm::Diff' => 0,
	'Text::Diff'      => 0,
    ],
) unless (can_run('diff'));

features(
    'Sign and verify PAR files'	=> [
	recommends( 'PAR::Dist'	=> 0 ),
    ],
);

include('ExtUtils/AutoInstall.pm');
auto_install();

&Meta->write;
&Makefile->write;
