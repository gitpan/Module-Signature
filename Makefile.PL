#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/Makefile.PL $ $Author: autrijus $
# $Revision: #10 $ $Change: 7401 $ $DateTime: 2003/08/08 02:48:32 $

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
        recommends( 'MIME::Base64' ),
	recommends( 'Compress::Zlib' ),
	recommends( 'Crypt::CBC' ),
	recommends( 'Crypt::DES' ),
	recommends( 'Crypt::Blowfish' ),
	recommends( 'Crypt::RIPEMD160' ),
	recommends( 'Tie::EncryptedHash' ),
	recommends( 'Class::Loader' ),
	recommends( 'Convert::ASCII::Armour' ),
	recommends( 'Data::Buffer' => 0.04 ),
	recommends( 'Digest::MD2' ),
	recommends( 'Math::Pari' ),
	recommends( 'Crypt::Random' ),
	recommends( 'Crypt::Primes' ),
	recommends( 'Crypt::DES_EDE3' ),
	recommends( 'Crypt::DSA' ),
	recommends( 'Crypt::RSA' ),
	recommends( 'Convert::ASN1' ),
	recommends( 'Convert::PEM' ),
	recommends( 'Crypt::OpenPGP' => 1.0 ),
    ],
) unless (can_run('gpg') and `gpg --version` =~ /GnuPG/ and defined `gpg --list-public-keys`);

features(
    'Show signature diffs'	=> [
	recommends('Algorithm::Diff' => 0),
	recommends('Text::Diff'      => 0),
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
