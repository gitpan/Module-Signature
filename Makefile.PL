#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/Makefile.PL $ $Author: autrijus $
# $Revision: #2 $ $Change: 603 $ $DateTime: 2002/08/13 06:46:33 $

require 5.005;

# ExtUtils::AutoInstall Bootstrap Code, version 4.
BEGIN{my$p='ExtUtils::AutoInstall';my$v=.30;eval"use $p $v;1"or
($ENV{PERL_EXTUTILS_AUTOINSTALL}!~/--(?:default|skip|testonly)/
and(-t STDIN)or eval"use ExtUtils::MakeMaker;WriteMakefile('PR'
.'EREQ_PM'=>{'$p',$v});1"and exit)and print"==> $p $v needed. "
."Install it from CPAN? [Y/n] "and<STDIN>!~/^n/i and print"***"
." Fetching $p\n"and do{eval{require CPANPLUS;CPANPLUS::install
$p};eval"use $p $v;1"or eval{require CPAN;CPAN::install$p};eval
"use $p $v;1"or die"Please install $p $v manually first...\n"}}

ExtUtils::AutoInstall->import(
    -core			=> [
	'Digest'		=> 0,
	'Test::More'		=> 0,
    ],
    'Crypt::OpenPGP Support'	=> [
	-default		=> system('gpg --version'),
        'MIME::Base64'		=> 0,
	'Compress::Zlib'	=> 0,
	'Crypt::CBC'		=> 0,
	'Crypt::DES'		=> 0,
	'Crypt::Blowfish'	=> 0,
	'Crypt::RIPEMD160'	=> 0,
	'Tie::EncryptedHash'	=> 0,
	'Class::Loader'		=> 0,
	'Convert::ASCII::Armour'=> 0,
	'Data::Buffer'		=> 0.04,
	'Digest::MD2'		=> 0,
	'Math::Pari'		=> 0,
	'Crypt::Random'		=> 0,
	'Crypt::Primes'		=> 0,
	'Crypt::DES_EDE3'	=> 0,
	'Crypt::DSA'		=> 0,
	'Crypt::RSA'		=> 0,
	'Convert::ASN1'		=> 0,
	'Convert::PEM'		=> 0,
	'Crypt::OpenPGP'	=> 1.0,
    ],
);

WriteMakefile(
    AUTHOR		=> 'Autrijus Tang (autrijus@autrijus.org)',
    ABSTRACT		=> 'Module signature file manipulation',
    NAME		=> 'Module::Signature',
    VERSION_FROM	=> 'Signature.pm', 
    DISTNAME		=> 'Module-Signature',
    BINARY_LOCATION	=> 'x86/ExtUtils-Signature.tar.gz',
    EXE_FILES		=> [ <bin/*> ],

    dist		=> {
        COMPRESS	=> 'gzip -9',
        SUFFIX		=> '.gz',
    },
);

