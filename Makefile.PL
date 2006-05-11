#!/usr/bin/perl

use 5.005;
use inc::Module::Install;

$|++;

name            'Module-Signature';
license         'MIT';
all_from        'lib/Module/Signature.pm';
install_script  'script/cpansign';

requires (can_cc() ? 'Digest::SHA' : 'Digest::SHA::PurePerl')
    unless can_use 'Digest::SHA'
        or can_use 'Digest::SHA1'
        or can_use 'Digest::SHA::PurePerl';

requires qw(
    MIME::Base64
    Compress::Zlib
    Crypt::CBC
    Crypt::DES
    Crypt::Blowfish
    Crypt::RIPEMD160
    Tie::EncryptedHash
    Class::Loader
    Convert::ASCII::Armour
    Data::Buffer    0.04
    Digest::MD2
    Math::Pari
    Crypt::Random
    Crypt::Primes
    Crypt::DES_EDE3
    Crypt::DSA
    Crypt::RSA
    Convert::ASN1
    Convert::PEM
    Crypt::OpenPGP  1.00
) if want_openpgp();

feature 'Display checksum differences', -default => 0, recommends qw(
    Algorithm::Diff
    Text::Diff
) unless can_run 'diff';

feature 'Sign and verify PAR (Perl Archive) files', -default => 0, recommends qw(
    PAR::Dist
);

feature 'Support for SHA-256', -default => 0, recommends
    (can_cc() ? 'Digest::SHA' : 'Digest::SHA::PurePerl')
    unless can_use 'Digest::SHA'
        or can_use 'Digest::SHA256'
        or can_use 'Digest::SHA::PurePerl';

auto_install
    prerequisites_policy => 'follow';

build_requires  'Test::More';
auto_include_deps;

sign; WriteAll;

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
        print "GnuPG found ($gpg).\n";

        return 1 if grep { /^--installdeps/} @ARGV;

        if (prompt("Import PAUSE and author keys to GnuPG?", 'y') =~ /^y/i) {
            print 'Importing... ';
            system 'gpg', '--quiet', '--import', glob('*.pub');
            print "done.\n";
        }
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
