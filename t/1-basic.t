#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/t/1-basic.t $ $Author: autrijus $
# $Revision: #2 $ $Change: 1283 $ $DateTime: 2002/10/09 08:59:43 $

use strict;
use Test::More tests => 2;

use_ok('Module::Signature');
Module::Signature->import('SIGNATURE_OK');
ok(defined(&SIGNATURE_OK));

__END__
