#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/t/1-basic.t $ $Author: autrijus $
# $Revision: #3 $ $Change: 1339 $ $DateTime: 2002/10/12 08:06:33 $

use strict;
use Test::More tests => 2;

use_ok('Module::Signature');
Module::Signature->import('SIGNATURE_OK');
ok(defined(&SIGNATURE_OK), 'constant exported');

__END__