#!/usr/bin/perl
# $File: //member/autrijus/Module-Signature/t/0-signature.t $ $Author: autrijus $
# $Revision: #2 $ $Change: 1737 $ $DateTime: 2002/10/28 23:12:30 $

use strict;
use Test::More tests => 1;

SKIP: {
    if (eval { require Socket; Socket::inet_aton('pgp.mit.edu') } and
	eval { require Module::Signature; 1 }
    ) {
	ok(Module::Signature::verify() == Module::Signature::SIGNATURE_OK()
	    => "Valid signature" );
    }
    else {
	diag("Next time around, consider install Module::Signature,\n".
	     "so you can verify the integrity of this distribution.\n");
	skip("Module::Signature not installed", 1)
    }
}

__END__
