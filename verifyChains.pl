#!/usr/bin/env perl

# script to validate certificates and sort them into error categories
# input file format: tab-separated
# 
# timestamp sni cert1,cert2,cert3,cert4 
# so e.g.
# 1347923636.343648	example.icsi.berkeley.edu	d249c37947b69fa66999518fb831b270,68e7d79daae3be7bb4eb39e9e2320fea
#
# cert1, etc. are the md5-hashes of the certificates in the chain, in correct
# order.
#
# The folder certificates/ has to contain files with the name [hash].der,
# containing the respective certificates in der-form.

use 5.10.1;
use strict;
use warnings;

# for this script to work, you have to take care that the file root.pem contains
# all the pem root-certificates that were used at the time of the connection.
# the crlset that shall be used should be in the file crlset.
#
# The directory intermediates has to contain all valid intermediate certificates
# that should be preloaded into nss (hence, the cached intermediates).
#
# Use the NSS perl bindings at https://github.com/amannb/perl-nss/tree/mozilla-functions (branch mozilla-functions).
# Please note that you also have to patch nss with the provided patch.

# to verify chains without caching, disable the intermediate loading
# to verify chains with aia loading, use the aia-capable function in the NSS module

use NSS qw/:dbpath db/;
use Perl6::Slurp;
use autodie;
use Carp;
use Digest::SHA qw(sha256 sha256_hex sha256_base64);

my $crl = {};

NSS->load_rootlist("root.pem");

for my $file (<intermediates/*.der>) {
	say STDERR "Loading intermediate in $file";
	my $cert = slurp($file);
	my $nsscert = NSS::Certificate->new($cert);
	NSS::add_cert_to_db($nsscert, $file);
}

NSS::_reinit(); # prevent possible cache tainting

loadcrl("crlset") if -e 'crlset';

while ( my $line = <> ) {
	chomp($line);

	my ( $ts, $sni, $certs ) = split(/\t/, $line);
	
	$sni =~ s/\.$//; # strip . at end of sni.	

	if ( !defined($ts) || !defined($sni) || !defined($certs) ) {
		croak "undefined entry";
	}

	my @certs = split(/,/, $certs);
	croak "no certs" if ( scalar @certs == 0 );	
	my $hostcert = shift @certs;

	my @loadedcerts; # we have to keep ref's to the certs when we
	# load them in the following loop. Otherwise they will be destroyed
	# by NSS
	
	for my $cert ( @certs ) {
		my $file = slurp("certificates/$cert.der");
		eval {
			my $nsscert = NSS::Certificate->new($file);
			push(@loadedcerts, $nsscert);
		} or do {
			my $error = $@;
			if ( $error =~ m#\-8054# ) {
				say STDERR "Intermediate loading of ".$cert->subject." FAILED, but it SHOULD already be present."; # Nss :(
			} else {
				croak("$@ while trying to import intermediate ".$cert->subject."");
			}
		};
	}

	my $nsscert;
	eval {
		my $file = slurp("certificates/$hostcert.der");
		$nsscert = NSS::Certificate->new($file);
	} or do {
		croak("$@ while trying to import end-host cert".$hostcert);
	};
	my $certvalid = $nsscert->verify_mozilla($ts);
	my $hostvalid = $nsscert->match_name($sni);

	my $revoked = 0;

	if ( $certvalid == 1 ) {
		# let's see if it is revoked.
		# get the chain

		my @chain = $nsscert->get_cert_chain_from_cert->dump;

		my $lastcert = shift(@chain);

		next if ( !defined($lastcert) );

		# get the public key hash of the issuer.
		for my $ic ( @chain ) {
			my $pkh = sha256_hex($ic->raw_spki);

			my $pkgcrl = ($crl->{$pkh});

			if ( defined($pkgcrl) ) {
				if ( defined($pkgcrl->{$lastcert->serial}) ) {
					say STDERR "found revoked: $lastcert->serial";
				}
			}

			$lastcert = $ic;
		}
	}	


	my $out = "$sni\t";
	$out .= "{";
	$out .= $certs;
	$out .= "}\t";
	$out .= "$certvalid\t";
	$out .= $hostvalid ? 'T' : 'F';
	$out .= "\t";
	$out .= $nsscert->is_root ? 'T' : 'F';

	say $out;

	# classification in the paper:
	# if is_root == 1, the certificate is classified as a selfsigned certificate
	# if $certvalid == -8181 or -8162 -> expired
	# if $certvalid == -8179 or -8172 -> untrusted issuer
	# if $certvalid < 1 -> non-overridable error
	# if $certvalid == 1 && !$hostvalid -> certificate for wrong domain
	# if $certvalud == 1 && $hostvalid -> valid certificate
}

sub loadcrl {
	my $crlfile = shift;
	say STDERR "Loading crlset";

	open ( my $fh, "<", $crlfile);

	for ( 1..3 ) {
		<$fh>; # first three lines are crap
	}

	my $currhash;
	while ( my $line = <$fh> ) {
		chomp($line);

		if ( $line =~ s#^  ## ) {
			Carp("no currhash?") unless defined($currhash);
			$crl->{$currhash}->{$line} = 1;
		} else {
			$currhash = $line;
		}
	}
}

