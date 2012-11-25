#!/usr/bin/env perl
# count entries in a crlset

use 5.10.1;
use strict;
use warnings;

use Data::Dumper;

my %crl;

loadcrl($ARGV[0]);

my $count = 0;
for my $key (%crl) {
	my $h = $crl{$key};
	$count += scalar keys %$h;
}
say $count;

sub loadcrl {
	my $crlfile = shift;

	open ( my $fh, "<", $crlfile);

	for ( 1..3 ) {
		<$fh>; # first three lines are crap
	}

	my $currhash;
	while ( my $line = <$fh> ) {
		chomp($line);

		if ( $line =~ s#^  ## ) {
			Carp("no currhash?") unless defined($currhash);
			$crl{$currhash}->{$line} = 1;
		} else {
			$currhash = $line;
		}
	}
}

