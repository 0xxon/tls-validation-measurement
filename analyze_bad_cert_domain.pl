use strict;
use warnings;

# perl analyze_bad_cert_domain.pl < inputfile
# Input is a TSV list with the following in each line:
# cnt  sni certfilename
# Where 
#     cnt is the number of times a particular sni+certfilename combination was seen
#     sni is the sni value sent by the client
#     certfilename is a name of the file which has the certificate presented



#http://github.com/amannb/perl-nss Use the dev-hostname branch
use NSS;
use Crypt::X509;

# Download from publicsuffix.org
use regDomain;
use effectiveTLDs;


use autodie;
use 5.10.1;

#keep everything global, since Dev is lazy.
my %totals = ();
my %totals_cert = ();
my %tldcerts =();
my $fulltotal=0;
my $updatecalled=0;
my ($cnt,$sni,$filename);
my $cert;
my @cnames;
my @anames;
my $snitld;
my $sniwww;
my $linetotal=0;
while(<>){
  chomp;
  my $line = $_;
  ($cnt,$sni,$filename) = split "\t",$line;
  print STDERR "\non $filename\n";
  unless( -e "$filename.der"){
    print STDERR "$filename.der NOT FOUND!\n";
    exit;
  }
  $updatecalled=0;
  #remove the . at the end of the sni.
  $sni = substr($sni,0,-1) if $sni =~ m/\.$/;
  {
    local $/;
    open my $fh,"<",$filename.".der";
    my $string = <$fh>;
    $cert = NSS::Certificate->new($string);
    close $fh;
  }
  $fulltotal+=$cnt;
  $linetotal++;
  #Modify the SNI with the WWW value.
  if($sni =~ m/^www\./){
    $sniwww = substr $sni,4;
  } else {
    $sniwww= "www.".$sni;
  }
  #first populate the cnames and anames array with the values in this array
  populateNames();
  update("allnames") if (checknames("moz",$sni,(@anames,@cnames)));
  update("www") if $cert->match_name($sniwww);
  if (checknames('new',$sni,(@anames,@cnames))){
    update("relaxed") ;
    update("relaxedwww");
  }else{
  update("relaxedwww") if (checknames('new',$sniwww,(@anames,@cnames)));
  }
  $snitld = regDomain::getRegisteredDomain($sni, $effectiveTLDs::tldTree);
  next if !(defined $snitld);
  update("tld") if checktldmatch_array(@anames,@cnames);
  unless($updatecalled == 1){
    print STDERR "\n$cnt\t The $sni $filename.der combination didn't fall into any category.";
  }
  next;
}

while ( my ($key,$value)  = each (%totals) ){
  print $key," => ",$value," ",(sprintf "%0.2f",($value * 100)/$fulltotal),"%\n";
}

print "\n\n";
while ( my ($key,$value)  = each (%totals_cert) ){
  print $key," => ",$value," ",(sprintf "%0.2f",($value * 100)/$linetotal),"%\n";
}

sub update {
  my $key = shift;
  $totals{$key} += $cnt;
  $totals_cert{$key} ++;
  $updatecalled = 1;
}


sub checknames { 
  my ($type,$target,@names ) = @_;
  my $function = \&moz_testname;
  $function = \&testname if $type eq 'new';
  foreach my $name (@names) {
	return 1 if (&$function($target,$name));
  }
 return 0;
}

	
sub populateNames {
  @anames =();
  @cnames = ();
  my $subj = $cert->subject;
  push @cnames, $1 while( $subj =~ m/CN=([^,+]+)/gi);
  my $x = "";
  eval {
   $x = $cert->subj_alt_name;
  };
  unless (ref $x) {
    push @anames, $1 while( $x =~ m/DNS:([^,+]+)/gi);
  }
}


sub checktldmatch {
  my ($candidate) = @_;
  my $candidatetld = regDomain::getRegisteredDomain($candidate, $effectiveTLDs::tldTree);
  return 0 unless( defined $candidatetld);
  return 1 if( lc($snitld) eq lc($candidatetld));
  return 0;

}

sub checktldmatch_array {
  foreach my $name (@_) {
   return 1 if ( checktldmatch($name) ) ;
 }
}


sub testname {
  my ($sni,$name) = @_;
  return 1 if(lc($name) eq lc($sni));
  return 0 unless $name =~ m/\*/;
  #the name has an asterisk. Check TLD thingie first.
  #The logic is simple:
  #       If the top level registered domain for the name is the same, then this is not cool.
  #       e.g., *.google.com will return google.com; but *.com will return *.com
  my $tld = regDomain::getRegisteredDomain($name, $effectiveTLDs::tldTree); 
  return 0 unless defined $tld;
  if (lc($tld) eq lc($name)){
      $tldcerts{$filename}= $name;
      return 0;
  }
  return 0 if $tld =~ m/\*/;
  $name = quotemeta($name);
  $name =~ s/\\\*/.+/g;
  return 1 if($sni =~ m/^$name$/);
  return 0;
}

sub moz_testname {
  my ($sni,$name) = @_;
  return 0 unless NSS::test_host_name($name, $sni);
  return 1;
}


