#!/usr/bin/perl -wT
#
#   VyattaLookingGlass - Looking glass for the vyatta routing suite
#
#    Copyright 2012 Merijntje Tak
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

package LookingGlass;
use base 'CGI::Application';
use Socket;
use strict;

#############################################################
# Edit these values
my $routeServer = '';
my $user = '';
my $keyFile = '';
#############################################################


#
# setup - Setup the CGI::Application framework
# Input: qt HTTP variable
# Output: start appropriate runmode
#
sub setup {
  my $self = shift;
  $self->run_modes(
    'default'       => 'defaultRm',
    'bgp'           => 'bgpQuery',
    'trace'         => 'traceQuery',
    'ping'          => 'pingQuery',
    'dig'           => 'digQuery',
    'as'            => 'asQuery'
  );
  $self->start_mode('default');
  $self->mode_param('qt');
}

#
# ipRegexp - regexp to check if a string is an IP
# Input: -
# Output: $1 - $4: octets of the IP address
# 
# Shamelessly copied off perlmonks.org, written by Dietz
#
my $ipRegexp = qr/^
(
 (?:                               # first 3 octets:
  (?: 2(?:5[0-5]|[0-4][0-9])\. )   # 200 - 255
  |                                # or
  (?: 1[0-9][0-9]\. )              # 100 - 199
  |                                # or
  (?: (?:[1-9][0-9]?|[0-9])\. )    # 0 - 99
 )
 {3}                               # above: three times

(?:                                # 4th octet:
 (?: 2(?:5[0-5]|[0-4][0-9]) )      # 200 - 255
  |                                # or
 (?: 1[0-9][0-9] )                 # 100 - 199
  |                                # or
 (?: [1-9][0-9]?|[0-9] )           # 0 - 99
)
 
$)
/x;

#
# digQuery - Perform a dig request on the provided parameter
# Input: Sanatized input from getArg (from CGI::Application param('arg'))
# Output: Flat text for AJAX retrieval
#
sub digQuery {
  my $self = shift;
  my $argument = getArg($self);

  my $command = qq#/usr/bin/host -a $argument#;
  my $output .= runSsh($command);

  return($output);

}


#
# pingQuery - Ping a host
# Input: IP from ipLookupArg (from CGI::Application param('arg'))
# Output: Flat text for AJAX retrieval
#
sub pingQuery {
  my $self = shift;
  my $ip = ipLookupArg($self);
  
  my $command = qq#/bin/ping -c4 -A -w4 -n -- $ip#;
  my $output .= runSsh($command);

  return($output);

}


#
# traceQuery - Traceroute
# Input: IP from ipLookupArg (from CGI::Application param('arg'))
# Output: Flat text for AJAX retrieval
#
sub traceQuery {
  my $self = shift;
  my $ip = ipLookupArg($self);

  my $command = qq#/usr/sbin/traceroute -n -q1 -w3 $ip#;
  my $output .= runSsh($command);

  return($output);

}


#
# bgpQuery - Query Vyatta BGP table for route information
# Input: IP from ipLookupArg (from CGI::Application param('arg'))
# Output: Flat text for AJAX retrieval
#
sub bgpQuery {
  my $self = shift;
  my $ip = ipLookupArg($self);

  my $command = qq#/usr/bin/vtysh -c \'show ip bgp $ip\'#;
  my $output .= runSsh($command);

  return($output);

}


#
# asQuery - Show all paths with an AS in them
# Input: Input from CGI::Application param('arg')
# Output: Flat text for AJAX retrieval
#
sub asQuery {
  my $self = shift;
  my $cgi = $self->query();
  my $as;

  my $output;

  my $raw = $cgi->param('arg');
  if ( $raw =~ m/([0-9]{5})/ ) {
    $as = $1;
    chomp($as);

    my $command = qq#/usr/bin/vtysh -c \'show ip bgp regexp $as\'#;
    $output .= runSsh($command);

  } else {
    $output .= "Error: Invalid AS number";
  }

}


# 
# ipLookupArg - Resolve raw input to an IP address
# Input: None
# Output: scalar with a sanatize IP address
sub ipLookupArg {
  my $self = shift;
  my($output,$ip);
  
  # Input processing
  # getArg -> getArgType -> Ip 
  #                     |-> getIpFromHost -> Ip
  my $san = getArg($self);
  if ( $san eq "invalid" ) {
    $output .= "Error: Invalid input";
    return($output);
  }

  my $type = getArgType($san);

  if ( $type eq "ip" ) {

    $ip = getIp($san);

  } elsif ( $type eq "host" ) {

    $ip = getIpFromHost($san);
    if ( $ip eq "unresolvable" ) {

      $output .= "Error: Address is unresolvable";
      return($output);

    } elsif ( $ip eq "invalid" ) {

      $output .= "Error: Invalid input";
      return($output);

    } else {

      $ip = getIp($ip);

    }

  } else {
    $output .= "Error: Invalid input";
    return($output);
  }

}


#
# getArg - Get the argument from the HTTP POST
# Input: $self
# Output: sanatized input
#
sub getArg {
  my $self = shift;
  my $cgi = $self->query();
  my $raw = $cgi->param('arg');
  my $san;

  if ( $raw =~ m/([A-Za-z0-9\.\-]+)/ ) {
    $san = $1;
  } else {
    $san = "invalid"
  }

  return($san);

}
  

#
# getArgType - get the type of arg argument given
#  Input: output from getArg
#  Output: scalar with one of the following values:
#   - ip
#   - host
#   - invalid
#
sub getArgType {
  my $arg = shift;
  my $output;

  if ( $arg =~ m/[A-Za-z]+/ ) {
    $output = "host"
  } elsif ( $arg =~ m/$ipRegexp/ ) {
    $output = "ip"
  } else {
    $output = "invalid";
  }

  return($output);

}

#
# getIp - Get the ip address from the input string
# Input: output from getArg
# Output: scalar containing the ip address
#
sub getIp {
  my $arg = shift;
  my $output;

  if ( $arg =~ m/$ipRegexp/ ) {
    $output = $1.$2.$3.$4;
  }

  return($output);

}

#
# getIpFromHost -  Get the IP address from a hostname
# Input: output from getArg
# Output: scalar with first IP associated with the hostname
#         or invalid if query failed
#         or unresolvable if address is unresolvable
#
sub getIpFromHost {
  my $arg = shift;
  my $output;

  if ( $arg =~ m/[A-Za-z]+/o ) {

    my $packed_ip = gethostbyname($arg);
    my $ip;

    if (defined $packed_ip) {
      $ip = inet_ntoa($packed_ip);
    }

    if ( !defined($ip) || $ip =~ m/[A-Za-z]+/o ) {
      $output = "unresolvable";
    } else {
      $output = $ip;
    }

  } else {
    $output = "invalid";
  }

  return($output);

}


#
# runSsh - Run provided command on the route server
# Input: scalar: command to run
# Output: Scalar containing output from the command
#
sub runSsh {
  my $command = shift;
  my $output;

  my $cmdOut = `/usr/bin/ssh -o strictHostKeyChecking=no -l $user -i $keyFile $routeServer \"$command\" `;

  # check if an SSH error occured
  if ( $? == 255) {
    $output = "Error: SSH error occurred: $cmdOut";
  } else {
    $output = $cmdOut;
  }

  return($output);
}

#
# defaultRm - Default runmode, check for config errors or show error
# Input: none
# Output: If configured properly, provide an error, else show config guide
#
sub defaultRm {
  my $self = shift;
  my $cgi = $self->query();
  my $output;
  my $configError = 0;

  if ( defined($user) && $user != "" )               { $configError = 1; }
  if ( defined($routeServer) && $routeServer != "" ) { $configError = 1; }
  if ( defined($keyFile) && $keyFile != "" )         { $configError = 1; }

  if ( $configError == 1 ) {
    $output = "Error: Please configure the variables in LookingGlass.pm first. See the readme file for installation instructions. Exiting..."
  } else {
    $output = "Error: This script should not be called directly. Exiting...";
  }

  return($output);

}
  

1;
