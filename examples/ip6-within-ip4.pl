#!/usr/bin/perl

use Net::Packet::Shell;

$Env->updateDevInfo('127.0.0.1');

$ip6 = F(IPv6, TCP);

$Env->doIPv4Checksum(1);
$Env->noFrameComputeLengths(1);
$ip4 = F(ETH,
         IPv4(protocol => NP_IPv4_PROTOCOL_IPv6,
              length   => NP_IPv4_HDR_LEN + $ip6->getLength,
         )
       );
 
print $ip4->print."\n";
print $ip6->print."\n";

sr($ip4->raw.$ip6->raw);
