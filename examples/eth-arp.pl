#!/usr/bin/perl

use Net::Packet::Shell;

$Env->updateDevInfo('127.0.0.1');

$f = F(ETH(type  => NP_ETH_TYPE_ARP),
       ARP(dstIp => '127.0.0.1')
     );

print $f->print."\n";

sd($f);
