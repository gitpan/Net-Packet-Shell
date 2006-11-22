#!/usr/bin/perl

use Net::Packet::Shell;

$Env->updateDevInfo('127.0.0.1');

$f = F(IPv4, TCP(dst => 443));

print $f->print."\n";

sd($f);
