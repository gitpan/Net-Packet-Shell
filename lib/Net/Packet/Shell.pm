#
# $Id: Shell.pm,v 1.2 2006/11/13 00:07:11 gomor Exp $
#
package Net::Packet::Shell;
use warnings;

our $VERSION = '0.10';

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
   sr
   sd
   sd2
   sd3
   nps
   sniff
   dsniff
   read
);

use Net::Packet;
use Net::Write::Layer2;
use Net::Write::Layer3;
use Data::Dumper;
use Term::ReadLine;

$Env->noFrameAutoDesc(1);
$Env->noFrameAutoDump(1);
$Env->noDescAutoSet(1);
$Env->noDumpAutoSet(0);
$Env->noFramePadding(1);
$Env->doFrameReturnList(1);

*F      = sub { Frame(@_)                                          };
*ETH    = sub { my $r = Net::Packet::ETH->new(@_);    $r->pack; $r };
*RAW    = sub { my $r = Net::Packet::RAW->new(@_);    $r->pack; $r };
*SLL    = sub { my $r = Net::Packet::SLL->new(@_);    $r->pack; $r };
*NULL   = sub { my $r = Net::Packet::NULL->new(@_);   $r->pack; $r };
*ARP    = sub { my $r = Net::Packet::ARP->new(@_);    $r->pack; $r };
*IPv4   = sub { my $r = Net::Packet::IPv4->new(@_);   $r->pack; $r };
*IPv6   = sub { my $r = Net::Packet::IPv6->new(@_);   $r->pack; $r };
*TCP    = sub { my $r = Net::Packet::TCP->new(@_);    $r->pack; $r };
*UDP    = sub { my $r = Net::Packet::UDP->new(@_);    $r->pack; $r };
*VLAN   = sub { my $r = Net::Packet::VLAN->new(@_);   $r->pack; $r };
*ICMPv4 = sub { my $r = Net::Packet::ICMPv4->new(@_); $r->pack; $r };
*PPPoE  = sub { my $r = Net::Packet::PPPoE->new(@_);  $r->pack; $r };
*PPP    = sub { my $r = Net::Packet::PPP->new(@_);    $r->pack; $r };
*PPPLCP = sub { my $r = Net::Packet::PPPLCP->new(@_); $r->pack; $r };
*LLC    = sub { my $r = Net::Packet::LLC->new(@_);    $r->pack; $r };
*CDP    = sub { my $r = Net::Packet::CDP->new(@_);    $r->pack; $r };

sub Frame {
   my $f = Net::Packet::Frame->new;
   for my $l (@_) {
      do { $f->l2($l); next } if $l->isLayer2;
      do { $f->l3($l); next } if $l->isLayer3;
      do { $f->l4($l); next } if $l->isLayer4;
      do { $f->l7($l); next } if $l->isLayer7;
   }
   $f->pack;
   $f;
}

sub sr {
   do { print "Nothing to send\n"; return } unless $_[0];

   my $d = Net::Write::Layer2->new(dev => $Env->dev);
   $d->open;
   $d->send(shift());
   $d->close;
}

sub sd {
   do { print "Nothing to send\n"; return } unless $_[0];

   return sd2(@_) if $_[0]->l2;
   return sd3(@_) if $_[0]->l3;
}

sub sd2 {
   do { print "Nothing to send\n"; return } unless $_[0];

   $Env->doIPv4Checksum(1);
   $Env->noFrameComputeLengths(1);
   $Env->noFrameComputeChecksums(1);

   my $raw = '';
   for (@_) {
      $_->pack;
      $raw .= $_->raw;
   }
   my $d = Net::Write::Layer2->new(dev => $Env->dev);
   $d->open;
   $d->send($raw);
   $d->close;

   $Env->doIPv4Checksum(0);
   $Env->noFrameComputeLengths(0);
   $Env->noFrameComputeChecksums(0);
}

sub sd3 {
   do { print "Nothing to send\n"; return } unless $_[0];

   do { print "We can only send IPv4 frames at layer 3\n"; return }
      if ($_[0]->l2 || ($_[0]->l3 && $_[0]->l3->isIpv4));

   $Env->doIPv4Checksum(0);
   $Env->noFrameComputeLengths(1);
   $Env->noFrameComputeChecksums(1);

   my $raw = '';
   my $dst;
   for (@_) {
      $dst = $_->l3->dst unless $dst;
      $_->pack;
      $raw .= $_->raw;
   }
   my $d = Net::Write::Layer3->new(dev => $Env->dev, dst => $dst);
   $d->open;
   $d->send($raw);
   $d->close;

   $Env->doIPv4Checksum(0);
   $Env->noFrameComputeLengths(0);
   $Env->noFrameComputeChecksums(0);
}

sub sniff {
   my ($filter) = @_;
   my $d = Net::Packet::Dump->new(
      noStore => 1,
   );
   $d->filter($filter) if $filter;
   $d->start;
   while (1) {
      if (my $f = $d->next) {
         for (@$f) {
            print $_->l2->print."\n" if $_->l2;
            print $_->l3->print."\n" if $_->l3;
            print $_->l4->print."\n" if $_->l4;
            print $_->l7->print."\n" if $_->l7;
         }
      }
   }
}

sub dsniff {
   my ($filter) = @_;
   my $d = Net::Packet::Dump->new(
      noStore => 1,
   );
   $d->filter($filter) if $filter;
   $d->start;
   while (1) {
      if (my $f = $d->next) {
         for my $c (@$f) {
            if ($c->l7) {
               my $data = $c->l7->data;
               next unless $data =~ /^user\s+|^pass\s+/i;
               print $c->l3->dst.':'.$c->l4->dst.'> '.$data."\n";
            }
         }
      }
   }
}

sub read {
   my ($file) = @_;
   do { print "Please specify a pcap file to read\n"; return } unless $file;

   my $d = Net::Packet::Dump->new(
      file          => $file,
      mode          => NP_DUMP_MODE_OFFLINE,
      overwrite     => 0,
      unlinkOnClean => 0,
      noStore       => 1,
   );
   $d->start;

   my $n = 0;
   while (my $fr = $d->next) {
      ++$n;
      print 'Number of frames in chunk: '.scalar(@$fr)."\n";
      for (@$fr) {
         print 'Frame number: '.$n."\n";
         print $_->print."\n";
         print "Padding: ".unpack('H*', $_->padding)."\n" if $_->padding;
      }
      print "\n";
   }

   $d->stop;
   $d->clean;
}

sub str {
   my $hex = unpack('H*', shift());
   $hex =~ s/(..)/\\x$1/g;
   $hex =~ s/\\x$//;
   print "\"$hex\"";
}

sub nps {
   my $prompt = 'nps> ';
   my $name   = 'NPS';
   my $term   = Term::ReadLine->new($name);
   $term->ornaments(0);

   my @subList   = qw(sr sd sd2 sd3 sniff dsniff read);
   my @layerList = qw(
      ETH IPv4 TCP UDP VLAN IPv6 ARP RAW SLL NULL ICMPv4 PPPoE PPPLCP PPP LLC
      CDP
   );
   $term->Attribs->{completion_function} = sub {
      ( @subList, @layerList )
   };

   while (my $line = $term->readline($prompt)) {
      eval($line);
      warn($@) if $@;
      print "\n";
   }

   print "\n";
}

1;

__END__

=head1 NAME

Net::Packet::Shell - Scapy like implementation using Net::Packet, just to prove it

=head1 SYNOPSIS
  
   perl -MNet::Packet::Shell -e nps

   # Optional, just to change default interface to localhost
   nps> $Env->updateDevInfo('127.0.0.1')

   # Example IPv6 within IPv4
   nps> $ip6=F(IPv6,TCP)
   nps> $Env->noFrameComputeLengths(1)
   nps> $ip4=F(ETH,IPv4(protocol=>41,hlen=>5,length=>NP_IPv4_HDR_LEN+$ip6->getLength))
   nps> sd($ip4,$ip6)

   # Sniffing (an IPv6 frame within IPv4 is shown)
   nps> sniff
   L2:+ETH: dst:ff:ff:ff:ff:ff:ff  src:ff:ff:ff:ff:ff:ff  type:0x0800
   L3:+IPv4: version:4  hlen:5  tos:0x00  length:80  id:769
   L3: IPv4: flags:0x00  offset:0  ttl:128  protocol:0x29  checksum:0x0000
   L3: IPv4: src:127.0.0.1  dst:127.0.0.1
   L3:+IPv6: version:6  trafficClass:0x00  flowLabel:0x00000  nextHeader:0x06
   L3: IPv6: payloadLength:20  hopLimit:255
   L3: IPv6: src:::1  dst:::1
   L4:+TCP: src:35997  dst:0  seq:0x34beb583  ack:0x0000 
   L4: TCP: off:0x05  x2:0x0  flags:0x2  win:65535  checksum:0x3902  urp:0x00

   # Sniffing with filter
   nps> sniff('tcp')

   # Dsniff tiny implementation
   nps> dsniff

   # Dsniff tiny implementation with filter
   nps> dsniff('tcp and port 110')

   # Read a pcap file
   nps> read('file.pcap')

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
