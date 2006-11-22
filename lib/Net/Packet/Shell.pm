#
# $Id: Shell.pm,v 1.3 2006/11/22 18:06:46 gomor Exp $
#
package Net::Packet::Shell;
use strict;
use warnings;

our $VERSION = '0.20';

my @subList = qw(
   F sr sd sd2 sd3 sniff dsniff read
);

my @layerList = qw(
   ETH RAW SLL NULL ARP IPv4 IPv6 TCP UDP VLAN ICMPv4 PPPoE PPP PPPLCP LLC CDP
   STP OSPF IGMPv4
);

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = (
   'nps',
   '$Env',
   @subList,
   @layerList,
   @Net::Packet::Env::EXPORT_OK,
   @Net::Packet::Utils::EXPORT_OK,
   @Net::Packet::Consts::EXPORT_OK,
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
$Env->doFrameReturnList(1);

_resetEnv();

sub _resetEnv {
   $Env->noFramePadding(1);
   $Env->noFrameComputeLengths(0);
   $Env->noFrameComputeChecksums(0);
   $Env->doIPv4Checksum(0);
}

sub _frame {
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

*F = sub { _frame(@_) };

{
   no strict 'refs';
   for my $l (@layerList) {
      *$l = sub { my $r = "Net::Packet::$l"->new(@_); $r->pack; $r };
   }
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
   my ($f) = @_;

   do { print "Nothing to send\n"; return } unless $f;

   $Env->doIPv4Checksum(1);
   $Env->noFrameComputeLengths(0);
   $Env->noFrameComputeChecksums(0);

   $f->pack;

   my $d = Net::Write::Layer2->new(dev => $Env->dev);
   $d->open;
   $d->send($f->raw);
   $d->close;

   _resetEnv();
}

sub sd3 {
   my ($f) = @_;

   do { print "Nothing to send\n"; return } unless $f;

   do { print "We can only send IPv4 frames at layer 3\n"; return }
      if ($f->l2 || ($f->l3 && ! $f->l3->isIpv4));

   $Env->doIPv4Checksum(0);
   $Env->noFrameComputeLengths(0);
   $Env->noFrameComputeChecksums(0);

   my $dst = $f->l3->dst;
   $f->pack;

   my $d = Net::Write::Layer3->new(dev => $Env->dev, dst => $dst);
   $d->open;
   $d->send($f->raw);
   $d->close;

   _resetEnv();
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
      }
      print "\n";
   }

   $d->stop;
   $d->clean;
}

sub nps {
   my $prompt = 'nps> ';
   my $name   = 'NPS';
   my $term   = Term::ReadLine->new($name);
   $term->ornaments(0);

   $term->Attribs->{completion_function} = sub {
      ( @subList, @layerList )
   };

   while (my $line = $term->readline($prompt)) {
      $line =~ s/s*read/Net::Packet::Shell::read/;
      eval($line);
      warn($@) if $@;
      print "\n";
   }

   print "\n";
}

END {
   if ($Env->dump) {
      $Env->dump->stop;
      $Env->dump->clean;
   }
}

1;

__END__

=head1 NAME

Net::Packet::Shell - Scapy like implementation using Net::Packet, just to prove it

=head1 SYNOPSIS
  
   perl -MNet::Packet::Shell -e nps

   # Optional, just to change default interface and related
   nps> $Env->updateDevInfo('127.0.0.1')

   # Basic example IPv4 with TCP
   # See also examples/ip4-tcp.pl for a scripted version
   nps> sd F(IPv4,TCP(dst=>443))

   # Advanced example: an IPv6 frame within IPv4
   # See also examples/ip6-within-ip4.pl for a scripted version
   nps> $ip6=F(IPv6,TCP)
   nps> $Env->doIPv4Checksum(1); $Env->noFrameComputeLengths(1)
   nps> $ip4=F(ETH,IPv4(protocol=>NP_IPv4_PROTOCOL_IPv6, \
      length=>NP_IPv4_HDR_LEN+$ip6->getLength))
   nps> sr $ip4->raw.$ip6->raw

   # Sniffing (an IPv6 frame within IPv4 is shown)
   nps> sniff
   L2:+ETH: dst:ff:ff:ff:ff:ff:ff  src:ff:ff:ff:ff:ff:ff  type:0x0800
   L3:+IPv4: version:4  hlen:5  tos:0x00  length:60  id:36492
   L3: IPv4: flags:0x00  offset:0  ttl:128  protocol:0x29  checksum:0xae0a
   L3: IPv4: src:127.0.0.1  dst:127.0.0.1
   L3:+IPv6: version:6  trafficClass:0x00  flowLabel:0x00000  nextHeader:0x06
   L3: IPv6: payloadLength:20  hopLimit:255
   L3: IPv6: src:::1  dst:::1
   L4:+TCP: src:20692  dst:0  seq:0x7bf55f60  ack:0x0000 
   L4: TCP: off:0x05  x2:0x0  flags:0x2  win:65535  checksum:0x83b7  urp:0x00

   # Sniffing with filter
   nps> sniff('tcp')

   # Dsniff tiny implementation
   nps> dsniff

   # Dsniff tiny implementation with filter
   nps> dsniff('tcp and port 110')

   # Read a pcap file
   nps> read('file.pcap')

=head1 DESCRIPTION

B<Net::Packet::Shell> is, as the name imply, a shell program to use B<Net::Packet>. With it, you will be able to send crafted frames (via B<Net::Packet::Frame>), or send raw data using directly related layers you wish to use.

It is also scriptable, while personaly I prefer to directly use B<Net::Packet> for scripted tasks. You can see examples scripts from B<examples> directory in the source tarball.

The main behaviour of B<Net::Packet::Shell> is driven by a B<Net::Packet::Env> object. I suggest you to read the man page (... now). Basically, the default B<$Env> object used has the following values set: B<noFramePadding(1)>, B<noFrameComputeLengths(0)>, B<noFrameComputeChecksums(0)>, B<doIPv4Checksum(0)>.

These default values change when you send a frame with B<sd2> or B<sd3> (and B<sd>, we will see that), to comply with kernel restrictions, and hopefully to help the user automate simple tasks. But at the end of the send call, default values will be reset as they were originally.

You can use B<sr> if you want to fully control the sending process. With this method, you simply pass a raw string (and not a B<Net::Packet::Frame> object), and it is directly written at layer 2 on the network. In this case, you are in charge of handling checksums, and lengths of the frame. There are helpers, though.

For a guide on how to use these helpers, see B<Net::Packet::Frame> and B<Net::Packet::Env>.

=head1 GENERAL FUNCTIONS

=over 4

=item B<nps>

This is the function to run for starting B<Net::Packet::Shell>. You will then be able to use the following functions. You do not use this function at all if you want to script B<Net::Packet::Shell>. See B<SYNOPSIS>.

=item B<sr> (raw scalar string)

You pass a raw string as a parameter, and it is directly written to the network, with no analyze at all. No checksums, no lengths will be computed before sending, you are on your own.

=item B<sd> (B<Net::Packet::Frame>)

This one is a wrapper around B<sd2> and B<sd3>. That is, it will use internally B<sd2> to send frame if it has a layer 2 built-in. If will use internally B<sd3> if the frame has a layer3 buil-in, and no a layer 2.

After a successfull call to B<sd>, or B<sd2>, or B<sd3>, B<Net::Packet::Env> env object will be reinitialized to default behaviour for B<Net::Packet::Shell>.

=item B<sd2> (B<Net::Packet::Frame>)

Sending frame here will auto-compute checksums and lengths, when implemented in the respective layers. Frame will be sent at layer 2.

=item B<sd3> (B<Net::Packet::Frame>)

Sending frame here will auto-compute checksums and lengths, when implemented in the respective layers. Frame will be sent at layer 3.

=item B<read> (file)

You pass a pcap file as a parameter, and it will be decoded and each frames printed to standard output.

=item B<sniff> [ (pcap filter) ]

This function will sniff the network using the default interface (set by default B<Net::Packet::Env> env object). It will decode each seen frames, and print them to standard output.

You can pass a pcap filter as a parameter to select only the traffic you want.

=item B<dsniff> [ (pcap filter) ]

This is a small implementation of Dug Song's Dsniff tool.

You can pass a pcap filter as a parameter to select only the traffic you want.

=item B<F>

Function packager for various layers. This is equivalent to B<Net::Packet::Frame>. When a frame object is created with various layers, they will be packed, and assembled into a raw string.

If B<Net::Packet::Env> env object has its attributes B<noFrameComputeChecksums>, B<noFrameComputeLengths>, B<doIPv4Checksum> set to true of false values, it will have an impact on the packing of the frame.

So, the packing will compute checksums and lengths, only if you tell it via this B<Net::Packet::Env> env object.

=back

=head1 LAYER FUNCTIONS

All the following functions handles respective layers. To know more about parameters they take, see respective B<Net::Packet> pod (example for ETH: B<Net::Packet::ETH>).

=over 4

=item B<ARP> [ (hash) ]

=item B<CDP> [ (hash) ]

=item B<ETH> [ (hash) ]

=item B<ICMPv4> [ (hash) ]

=item B<IGMPv4> [ (hash) ]

=item B<IPv4> [ (hash) ]

=item B<IPv6> [ (hash) ]

=item B<LLC> [ (hash) ]

=item B<NULL> [ (hash) ]

=item B<OSPF> [ (hash) ]

=item B<PPP> [ (hash) ]

=item B<PPPLCP> [ (hash) ]

=item B<PPPoE> [ (hash) ]

=item B<RAW> [ (hash) ]

=item B<SLL> [ (hash) ]

=item B<STP> [ (hash) ]

=item B<TCP> [ (hash) ]

=item B<UDP> [ (hash) ]

=item B<VLAN> [ (hash) ]

=back

=head1 SEE ALSO

L<Net::Packet>, L<Net::Packet::Env>, L<Net::Packet::Frame>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
