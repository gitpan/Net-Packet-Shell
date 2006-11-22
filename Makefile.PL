#
# $Id: Makefile.PL,v 1.3 2006/11/22 18:01:32 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Packet::Shell',
   LICENSE       => 'Artistic',
   VERSION_FROM  => 'lib/Net/Packet/Shell.pm',
   PREREQ_PM     => {
      Net::Packet => '3.20',
   },
   ABSTRACT_FROM => 'lib/Net/Packet/Shell.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
);
