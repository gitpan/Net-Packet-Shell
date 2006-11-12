#
# $Id: Makefile.PL,v 1.2 2006/11/13 00:07:40 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Packet::Shell',
   VERSION_FROM  => 'lib/Net/Packet/Shell.pm',
   PREREQ_PM     => {
      Net::Packet => '3.20',
   },
   ABSTRACT_FROM => 'lib/Net/Packet/Shell.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
);
