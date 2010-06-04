#
# $Id: Makefile.PL 8 2010-06-04 11:43:42Z gomor $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Packet::Shell',
   LICENSE       => 'artistic',
   VERSION_FROM  => 'lib/Net/Packet/Shell.pm',
   PREREQ_PM     => {
      Net::Packet    => '3.20',
      Net::Write     => 0,
      Term::ReadLine => 0,
   },
   ABSTRACT_FROM => 'lib/Net/Packet/Shell.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
);
