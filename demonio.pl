#!/usr/bin/perl
use strict;
use Proc::Daemon;
#my $filename = shift;
#print "Archivo: ".$filename;
my $daemon = Proc::Daemon -> new(
	work_dir => '/home/jrevilla/Downloads/dcruz-jrevilla/',
	child_SDTOUT => 'salida.txt',
	child_STDERR => '+>>debug.txt',
	exec_command => 'perl /home/jrevilla/Downloads/dcruz-jrevilla/mejor_archivo.pl /home/dcruz-jrevilla/eventosgenerados'
	);

my $pid = $daemon->Init();
