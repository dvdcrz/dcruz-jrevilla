#!/usr/bin/perl
use File::Find;

sub obtener_archivos{
	opendir (DIR,shift) or die "No se pudo abrir el directorio";
	my @files;
	while(readdir(DIR)){
		if($_ !~  /^\..*/){ push @files,$_; }
	}
	closedir (DIR);
	return @files;
}

my @filenames = obtener_archivos("/home/jrevilla/archivos/");
foreach(@filenames){
	print "\n".$_;
}
