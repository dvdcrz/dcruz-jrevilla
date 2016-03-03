#!/usr/bin/perl

sub obtener_archivos{
	opendir (DIR,shift) or die "No se pudo abrir el directorio";
	my @files;
	while(readdir(DIR)){
		if($_ !~  /^\..*/){ push @files,$_; }
	}
	closedir (DIR);
	return @files;
}
