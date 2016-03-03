#!/usr/bin/perl
use strict;

package VARIABLES

=pod


=head1 VARIABLES GLOBALES DE CONFIGURACION DEL PROGRAMA

$filename_prefix_unified_output  ------->  Prefijo para el nombre de salida para los archivos unified2

$filename_prefix_plano_output    ------->  Prefijo para el nombre de salida para los archivos planos

$log_dir                         ------->  Directorio por default para las bitacoras

$directory                       ------->  Directorio por defecto para los archivos de salida

=cut

my $filename_prefix_unified_output = 'unified';  #Prefijo de salida para los archivos unified2
my $filename_prefix_plano_output = 'plano';  #Prefijo de salida para los archivos planos
my $log_dir = getcwd();  #Directorio por default para las bitacoras
my $directory = getcwd();  #Directorio por defecto para los archivos de salida


1;