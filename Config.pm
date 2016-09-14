#!/usr/bin/perl
use strict;
use Cwd;

package VARIABLES;

=pod


=head1 VARIABLES GLOBALES DE CONFIGURACIO	N DEL PROGRAMA

$filename_prefix_unified_output  ------->  Prefijo para el nombre de salida para los archivos unified2

$filename_prefix_plano_output    ------->  Prefijo para el nombre de salida para los archivos planos

$log_dir                         ------->  Directorio por default para las bitacoras

$directory                       ------->  Directorio por defecto para los archivos de salida

=cut

our $filename_prefix_output = '';  #Prefijo de salida para los archivos unified2
our $log_directory = getcwd();  #Directorio por default para las bitacoras
our $directorio = getcwd();  #Directorio por defecto para los archivos de salida

1;
