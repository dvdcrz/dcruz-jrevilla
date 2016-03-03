#!/usr/bin/perl
use strict;

package VARIABLES

=pod


=head1 VARIABLES GLOBALES DE CONFIGURACIO	N DEL PROGRAMA

$filename_prefix_unified_output  ------->  Prefijo para el nombre de salida para los archivos unified2

$filename_prefix_plano_output    ------->  Prefijo para el nombre de salida para los archivos planos

$log_dir                         ------->  Directorio por default para las bitacoras

$directory                       ------->  Directorio por defecto para los archivos de salida

=cut

our $filename_prefix_unified_output = 'unified';  #Prefijo de salida para los archivos unified2
our $filename_prefix_plano_output = 'plano';  #Prefijo de salida para los archivos planos
our $log_dir = getcwd();  #Directorio por default para las bitacoras
our $directory = getcwd();  #Directorio por defecto para los archivos de salida

1;