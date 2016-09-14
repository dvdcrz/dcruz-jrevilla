#!/usr/bin/perl
#use strict;
use SnortUnified(qw(:ALL));
use Funciones;
use Cwd;
use Data::Dumper;

=pod

=head1 DESCRIPCION DE LA HERRAMIENTA
 
 GENINC es una herramienta que clasifica las alertas generadas por Snort en 
 incidentes, recibiendo uno o mas archivos en formato unified2, procesandolos
 y generando un nuevo archivo unified2 optimizado en formato unified2, ademas
 de un archivo de texto plano con un resumen de los incidentes. Cada evento
 en los archivos unified2 contiene información relacionada con su detección,
 fecha, IP origen, IP destino, puerto origen, puerto destino, entre otros. 
 
 GENINC procesa los eventos y conforma los incidentes clasificando todos 
 aquellos eventos que tienen en común el protocolo, dirección IP origen y la
 alerta. Es decir, todas las alertas que se originen desde la misma dirección
 IP, protocolo y nombre de la alerta conformará un incidente de seguridad.


=head2 Declaracion de variables locales

	$directory  #Directorio de trabajo
	$origin #Directorio de origen de los archivos
	$log_dir #Directorio de las bitacoras	
	$modo_continuo  #1 - modo continuo activado         0 - modo continuo desactivado
	$modo_batch  #1 - modo batch activado         0 - modo batch desactivado
	@files  #Arreglo con los archivos para batch
	$file  #Archivo a procesar

=cut

#Variables locales
my $directory = getcwd();  #Directorio actual por default
my $origin= ""; #????
my $log_dir = getcwd(); #Directorio actual por default
my $modo_continuo=0;
my $modo_batch=0;
my @files; #Para el modo batch
my $file=""; #Solo para un archivo


=head3 Procesamos los argumentos

	OPCIONES:
    -h, --help           Ayuda del programa
    -b, --batch          Modo por lotes: Procesa varios archivos para obtener incidentes
    -c, --continuos      Modo continuo: El programa se ejecuta en modo demonio y revisa el archivo en busca de nuevos eventos
    -d, --directory      Directorio en el cual se guardaran los archivos generados
    -l, --log            Directorio para las bitácoras de ejecución de geninc
=cut

#Comprobamos para la ayuda
if($ARGV[0] eq '-h' || $ARGV[0] eq '--help')
{
        print "\n-------------------------------------------------------------------------";
		print "\n			GENERADOR DE INCIDENTES				  ";
        print "\n-------------------------------------------------------------------------";
		print "\n\nDESCRIPCION:";
		print "\nGENINC es una herramienta que clasifica las alertas generadas por Snort en ";
		print "\nincidentes, recibiendo uno o mas archivos en formato unified2, procesandolos";
		print "\ny generando un nuevo archivo unified2 optimizado en formato unified2, ademas";
		print "\nde un archivo de texto plano con un resumen de los incidentes. Cada evento";
		print "\nen los archivos unified2 contiene información relacionada con su detección,";
		print "\nfecha, IP origen, IP destino, puerto origen, puerto destino, entre otros. ";
		print "\n\nGENINC procesa los eventos y conforma los incidentes clasificando todos ";
      	print "\naquellos eventos que tienen en común el protocolo, dirección IP origen y la";
      	print "\nalerta. Es decir, todas las alertas que se originen desde la misma dirección";
      	print "\nIP, protocolo y nombre de la alerta conformará un incidente de seguridad.";
      	print "\n\nOPCIONES:";
      	print "\n   -h, --help           Ayuda del programa.";
      	print "\n\n   -b, --batch          Modo por lotes: Procesa varios archivos para obtener incidentes.";
      	print "\n\n   -c, --continuos      Modo continuo: El programa se ejecuta en modo demonio y revisa";
      	print "\n                        el archivo en busca de nuevos eventos.";
      	print "\n\n   -d, --directory      Directorio en el cual se guardaran los archivos generados.";
      	print "\n\n   -l, --log            Directorio para las bitácoras de ejecución de geninc.";
      	print "\n\nSINTAXIS:";
      	print "\n\n1 archivo -> ./geninc.pl [<filepath> [-d <directory>] [-l <log_directory] [-c]]";
      	print "\n\n1 o mas archivos -> ./geninc [-b <filepath1> .. <filepathN> [-l <log_directory>] [-d <directory>]]";
		print "\n\nEJEMPLOS DE EJECUCIÓN:";
      	print "\n\n\t./geninc -f merged-log -d /home/becario/ -l /var/log/";
      	print "\n\n\t./geninc -f merged-log -c";
      	print "\n\n\t./geninc -b unified1 unified2 unified3 -d /home/becario/\n\n";
      	exit 0;
}
else
{
        my $error=0;
	if($ARGV[0] !~ /-.*/){ #Si no es una bandera, es decir no empieza con -, entonces es el archivo
		print "Archivo: ".$ARGV[0];
		$file = shift @ARGV;	
	}
		#Recorremos todos los argumentos
	       	while((my $arg = shift @ARGV) && $error == 0)
	        {
	                if($arg eq '-d' || $arg eq '--directory')
	                {
	                        $directory = shift @ARGV;
	                        print "\nDirectory: ".$directory;
	                }
	                elsif($arg eq '-o' || $arg eq '--origin')
	                {
	                        $origin = shift @ARGV;
	                        print "\nOrigin Directory: ".$origin;
	                }
	                elsif($arg eq '-l' || $arg eq '--log')
	                {
	                        $log_dir = shift @ARGV;
	                        print "\nLog Directory: ".$log_dir;
	                }
        	        elsif($arg eq '-c' || $arg eq '--continuos')
	                {
	                        $modo_continuo = 1;
                        	print "\nModo continuo activado";
	                }	
	                elsif($arg eq '-b' || $arg eq '--batch')
	                {
	                        $modo_batch = 1;
	                        print "\nModo batch activado: ";
	                }
	                elsif($modo_batch == 1)
                	{
	                        push @files,$arg;
	                        print "\t".$arg;
	                }
	                else
	                {
	                        $error=1;
	                        print "Error de sintaxis";
				exit 0;
	                }
		}
}

if($modo_continuo == 1){
	if($origin ne ""){
		print "\n\nObtener lista de archivos aqui";
		print "\n\nLlamar al demonio para batch aqui.";
	}else{
		print "\n\nLlamar al demonio a un archivo aqui.";
		demonio($log_directory,$directory,$file,$file);
	}	
}else{
	if($origin ne ""){
		print "\n\nOntener lista.";
		print "\n\nLlamar por lotes.";
		my @files = obtener_archivos($origin);
		$referencia_incidentes =procesa_lote(\@files);
		%incidentes = %{$referencia_incidentes};
		imprime_incidentes(\%incidentes,$log_directory,$directory,1);

	}elsif($modo_batch == 1){
		print "Llamar por lotes con lista en comandos.";
		$referencia_incidentes =procesa_lote(\@files);
		%incidentes = %{$referencia_incidentes};
		imprime_incidentes(\%incidentes,$log_directory,$directory,1);
	}else{
		print "\n\nLlamar al modo normal";
		#procesa_archivo($file,$log_directory,$directory,'salida');
		procesa_archivo($file,$log_directory,$directory,$file);
	}	
}

print "\n\n";
