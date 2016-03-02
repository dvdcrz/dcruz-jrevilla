#!/usr/bin/perl
#use strict;
use SnortUnified(qw(:ALL));
use Funciones;
use Cwd;
use Data::Dumper;

#Variables locales
my $directory = getcwd();  #Directorio actual por default
my $origin= ""; #????
my $log_dir = getcwd(); #Directorio actual por default
my $modo_continuo=0;
my $modo_batch=0;
my @files; #Para el modo batch
my $file=""; #Solo para un archivo

#Comprobamos para la ayuda
if($ARGV[0] eq '-h' || $ARGV[0] eq '--help')
{
	print "\nAyuda\n";
}
else
{
	my $error=0;	
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
			$file = shift @ARGV;
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
		elsif($arg eq '-f' || $arg eq '--file')
		{
			$file = shift @ARGV;
			print "\nArchivo: ".$file;	
		}
		else
		{
			$error=1;
			print "Error de sintaxis";
		}
	}

	#Si no hubo error en la sintaxis de los argumentos
	if($error == 0)
	{
		#Checamos la opciones
		if($modo_batch == 0)
		{ 
			if($file ne "")
			{
				#modo demonio
				if($modo_continuo == 1)
				{
					#AQUI DEBE IR LLAMADA A DEMONIO
					print "Se activa el demonio";
					demonio($log_directory,$directory,'uno',$file);
				}
				else
				{
					#funcionamiento normal
					procesa_archivo($file,$log_directory,$directory,'salida');
				}
			}
			else
			{

				print "\n\nERROR debes ingresar un el nombre del archivo con la bandera -f\n\n";
			}
		}
		else
		{
			if($file eq "")
			{  #checamos que si esta modo por lotes no pueda usar la bandera -f porque los archivo se pasan por -b archivo1 archivo2
				if(my $tam = @files != 0)
				{
					#est es el modo batch
					#my $cont=0;
					#foreach(@files)
					#{
						#se manda el nombre del archivo, directorio de log y de salida y numero??
					#	procesa_archivo($_,$log_directory,$directory,$cont);
					#	$cont++;
					#}
					#print "entro a alote\n";
					#procesa_lote(\@files,$log_directory,$directory,1);
					$referencia_incidentes =procesa_lote(\@files);
					%incidentes = %{$referencia_incidentes};

					imprime_incidentes(\%incidentes,$log_directory,$directory,1);
				}
				else
				{
					print "\n\nERROR debes ingresar la lista de archivos despues de -b\n\n";
				}
			}
			else
			{ 
				print "\n\nERROR de sintaxis: no puedes usar -b con -f\n\n";
			}
		}
	}
}

print "\n\n";
