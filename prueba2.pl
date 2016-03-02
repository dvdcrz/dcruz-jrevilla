#!/usr/bin/perl
#use strict;
use SnortUnified(qw(:ALL));
use Cwd;

sub procesa_archivo{
	my @argumentos = @_;
	my $file = $argumentos[0];
	my $directory_log = $argumentos[1];
	my $directory = $argumentos[2];
	my $name_output_file = $argumentos[3];

	open (STDERR, '>>', $directory_log.'bitacora.log') or die "No se pudo abrir";       
                $UF_Data = openSnortUnified($file) or die "ERROR al abrir archivo";
                %incidentes=();
                $id=0;
                while ( $record = readSnortUnified2Record() )
                {
                                #7               Unified2 IDS Event
                                #72              Unified2 IDS Event IP6
                                #si el registro es un evento
                        if($record->{TYPE} == 7 || $record->{TYPE} == 72)
                        {
				#si el incidente ya existe en el hash de eventos se agrega 1 al contador y se sobre escribe registro ultimo
                                if(exists($incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}))
                                {
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'n_eventos'}++;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;
                                        #suponiendo que snort siempre escribe el los eventos en un orden evento,paquete,evento
                                        # obtenemos el paquete correspondiente al evento
                                        $paquete = readSnortUnified2Record();
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paquete'} = $paquete;
                                }
                                else
                                {
                                        #si no existe el incidente se crea con el eventeo primero ultimo iguales
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}={'id_incidente' => ++$id,'n_eventos' => 1,'primero' => $record, 'ultimo' => $record};
                                        $paquete = readSnortUnified2Record();
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primero_paquete'} = $paquete;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paquete'} = $paquete;
                                }
                                        #print "$record->{'class'} $record->{'sip'} $record->{'protocol'}\n";
                                        #$incidentes{$record->{'class'}}{$record->{'sip'}}{$record->{'protocol'}}++;
                                        #print("entro");
                        }
		}
                open($salida, '+>:raw',$directory.'/'.$name_output_file.'_unified2')or die "no se pudo abrir $!";
                open($salida_plano, '+>',$directory.'/'.$name_output_file.'_plano')or die "no se pudo abrir $!";

                #se iteran en el hash de incidentes
                print $salida_plano "ID_incidente\tSeparador\tN_eventos\n";


                foreach $key (keys %incidentes)
                {
			#pasa a binario solo el tipo y la longitud, el contenido en binario lo proporciona SnortUnified cuando se lee el registor
                        print $salida  pack('NN',$incidentes{$key}{primero}{TYPE},$incidentes{$key}{primero}{SIZE}).$incidentes{$key}{primero}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{primero_paquete}{TYPE},$incidentes{$key}{primero_paquete}{SIZE}).$incidentes{$key}{primero_paquete}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{ultimo}{TYPE},$incidentes{$key}{ultimo}{SIZE}).$incidentes{$key}{ultimo}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{ultimo_paquete}{TYPE},$incidentes{$key}{ultimo_paquete}{SIZE}).$incidentes{$key}{ultimo_paquete}{raw_record};


                        print $salida_plano "$incidentes{$key}{id_incidente}\t|\t$incidentes{$key}{n_eventos} \n";
		}
                #print (Dumper(%incidentes));
                closeSnortUnified();
                close($salida);
                close($salida_plano);
}

#Variables locales
my $directory = getcwd();  #Directorio actual por default
my $origin= ""; #????
my $log_dir = getcwd(); #Directorio actual por default
my $modo_continuo=0;
my $modo_batch=0;
my @files; #Para el modo batch
my $file=""; #Solo para un archivo

#Comprobamos para la ayuda
if($ARGV[0] eq '-h' || $ARGV[0] eq '--help'){
	print "\nAyuda\n";
}else{
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
				if($modo_continuo == 1)
				{
					print "Se activa el demonio";
				}
				else
				{
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
					my $cont=0;
					foreach(@files)
					{
						procesa_archivo($_,$log_directory,$directory,$cont);
						$cont++;
					}
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
