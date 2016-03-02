#!/usr/bin/perl

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

1;