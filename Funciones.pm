#!/usr/bin/perl
use Proc::Daemon;
use Data::Dumper;
sub obtiene_incidentes
{
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my %incidentes = %{$argumentos[0]};
        my $file = $argumentos[1];
        my $id=$argumentos[2];
        my $contador;
        $UF_Data = openSnortUnified($file) or die "ERROR al abrir archivo";
        while ( $record = readSnortUnified2Record() )
                {
                        
                                #7               Unified2 IDS Event
                                #72              Unified2 IDS Event IP6
                                #si el registro es un evento
                        if($record->{TYPE} == 7 || $record->{TYPE} == 72)
                        {
                                $contador++;
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
                closeSnortUnified();
                print "se contaron $contador eventos \n";
       # print Dumper(%incidentes);
       print $id;
        return (\%incidentes,$id);


}
sub procesa_archivo{
	my @argumentos = @_;
	my $file = $argumentos[0];
	my $directory_log = $argumentos[1];
	my $directory = $argumentos[2];
	my $name_output_file = $argumentos[3];
        my $id=0;
         print "\nprocesando $file\n";
                @resultado=obtiene_incidentes(\%incidentes,$file,$id);
                $id=$resultado[1];
                %incidentes=%{$resultado[0]};
                        
        print "\nse proceso $file\n";
        imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);

	
}

sub demonio{

        #my $filename = shift;
        #print "Archivo: ".$filename;
        my $daemon = Proc::Daemon -> new(
                work_dir => '/home/jrevilla/Downloads/dcruz-jrevilla/',
                child_SDTOUT => 'salida.txt',
                child_STDERR => '+>>debug.txt',
                exec_command => 'perl /home/jrevilla/Downloads/dcruz-jrevilla/mejor_archivo.pl /home/dcruz-jrevilla/eventosgenerados'
                );

        my $pid = $daemon->Init();

}
sub procesa_lote{
        #$|=1;
        print "\n\nentro a lote sdsd";
        my $referenciaarch = shift;
        my @files = @{$referenciaarch};
       # print @files;
        #print "entro\n";
        #my $directory_log = $argumentos[1];
        #my $directory = $argumentos[2];
        #my $name_output_file = $argumentos[3];

        open (STDERR, '>>', $directory_log.'bitacora.log') or die "No se pudo abrir";       
        $incidentes_ref;
        @resultado;
        %incidentes=();
        $id=0;
        $posicion_final;
                foreach(@files)
                {
                        print "\nprocesando $_\n";
                       @resultado=obtiene_incidentes(\%incidentes,$_,$id);
                       $id=$resultado[1];
                       %incidentes=%{$resultado[0]};
                        
                         print "\nse proceso $_\n";

                }
        #imprime_incidentes(\%incidentes);
        return \%incidentes;

}

sub imprime_incidentes
{
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my %incidentes = %{$argumentos[0]};
        my $directory_log = $argumentos[1];
        my $directory = $argumentos[2];
        my $name_output_file = $argumentos[3];
        
        open($salida, '+>:unix',$directory.'/'.$name_output_file.'_unified2')or die "no se pudo abrir $!";
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
        print "lelgo aqui $posicion_final";
        #print (Dumper(%incidentes));
                
        close($salida);
        close($salida_plano);
}



1;