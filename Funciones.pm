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
                                
                                #si el incidente ya existe en el hash de eventos se agrega 1 al contador y se sobre escribe registro ultimo
                                if(exists($incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}))
                                {
                                        if(exists($incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'eventos'}{$record->{'event_id'}})){next};
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'n_eventos'}++;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;
                                        #suponiendo que snort siempre escribe el los eventos en un orden evento,paquete,evento
                                        # obtenemos el paquete correspondiente al evento
                                        $paquete = readSnortUnified2Record();
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paquete'} = $paquete;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'eventos'}{$record->{'event_id'}}=1;
                                }
                                else
                                {
                                        #si no existe el incidente se crea con el eventeo primero ultimo iguales
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}={'id_incidente' => ++$id,'n_eventos' => 1,'primero' => $record, 'ultimo' => $record};
                                        $paquete = readSnortUnified2Record();
                                        #los dos comparten el mismo paquete 
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primero_paquete'} = $paquete;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paquete'} = $paquete;
                                        $incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'eventos'}{$record->{'event_id'}}=1;
                                }
                                        #print "$record->{'class'} $record->{'sip'} $record->{'protocol'}\n";
                                        #$incidentes{$record->{'class'}}{$record->{'sip'}}{$record->{'protocol'}}++;
                                        #print("entro");
                                        $contador++;
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
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my $directory_log = $argumentos[0];
        my $directory = $argumentos[1];
        my $name_output_file = $argumentos[2];
        my $file = $argumentos[3];
        #my $filename = shift;
        #print "Archivo: ".$filename;
        my $daemon = Proc::Daemon -> new(
                work_dir => $directory,
                child_SDTOUT => '+>>salida.txt',
                child_STDERR => '+>>debug.txt',
                
                );

        my $pid = $daemon->Init;
        my $id=0;
        my %incidentes;
        my @resultado;
        my $file_size_act = -s $file;
        my $file_size_ant = 0;
        $|=1;
        print "se incio con $pid";
        while (1)
        {
                print "archivo $file id $id  tamño $file_size_act\n";
                open ($bitacora, '>>', 'bitacora.log') or die "No se pudo abrir";

                if($file_size_act != $file_size_ant)
                {
                        print $bitacora "\n--->Entro en el if";
                        print $bitacora "\nTam actual en if: ".$file_size_act;
                        print $bitacora "\nTam Anterior en if: ".$file_size_ant."\n";
                        @resultado=obtiene_incidentes(\%incidentes,$file,$id);
                        $id=$resultado[1];
                        %incidentes=%{$resultado[0]};
                        imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);
                }

                $file_size_ant = $file_size_act;
                $file_size_act = -s $file;
                print $bitacora "\n----------------------------------------------------";
                print $bitacora "\nTam actual : ".$file_size_act;
                print $bitacora "\nTam Anterior : ".$file_size_ant."\n";
                close($bitacora);
                sleep(30);
        }

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

sub obtener_archivos{
    my $directorio = shift;
    if($directorio !~ /.*\/$/){  #Agregamos una / si no acaba para concatenar el nombnre del archivo
        $directorio = $directorio."/";
    }
        opendir (DIR,$directorio) or die "No se pudo abrir el directorio";
        my @files;
        while(readdir(DIR)){
                if($_ !~  /^\..*/){ push @files,$_; }
        }
        closedir (DIR);
    #Concatenamos el directorio a los archivos.
    foreach(@files){
        $_ = $directorio.$_;
    }
        return @files;
}

sub demonio_batch{
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my $directory_log = $argumentos[0];
        my $directory = $argumentos[1];
        my $name_output_file = $argumentos[2];
        my $origin = $argumentos[3];
        #my $filename = shift;
        #print "Archivo: ".$filename;
        my $daemon = Proc::Daemon -> new(
                work_dir => $directory,
                child_SDTOUT => '+>>salida.txt',
                child_STDERR => '+>>debug.txt',
                
                );

        my $pid = $daemon->Init;
        #creacion de hash de archivos
        my @archivos = obtener_archivos($origin);
        my %tamanio_archivo;
        foreach  (@archivos)
        {
            $tamanio_archivo{$_}={'file_size_act' => -s $_,'file_size_ant' => 0 };

        }

        my $id=0;
        my %incidentes;
        my @resultado;
        #my $file_size_act = -s $file;
        #my $file_size_ant = 0;
        $|=1;
        print "se incio con $pid";
        while (1)
        {
                print "archivo $file id $id  tamño $file_size_act\n";
                open ($bitacora, '>>', 'bitacora.log') or die "No se pudo abrir";
                foreach $key(keys %tamanio_archivo)
                {
                     if($tamanio_archivo{$key}{'file_size_act'} != $tamanio_archivo{$key}{'file_size_ant'} )
                    {
                        print $bitacora "\n--->Entro en el if";
                        print $bitacora "\nTam actual en if: ".$tamanio_archivo{$key}{'file_size_act'};
                        print $bitacora "\nTam Anterior en if: ".$tamanio_archivo{$key}{'file_size_ant'}."\n";
                        @resultado=obtiene_incidentes(\%incidentes,$key,$id);
                        $id=$resultado[1];
                        %incidentes=%{$resultado[0]};
                        
                    }
                }
                imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);

                foreach $key(keys %tamanio_archivo)
                {
                    $tamanio_archivo{$key}{'file_size_ant'} = $tamanio_archivo{$key}{'file_size_act'};
                    $tamanio_archivo{$key}{'file_size_act'} = -s $key;

                    print $bitacora "\n----------------------------------------------------";
                    print $bitacora "\nTam actual : ".$tamanio_archivo{$key}{'file_size_act'};
                    print $bitacora "\nTam Anterior : ".$tamanio_archivo{$key}{'file_size_ant'}."\n";
                }
               

            
                close($bitacora);
                sleep(30);
        }

}

1;
