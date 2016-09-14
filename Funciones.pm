#!/usr/bin/perl
use strict;
use Proc::Daemon;
use Data::Dumper;
=pod

=head1 MODULO CON LAS FUNCIONES PRINCIPALES DE GENINC

=cut

=head2 Funcion ------->  obtiene_incidentes

Recibe una referencia dehash ,un nombre de archivo y un id , se abre el archivo indicado y se cuentan los 
eventos tipo 7 y 72 y los agrupa en incidentes dentro del hash recibido.

=cut 

#obtine_inccidentes recibe una referencia dehash ,un nombre de archivo y un id , se abre el archivo indicado y se cuentan los 
#eventos tipo 7 y 72 y los agrupa en incidentes dentro del hash recibido
sub obtiene_incidentes
{
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my %incidentes = %{$argumentos[0]};
        my $file = $argumentos[1];
        my $id=$argumentos[2];
        my $contador;
        my $UF_Data = openSnortUnified($file) or die "ERROR al abrir archivo";
        while ( my $record = readSnortUnified2Record() )
                {
			#print Dumper($record);
                        
                                #7               Unified2 IDS Event
                                #72              Unified2 IDS Event IP6
                                #si el registro es un evento
                        if($record->{TYPE} == 7 || $record->{TYPE} == 72)
                        {
                                my $paquete;
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
					#print Dumper($paquete);
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
       
       print $id;
        return (\%incidentes,$id);


}

=head2 Funcion -------->  procesa_archivo

Recibe un nombre de archivo un directorio para escibir al log un directorio y nombre de salida llama a obtien incidentes 
y con el hash obtenido llama a imprime incidentes que se encarga de deplegar la informaicon.

=cut


#procesa archivo  recibe un nombre de archivo un directorio para escibir al log un directorio y nombre de salida
#llama a obtien incidentes y con el hash obtenido llama a imprime incidentes que se encarga de deplegar la informaicon
sub procesa_archivo{
	my @argumentos = @_;
	my $file = $argumentos[0];
	my $directory_log = $argumentos[1];
	my $directory = $argumentos[2];
	my $name_output_file = $argumentos[3];
	my %incidentes;
        my $id=0;
         print "\nprocesando $file\n";
                my @resultado=obtiene_incidentes(\%incidentes,$file,$id);
                $id=$resultado[1];
                %incidentes=%{$resultado[0]};
                        
        print "\nse proceso $file\n";
        imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);

	
}

=head2 Funcion -------> demonio

La funcion demonio recibe un directorio de log, directorio de salida, nombre de archivo de salida y nombre de archivo
se inicializa un demonio que dentro de un loop obiene los incidentes y los imprime cada 30 seg.

=cut

#demonio, el demonio recibe un directorio de log, directorio de salida, nombre de archivo de salida y nombre de archivo
#se inicializa un demonio que dentro de un loop obiene los incidentes y los imprime cada 30 seg
sub demonio{
        my @argumentos = @_;
        #print Dumper(@argumentos); 
        my $directory_log = $argumentos[0];
        my $directory = $argumentos[1];
        my $name_output_file = $argumentos[2];
        my $file = $argumentos[3];
        #my $filename = shift;
        #print "Archivo: ".$filename;
        #preconfiguracion del demonio
        my $daemon = Proc::Daemon -> new(
                work_dir => $directory,
                child_SDTOUT => '+>>salida.txt',
                child_STDERR => '+>>debug.txt',
                
                );
        #inicializacion del demonio
        my $pid = $daemon->Init;
        my $id=0;
        my %incidentes;
        my @resultado;
        #se obtiene el tamaño actual de archivo
        my $file_size_act = -s $file;
        my $file_size_ant = 0;
        #$|=1;
        print "se incio con $pid";
        while (1)
        {
                print "archivo $file id $id  tamño $file_size_act\n";
                open (my $bitacora, '>>', 'bitacora.log') or die "No se pudo abrir";
                #si el tamaño a cambiado
                if($file_size_act != $file_size_ant)
                {
                        print $bitacora "\n--->Entro en el if";
                        print $bitacora "\nTam actual en if: ".$file_size_act;
                        print $bitacora "\nTam Anterior en if: ".$file_size_ant."\n";
                        #gactualiza el hash con la informaicon nueva
                        @resultado=obtiene_incidentes(\%incidentes,$file,$id);
                        $id=$resultado[1];
                        %incidentes=%{$resultado[0]};
                        imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);
                }
                #recalcula el tamaño del archvio
                $file_size_ant = $file_size_act;
                $file_size_act = -s $file;
                print $bitacora "\n----------------------------------------------------";
                print $bitacora "\nTam actual : ".$file_size_act;
                print $bitacora "\nTam Anterior : ".$file_size_ant."\n";
                close($bitacora);
                #esoera 30 seg
                sleep(30);
        }

}

=head2 Funcion -------> procesa_lote

Recibe una referencia a un arreglo que contiene los nombres de los archivos a procesar se llama a obtiene incidente 
y se actualiza el hash, regresa una referencia a un  hash con los incidentes de los 3 archivos.

=cut

#procesa_lote recibe una referencia a un arreglo que contiene los nombres de los archivos a procesar
#se llama a obtiene incidente y se actualiza el hash, regresa una referencia a un  hash con los incidentes de los 3 archivos
sub procesa_lote{
        #$|=1;
        print "\n\nentro a lote sdsd";
        my $referenciaarch = shift;
        my @files = @{$referenciaarch};
        my $directory_log = shift;
       # print @files;
        #print "entro\n";
        #my $directory_log = $argumentos[1];
        #my $directory = $argumentos[2];
        #my $name_output_file = $argumentos[3];

        open (STDERR, '>>', $directory_log.'bitacora.log') or die "No se pudo abrir";       
        my $incidentes_ref;
        my @resultado;
        my %incidentes=();
        my $id=0;
        my $posicion_final;
                #recorres el arreglo y obtiene incidentes de cada archivo
                foreach(@files)
                {
                        print "\nprocesando $_\n";
                       @resultado=obtiene_incidentes(\%incidentes,$_,$id);
                       $id=$resultado[1];
                       %incidentes=%{$resultado[0]};
                        
                         print "\nse proceso $_\n";

                }
        #imprime_incidentes(\%incidentes);
        #retorna referencia a hash
        return \%incidentes;

}

=head2 Funcion -------> imprime_incidentes

Imprime los incidentes que recibe de una referencia de hash, aqui se imprime el resument a un texto plano
los eventos y sus paquetes se escriben en un archivo unified2.

=cut

#imprime los incidentes que recibe de una referencia de hash, aqui se imprime el resument a un texto plano
#los eventos y sus paquetes se escriben en un archivo unified2
sub imprime_incidentes
{
        my @argumentos = @_;
        #print Dumper(@argumentos);
        my %incidentes = %{$argumentos[0]};
        my $directory_log = $argumentos[1];
        my $directory = $argumentos[2];
        my $name_output_file = $argumentos[3];
       
        #open(my $salida, '+>:unix',$directory.'/'.$name_output_file.'_unified2')or die "no se pudo abrir $!";
        open(my $salida_plano, '+>',$directory.'/'.$name_output_file.'_plano')or die "no se pudo abrir $!";
 
        #se iteran en el hash de incidentes
        print $salida_plano "ID_incidente\tSeparador\tN_eventos\n";
 
        #recorremos el hash donde cada llave es un incidente
        foreach my $key (keys %incidentes)
        {
            open(my $salida, '+>:unix',$directory.'/'.$incidentes{$key}{id_incidente}.'-'.$incidentes{$key}{primero}{protocol}.'-'.$incidentes{$key}{primero}{sig_id}.'.'.$name_output_file)or die "no se pudo abrir $!";
                        #pasa a binario solo el tipo y la longitud, el contenido en binario lo proporciona SnortUnified cuando se lee el registro
                        print $salida  pack('NN',$incidentes{$key}{primero}{TYPE},$incidentes{$key}{primero}{SIZE}).$incidentes{$key}{primero}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{primero_paquete}{TYPE},$incidentes{$key}{primero_paquete}{SIZE}).$incidentes{$key}{primero_paquete}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{ultimo}{TYPE},$incidentes{$key}{ultimo}{SIZE}).$incidentes{$key}{ultimo}{raw_record};
                        print $salida  pack('NN',$incidentes{$key}{ultimo_paquete}{TYPE},$incidentes{$key}{ultimo_paquete}{SIZE}).$incidentes{$key}{ultimo_paquete}{raw_record};
 
            close($salida);
                        print $salida_plano "$incidentes{$key}{id_incidente}\t|\t$incidentes{$key}{n_eventos} \n";
        }
        print "llego aqui";
        #print (Dumper(%incidentes));
               
        #close($salida);
        close($salida_plano);
}

=head2 Funcion -------> obtener_archivos

Recibe un nombre de directorio y regresa un arreglo con todos los nombres de los archivos.

=cut

#obteber_archivos recibe un nombre de directorio y regresa un arreglo con todos los nombres de los archivos

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

=head2 Funcion --------> demonio_batch

Recibe directorio de logs y salida, nombre de archiivo de salida y un directorio de origen, se obtienne todos los 
archivos de origen con obtener archibvos, se crea un hash que contiene el tamaño actual y anterior de cada archivo, 
en un loop se comprueba si ha cmabiado el tamño del archivo, de ser asi se procesa el contenido del archivo y se
reescriben los archivos de salida.

=cut


#demonio_batch  recibe directorio de logs y salida, nombre de archiivo de salida y un directorio de origen
#se obtienne todos los archivos de origen con obtener archibvos, se crea un hash que contiene el tamaño actual y anterior
#de cada archivo, en un loop se comprueba si ha cmabiado el tamño del archivo, de ser asi se procesa el contenido del archivo y se
# reescriben los archivos de salida
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
        #$|=1;
        my $pid = $daemon->Init;
        #creacion de hash de archivos
        my @archivos = obtener_archivos($origin);
        my %tamanio_archivo;
        my $tam = @archivos;
        print "tamaño $tam";
        #creaccion de hash donde la llave es le nombre del archvio, se agrega el tamaño
        foreach  (@archivos)
        {
            print $_;
            $tamanio_archivo{$_}={'file_size_act' => -s $_,'file_size_ant' => 0 };

        }

        my $id=0;
        my %incidentes;
        my @resultado;
        #my $file_size_act = -s $file;
        #my $file_size_ant = 0;
        #$|=1;
        print "se incio con $pid";
        while (1)
        {
                #print "archivo $file id $id  tamño $file_size_act\n";
                open (my $bitacora, '>>', 'bitacora.log') or die "No se pudo abrir";
                #se recorre el hash de archivos verificando si hay algun cambio, de ser asi se procesa el archivo
                foreach my $key(keys %tamanio_archivo)
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
                #cuando se terminan de procesar todos los archivos con cambios se escriben los archivos de salida
                imprime_incidentes(\%incidentes,$directory_log,$directory,$name_output_file);

                #se recalcula el tamaño de los archivos
                foreach my $key(keys %tamanio_archivo)
                {
                    $tamanio_archivo{$key}{'file_size_ant'} = $tamanio_archivo{$key}{'file_size_act'};
                    $tamanio_archivo{$key}{'file_size_act'} = -s $key;

                    print $bitacora "\n----------------------------------------------------";
                    print $bitacora "\nTam actual : ".$tamanio_archivo{$key}{'file_size_act'};
                    print $bitacora "\nTam Anterior : ".$tamanio_archivo{$key}{'file_size_ant'}."\n";
                }
               

            
                close($bitacora);
                #se esperan 30 seg para el siguiente ciclo
                sleep(30);
        }

}

1;
