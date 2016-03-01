#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
%incidentes=();
$id=0;
#se lee eel archivo en busca de eventos y se generan incidentes mediante uso de un hash de hashes
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


		}
		else
		{
			#si no existe el incidente se crea con el eventeo primero ultimo iguales
			$incidentes{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}={'id_incidente' => ++$id,'n_eventos' => 1,'primero' => $record, 'ultimo' => $record}; 
		}
			#print "$record->{'class'} $record->{'sip'} $record->{'protocol'}\n";
			#$incidentes{$record->{'class'}}{$record->{'sip'}}{$record->{'protocol'}}++;
			#print("entro");
	}		
} 
open($salida, '>:raw','salidaunified2')or die "no se pudo abrir $!";
open($salida_plano, '>','salidaplano')or die "no se pudo abrir $!";

#se iteran en el hash de incidentes
print $salida_plano "ID_incidente\tSeparador\tN_eventos\n";

foreach $key (keys %incidentes)
{

	if($incidentes{$key}{primero}{TYPE} == 7)
	{
		#print "entro \n";
		#print $salida pack('N11n2c2',$incidentes{$key}{primero}{TYPE},$incidentes{$key}{primero}{SIZE},$incidentes{$key}{primero}{raw_record});
		#print $salida pack('NNN11n2c2',$incidentes{$key}{primero}{TYPE},$incidentes{$key}{primero}{SIZE},$incidentes{$key}{primero}{raw_record});

		#pasa a binario solo el tipo y la longitud, el contenido en binario lo proporciona SnortUnified cuando se lee el registor
		print $salida  pack('NN',$incidentes{$key}{primero}{TYPE},$incidentes{$key}{primero}{SIZE}).$incidentes{$key}{primero}{raw_record};
		print $salida_plano "$incidentes{$key}{id_incidente}\t|\t$incidentes{$key}{n_eventos} \n";
	}
	
	#print "key : $key  \n";
	for $dentro (keys $incidentes{$key})
	{
	#	print "$dentro  : $incidentes{$key}{$dentro}\n";
	}
}
#print (Dumper(%incidentes));
closeSnortUnified();
close($salida);
close($salida_plano);


