#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
%incidentes=();
$id=0;

 while ( $record = readSnortUnified2Record() ) 
{
		#7               Unified2 IDS Event
		#72              Unified2 IDS Event IP6
	if($record->{TYPE} == 7 || $record->{TYPE} == 72)
	{
		if(exists($incidentes{$record->{'class'},$record->{'sip'},$record->{'protocol'}}))
		{
			$incidentes{$record->{'class'},$record->{'sip'},$record->{'protocol'}}{'n_eventos'}++;
			$incidentes{$record->{'class'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;

		}
		else
		{
			$incidentes{$record->{'class'},$record->{'sip'},$record->{'protocol'}}={'id_incidente' => ++$id,'n_eventos' => 1,'primero' => $record, 'ultimo' => $record}; 
		}
			#print "$record->{'class'} $record->{'sip'} $record->{'protocol'}\n";
			#$incidentes{$record->{'class'}}{$record->{'sip'}}{$record->{'protocol'}}++;
			#print("entro");
	}		
} 
foreach $key (keys %incidentes)
{
	print "key : $key  \n";
	for $dentro (keys $incidentes{$key})
	{
		print "$dentro  : $incidentes{$key}{$dentro}\n";
	}
}
#print (Dumper(%incidentes));
closeSnortUnified();


