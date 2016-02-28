#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
%incidentes=();

 while ( $record = readSnortUnified2Record() ) 
{

	#print($record->{'TYPE'});
	#print($record->$TYPE);

	if($record->{TYPE} == 7)
	{
			$incidentes{$record->{'class'}}{$record->{'sip'}}{$record->{'protocol'}}++;
			#print("entro");
	}		
} 
print (Dumper(%incidentes));
closeSnortUnified();


