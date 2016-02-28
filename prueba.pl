#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
%incidentes;
 while ( $record = readSnortUnified2Record() ) 
{
	if($record{'TYPE'} == 7)
	{
			$incidentes{$record{'class'}}{$record{'sip'}}{$record{'protocol'}}++;
	}		
} 
print (Dumper(%incidentes))
closeSnortUnified();


