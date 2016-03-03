#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
$UF_Data = openSnortUnified(shift);
for(1..40)
{
	open($salida2, '>>:unix','parte1')or die "no se pudo abrir $!";
	$record = readSnortUnified2Record();
	print $salida2 pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	$record = readSnortUnified2Record();
	print $salida2 pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	close($salida2);

}
 while ( $record = readSnortUnified2Record() ) 

{
	open($salida, '>>:unix','parte2')or die "no se pudo abrir $!";
	print $salida pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	$record = readSnortUnified2Record();
	print $salida pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	close($salida);

	

}