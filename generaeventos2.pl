#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
$UF_Data = openSnortUnified(shift);


 while ( $record = readSnortUnified2Record() ) 
{
	open($salida, '>>:unix','/home/david/unifiedarch/dos')or die "no se pudo abrir $!";
	print $salida pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	$record = readSnortUnified2Record();
	print $salida pack('NN',$record->{TYPE},$record->{SIZE}).$record->{raw_record};
	close($salida);

	sleep(7);

}