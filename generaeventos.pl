#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
$UF_Data = openSnortUnified(shift);


open($salida, '>>:raw','eventosgenerados')or die "no se pudo abrir $!";
 while ( $record = readSnortUnified2Record() ) 
{
	open($salida, '>:raw','eventosgenerados')or die "no se pudo abrir $!";
	print $salida pack('NN',$record{TYPE},$record{SIZE}).$record{raw_record};
	$record = readSnortUnified2Record();
	print $salida pack('NN',$record{TYPE},$record{SIZE}).$record{raw_record};
	close($salida);

	sleep(30);

}