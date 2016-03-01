use SnortUnified(qw(:ALL)); 
UF_Data = openSnortUnified(shift);


open($salida, '>:raw','eventosgenerados')or die "no se pudo abrir $!";
 while ( $record = readSnortUnified2Record() ) 
{
	open($salida, '>:raw','eventosgenerados')or die "no se pudo abrir $!";
	print salida pack('NN',$record{TYPE},$record{SIZE}).$record{raw_data};
	$record = readSnortUnified2Record();
	print salida pack('NN',$record{TYPE},$record{SIZE}).$record{raw_data};
	close($salida);

	sleep(30);

}