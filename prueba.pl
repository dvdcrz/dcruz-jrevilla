#!/usr/bin/perl
use SnortUnified(qw(:ALL)); 
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
%incidentes;
 while ( $record = readSnortUnified2Record() ) 
{

} 
closeSnortUnified();
