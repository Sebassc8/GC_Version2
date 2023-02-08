#!/bin/bash


for verilogfile in /home/soler/FerretOT/emp-ot/testing/scd/netlists/*.v
do
  scdfile=${verilogfile%.*}.scd
  /home/soler/FerretOT/emp-ot/testing/scd/V2SCD_Main -i $verilogfile -o $scdfile --log2std &
done
wait
