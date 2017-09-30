$computerobj1 = import-clixml c:\users\gates\documents\cctc\objectify.xml
$computerobj2 = import-clixml c:\users\gates\documents\cctc\objectify3.xml
$computertxt1 = get-content c:\users\gates\documents\cctc\objectify.txt
$computertxt2 = get-content c:\users\gates\documents\cctc\objectify3.txt
#$computerobj2 | gm
compare-object $computertxt1 $computertxt2 | ?{$_.sideIndicator -eq "=>"} | select inputobject
compare-object $computertxt1 $computertxt2 | ?{$_.sideIndicator -eq "<="} | format-table

foreach ( $noteproperty in $computerobj1.psobject.properties) {
	"`n$($noteproperty.name)"
	"`n------------------------------------------------------------------------------`n"
	#$computerobj1.$($noteproperty.name) 
	$test1 = $computerobj1.$($noteproperty.name)
	$test2 = $computerobj2.$($noteproperty.name)
	
	#$test1 | format-table 
	#$test2  | format-table
	#compare-object  $($test1arr) $($test2arr) | ?{$_.sideIndicator -eq "=>"} | select inputobject

	#$results = compare-object  $test1arr $test2arr| ?{$_.sideIndicator -eq "<="} |select inputobject
	#$results = compare-object  $test1arr $test2arr   -passthru
	#$results | format-table *
	
<# 	Switch ($results) {
		#{$_.sideindicator -eq "<=" } {"`t$($_.tostring()) is in objectify"}
		{$_.sideindicator -eq "<=" } {[String]::Join("`n", $_) }
		{$_.sideindicator -eq "=>" } {$_.inputobject}
	} #> 
} 