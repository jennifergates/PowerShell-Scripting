<#
    .Synopsis
        This script compares two baseline files.
    .Description
        This script takes two baseline files created by Gates_enum-LocalMachine.ps1,
		compares them line by line, and writes the lines that differ to a file.
		
		Differing lines written to a file named Hostname_compared_yyyyMMdd_HHmmss.txt.
		
    .Example
        ./Gates_Compare-Enum.ps1 Hostname_compared_20170101_125022.txt  Hostname_compared_20171231_125022.txt 
		
    .Notes
        Exercise: 1. Compare baselines
        AUTHOR: Jennifer Gates
		
#>
#----------------------------------- Parameters  ---------------------------------------------->
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True,Position=1)]
		[string]$BaselineFile1,
	
	[Parameter(Mandatory=$True,Position=2)]
		[string]$BaselineFile2
)

#----------------------------------- Variables  ---------------------------------------------->
$daterun = $(get-date -Format "yyyyMMdd_HHmmss")
$hostname = "$env:computername"
$comparefile = "$($hostname)_compared_$($daterun).txt"

#----------------------------------- Functions  ---------------------------------------------->
function SplitText ($t) {
	
	$alldivs = $t.where({ $_ -like "---------------------------*"}, 'Split')  #returns all that match in array 0 and rest in array 1
	$alldivs = $alldivs[0]
	
	$x = 0
	$len = $alldivs.count
	$partp = @("") * $len
	$parts = @("") * $len
	
	
	while ($x -lt $len) {
		$partp[$x] = $t.where({ $_ -like "$($alldivs[$x])" }, 'Until')
		$x++
	}
	
	$c = 0
	while ($c -lt $len) {
		$parts[$c] = $partp[$c].where({ $_ -notin $partp[($c-1)]})
		$c++
	}
	
	return $parts
}

function CompareBaselines ($p1, $p2, $f1, $f2) {

	$ct = $p1.count
	$y =0
	$b1diffs = @()
	$b2diffs = @()
	
	while ($y -lt $ct) {
		$b1diffs += " "
		$b2diffs += " "
		$b1diffs += $p1[$y][0] # adds section header info
		$b2diffs += $p2[$y][0]

		switch ( compare-object $p1[$y] $p2[$y] -passthru )
		{
			{$_.sideindicator -eq "<=" } {$b1diffs += $_.tostring()}
			{$_.sideindicator -eq "=>" } {$b2diffs += $_.tostring()}
		}
		$y++
	}	
		"The following items were different in baseline file: $($f1)"
		"	"
		$b1diffs
		"============================================================================================================"
		" "
		"The following items were different in baseline file: $($f2)"
		"	"
		$b2diffs
		
		"============================================================================================================"

}

Function WriteHeader {
	"==========================================================================================================="
	"COMPARING BASELINE FILES:"
	"	Hostname:	$($hostname)"
	"	File 1:		$($BaselineFile1) "
	"	File 2:		$($BaselineFile2)"
	" 	Date Compared:	$($daterun)"
	"==========================================================================================================="
	" "
	" "
}

#----------------------------------- Script	    ---------------------------------------------->

$b1 = get-content $BaselineFile1 
$b2 = get-content $BaselineFile2 

$b1parts = SplitText($b1)
$b2parts = SplitText($b2)

WriteHeader | write-output |  out-file $comparefile  -encoding unicode 
CompareBaselines $b1parts $b2parts $BaselineFile1 $BaselineFile2 | write-output | out-file $comparefile  -encoding unicode -append
