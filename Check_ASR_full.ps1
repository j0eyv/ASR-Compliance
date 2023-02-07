##ASR Rule Reference
#ASR1: Block abuse of exploited vulnerable signed drivers	- 56a863a9-875e-4185-98a7-b882c64b5ce5
#ASR2: Block Adobe Reader from creating child processes - 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
#ASR3: Block all Office applications from creating child processes - d4f940ab-401b-4efc-aadc-ad5f3c50688a
#ASR4: Block credential stealing from the Windows local security authority subsystem (lsass.exe) - 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
#ASR5: Block executable content from email client and webmail - be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
#ASR6: Block executable files from running unless they meet a prevalence, age, or trusted list criterion - 01443614-cd74-433a-b99e-2ecdc07bfc25
#ASR7: Block execution of potentially obfuscated scripts - 5beb7efe-fd9a-4556-801d-275e5ffc04cc
#ASR8: Block JavaScript or VBScript from launching downloaded executable content - d3e037e1-3eb8-44c8-a917-57927947596d
#ASR9: Block Office applications from creating executable content - 3b576869-a4ec-4529-8536-b80a7769e899
#ASR10: Block Office applications from injecting code into other processes - 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
#ASR11: Block Office communication application from creating child processes - 26190899-1602-49e8-8b27-eb1d0a1ce869
#ASR12: Block persistence through WMI event subscription - e6db77e5-3df2-4cf1-b95a-636979351e5b
#ASR13: Block process creations originating from PSExec and WMI commands - d1e49aac-8f56-4280-b9ba-993a6d77406c
#ASR14: Block untrusted and unsigned processes that run from USB - b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
#ASR15: Block Win32 API calls from Office macros - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
#ASR16: Use advanced protection against ransomware - c1db55ab-c21a-4637-bb3f-a12568109d35

#ASR1
$GetASR1 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value1 = "56a863a9-875e-4185-98a7-b882c64b5ce5"

If ($GetASR1 -contains $Value1){
$Value1 = "1"
} 
else
{
$Value1 = "0"
}

#ASR2
$GetASR2 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value2 = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

If ($GetASR2 -contains $Value2){
$Value2 = "1"
} 
else
{
$Value2 = "0"
}

#ASR3
$GetASR3 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value3 = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"

If ($GetASR3 -contains $Value3){
$Value3 = "1"
} 
else
{
$Value3 = "0"
}

#ASR4
$GetASR4 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value4 = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

If ($GetASR4 -contains $Value4){
$Value4 = "1"
} 
else
{
$Value4 = "0"
}

#ASR5
$GetASR5 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value5 = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

If ($GetASR5 -contains $Value5){
$Value5 = "1"
} 
else
{
$Value5 = "0"
}

#ASR6
$GetASR6 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value6 = "01443614-cd74-433a-b99e-2ecdc07bfc25"

If ($GetASR6 -contains $Value6){
$Value6 = "1"
} 
else
{
$Value6 = "0"
}

#ASR7
$GetASR7 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value7 = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"

If ($GetASR7 -contains $Value7){
$Value7 = "1"
} 
else
{
$Value7 = "0"
}

#ASR8
$GetASR8 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value8 = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"

If ($GetASR8 -contains $Value8){
$Value8 = "1"
} 
else
{
$Value8 = "0"
}

#ASR9
$GetASR9 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value9 = "3b576869-a4ec-4529-8536-b80a7769e899"

If ($GetASR9 -contains $Value9){
$Value9 = "1"
} 
else
{
$Value9 = "0"
}

#ASR10
$GetASR10 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value10 = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

If ($GetASR10 -contains $Value10){
$Value10 = "1"
} 
else
{
$Value10 = "0"
}

#ASR11
$GetASR11 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value11 = "26190899-1602-49e8-8b27-eb1d0a1ce869"

If ($GetASR11 -contains $Value11){
$Value11 = "1"
} 
else
{
$Value11 = "0"
}

#ASR12
$GetASR12 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value12 = "e6db77e5-3df2-4cf1-b95a-636979351e5b"

If ($GetASR12 -contains $Value12){
$Value12 = "1"
} 
else
{
$Value12 = "0"
}

#ASR13
$GetASR13 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value13 = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

If ($GetASR13 -contains $Value13){
$Value13 = "1"
} 
else
{
$Value13 = "0"
}

#ASR14
$GetASR14 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value14 = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

If ($GetASR14 -contains $Value14){
$Value14 = "1"
} 
else
{
$Value14 = "0"
}

#ASR15
$GetASR15 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value15 = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

If ($GetASR15 -contains $Value15){
$Value15 = "1"
} 
else
{
$Value15 = "0"
}

#ASR16
$GetASR16 = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$Value16 = "c1db55ab-c21a-4637-bb3f-a12568109d35"

If ($GetASR16 -contains $Value16){
$Value16 = "1"
} 
else
{
$Value16 = "0"
}

$hash = @{ ASR1 = $value1; ASR2 = $Value2;ASR3 = $Value3; ASR4 = $Value4; ASR5 = $Value5; ASR6 = $Value6; ASR7 = $Value7; ASR8 = $Value8; ASR9 = $Value9; ASR10 = $Value10; ASR11 = $Value11; ASR12 = $Value12; ASR13 = $Value13; ASR14 = $Value14; ASR15 = $Value15; ASR16 = $Value16}
return $hash | ConvertTo-Json -Compress