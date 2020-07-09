import-module activedirectory;
$Arr = [System.Collections.ArrayList]@(,(0,0));
write-output "`n`n";
$usr = read-host "User";
$dom = read-host "Domain";

##############################################################################################################################
#
# replicated attributes first - query on any DC
#
##############################################################################################################################
write-output "`r`nReplicated attributes: ==========================================================================================================================";
$usrobj = $null;
$seap = $ErrorActionPreference;
$ErrorActionPreference = 'SilentlyContinue';
$CurErr = $error.count;
$usrobj = get-adobject -ldapfilter "samaccountname=$usr" -properties * -server $dom;
$ErrorActionPreference = $seap;
if ($CurErr -ne $error.count)
{
    write-host "Error fetching data for user '$usr' in '$dom'`r`n`nReason = $( $error[0].Exception.Message.ToString())";;
    exit;
}

if ($usrobj -eq $null)
{
    Write-Output "User '$usr' not found in '$dom'";
    exit;
}

write-host "";
write-host "givenname, sn       '$($usrobj.givenname)' '$($usrobj.sn)'";
write-host "displayname         '$($usrobj.displayname)'";
write-host "samAccountname      '$($usrobj.samaccountname)'";
write-host "userPrincipalName   '$($usrobj.userPrincipalName)'";
write-host "objectSID           '$($usrobj.objectSID)'";
write-host "sidHistory          '$($usrobj.sidHistory)'";
write-host "objectGUID          '$($usrobj.objectGUID)'";
write-host "Description         '$($usrobj.description)'";
write-host "title               '$($usrobj.title)'";
write-host "distinguishedName    $($usrobj.distinguishedName)";

$usraccctrl = $usrobj.userAccountControl;
        $uacstr = "";
        if ($usraccctrl -band 1) {$uacstr = "$uacstr Script";};
        if ($usraccctrl -band 2) {$uacstr = "$uacstr Disabled";};
        if ($usraccctrl -band 4) {$uacstr = "$uacstr Reserved";};
        if ($usraccctrl -band 8) {$uacstr = "$uacstr HomeDirReq";};
        if ($usraccctrl -band 16) {$uacstr = "$uacstr Locked";};
        if ($usraccctrl -band 32) {$uacstr = "$uacstr PwdNotReq";};
        if ($usraccctrl -band 64) {$uacstr = "$uacstr PwdCan'tChange";};
        if ($usraccctrl -band 128) {$uacstr = "$uacstr EncTxtPwdAllowed";};
        if ($usraccctrl -band 256) {$uacstr = "$uacstr TmpDuplAccount";};
        if ($usraccctrl -band 512) {$uacstr = "$uacstr Normal";};
        if ($usraccctrl -band 2048) {$uacstr = "$uacstr IntrDomTrust";};
        if ($usraccctrl -band 4096) {$uacstr = "$uacstr WorkstTrust";};
        if ($usraccctrl -band 8192) {$uacstr = "$uacstr ServerTrust";};
        if ($usraccctrl -band 65536) {$uacstr = "$uacstr NeverExpires";};
        if ($usraccctrl -band 131072) {$uacstr = "$uacstr MNSlogon";};
        if ($usraccctrl -band 262144) {$uacstr = "$uacstr SmartCardReq";};
        if ($usraccctrl -band 524288) {$uacstr = "$uacstr TrustDelg";};
        if ($usraccctrl -band 1048576) {$uacstr = "$uacstr NotDelg";};
        if ($usraccctrl -band 2097152) {$uacstr = "$uacstr UseDESkey";};
        if ($usraccctrl -band 4194304) {$uacstr = "$uacstr Don'tReqPreauth";};
        if ($usraccctrl -band 8388608) {$uacstr = "$uacstr PwdExpired";};
        if ($usraccctrl -band 16777216) {$uacstr = "$uacstr TrustedAuthDelg";};
        if ($usraccctrl -band 67108864) {$uacstr = "$uacstr RODC";};
write-host "Displayname         $($usrobj.displayname)";
write-host "userAccountControl  $($usrobj.useraccountcontrol) - $uacstr";
$TMPlastlogontimestamp = [datetime]::fromfiletime($usrobj.lastlogonTimestamp);
$TMPwhenCreated = $usrobj.whenCreated;
$TMPpwdLastSet = [datetime]::fromfiletime($usrobj.pwdLastSet);
$TMPaccountExpires = $usrobj.accountExpires;
if (($TMPaccountExpires -eq 0) -or ($TMPaccountExpires -eq 9223372036854775807))
{
    # Posebnost atributa accountExpires:
    # Ce je 0 ali 0x7FFFFFFFFFFFFFFF, potem to pomeni da ne potece usermame
    $TMPaccountExpires_str = "Never"
}
else
{
    # drugace pa priredim to, kar not pise
    $TMPaccountExpires_str = [datetime]::fromfiletime($TMPaccountExpires);
    $TMPaccountExpires_str = $TMPaccountExpires_str.ToString("dd-MM-yyyy HH:mm:ss");
}

write-host "lastLogonTimeStamp  $($TMPlastlogontimestamp.ToString("dd-MM-yyyy HH:mm:ss"))";
write-host "whenCreated         $($TMPwhenCreated.ToString("dd-MM-yyyy HH:mm:ss"))";
write-host "pwdLastSet          $($TMPpwdLastSet.ToString("dd-MM-yyyy HH:mm:ss"))";
write-host "accountExpires      $TMPaccountExpires_str";

##############################################################################################################################
#
# Non-replicated attributes - fetch data from every DC separately
#
##############################################################################################################################
write-output "`r`nNon-replicated attributes: ======================================================================================================================`r`n"
write-output "             domaincontroller             lastLogon       logonCount       whenChanged        badPasswordTime   badPwdCount   lockOutTime";
write-output "-----------------------------------  -------------------  ----------   -------------------  ------------------- -----------   -------------------";
$allDC = Get-ADDomainController -filter * -Server $dom;
foreach ($enDC in $allDC)
{
    $enDCcn = $enDC.hostname;
	#write-output "Querying $enDCcn...";
    $seap = $ErrorActionPreference;
    $ErrorActionPreference = 'SilentlyContinue';
    $CurErr = $error.count;
	$DCdataSet = get-adobject -ldapfilter "samaccountname=$usr" -properties * -server $enDCcn;
    if ($CurErr -ne $error.count)
    {
        write-output ("{0,35} {1,20}" -f $enDCcn, "*** unavailable ***");
    }
    else
    {
        $ErrorActionPreference = $seap;
	    $TMPlastlogon = [datetime]::fromfiletime($DCdataset.lastlogon);
    	$TMPwhenchanged = $DCdataset.whenchanged;
	    $TMPbadpwdtime = [datetime]::fromfiletime($DCdataset.badPasswordTime);
        $TMPlogonCount = $DCdataSet.logonCount;
        $TMPbadPwdCount = $DCdataset.badPwdCount;
        $TMPlockoutTime = [datetime]::fromfiletime($DCdataset.lockoutTime);

	    write-output ("{0,35} {1,20} {2,11}  {3,20}  {4,11}  {5,10}  {6,20}"   `
                    -f $enDCcn,                                                `
                       $TMPlastlogon.ToString("dd-MM-yyyy HH:mm:ss"),          `
                       $TMPlogonCount,                                         `
                       $TMPwhenchanged.ToString("dd-MM-yyyy HH:mm:ss"),        `
                       $TMPbadpwdtime.ToString("dd-MM-yyyy HH:mm:ss"),         `
                       $TMPbadPwdCount,                                        `
                       $TMPlockoutTime.ToString("dd-MM-yyyy HH:mm:ss"));
    }
}
write-output "-----------------------------------  -------------------  ----------   -------------------  ------------------- -----------   -------------------";
write-output "`n";
