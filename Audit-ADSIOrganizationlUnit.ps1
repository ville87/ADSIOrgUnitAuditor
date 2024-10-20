<#
.SYNOPSIS
    Script to audit ACEs of given OUs in Active Directory.

.DESCRIPTION
    
    This script searches for ACEs with GenericAll or CreateChild in the provided OU

    File-Name:  Audit-ADSIOrganizationlUnit.ps1
    Author:     Ville Koch (@vegvisir87, https://github.com/ville87)
    Version:    v1.1 (19.10.2024)

    TODO:
    - Add Parameter sets for better handling required parameters
    - Add parameters to further specify types of access control rights (other than GenericAll and CreateChilds)

.LINK
    https://github.com/ville87/ADSIOrgUnitAuditor

.EXAMPLE
    Run the script in the current domain user context and export the results to a CSV:
    .\Audit-ADSIOrganizationlUnit.ps1 -OUName newuserou -exportasCSV $true
#>

#################################### PARAMETERS ###########################################
[CmdletBinding()] 
Param (
    
    # OU to audit
    [Parameter(Mandatory = $true)]
    [string]$OUName,

    # domain: Domain to connect to. Should be in format domain.tld (currently no built-in validation)
    [Parameter(Mandatory=$false)]
    [string]$domain,

    # DCIP: DC IP address to use to connect to via 636
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if( -Not ([bool]($_ -as [ipaddress]))){
            throw "Provided DC IP is not a valid IP address"
        }
        return $true
    })]
    [string]$DCIP,

    # exportasCSV: If set to true, will export results as CSV file
    [Parameter(Mandatory=$false)]
    [bool]$exportasCSV = $false
)

Begin {
    
#################################### VARIABLES ###########################################

    [string]$scriptPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition;
    if($scriptPath -eq ''){ $scriptPath = (Get-Location).Path }
    $DebugPreference                 = "SilentlyContinue"

#################################### FUNCTIONS ###########################################
    function printInfo { 
        Param (
        [Parameter(Mandatory = $true)][string]$info, # String to log
        [Parameter(Mandatory = $true)][ValidateSet("INFO","WARNING","ERROR")][string]$level
        )
        if($level -eq "ERROR"){
            Write-Host -ForegroundColor Red -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }elseif($level -eq "WARNING"){
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }else{
            Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info"
        }
            
        if($loggingenabled){
            "$('[{0:HH:mm}]' -f (Get-Date)) - $level - $info" | Out-File -FilePath $logfilepath -Append
        }
    }

} # Begin

#################################### MAIN ################################################
Process {

    try {
        printInfo -info "Started script..." -level "INFO"
        $search = [adsisearcher]"(&(objectCategory=organizationalUnit)(name=$OUName))"
        Write-Debug "LDAP query specified: $($search.Filter)"
        if($domain -ne ""){
            Write-Debug "Domain $domain was specified by user"
            if($DCIP -eq ""){
                printInfo -info "Require DC IP address if specific domain is provided. Please start the script again and provide the parameter DCIP..." -level "ERROR"
                Exit
            }else{
                Write-Debug "DC IP  $DCIP was specified by user"
                printInfo -info "Checking connectivity to specified domain and domain controller..." -level "INFO"
                if(([System.Net.Sockets.TcpClient]::new().ConnectAsync("$DCIP", 636).Wait(1000)) -eq $false){ 
                    printInfo -info "Could not connect to $DCIP on port 636. Cannot continue..." -level "ERROR"
                    Exit
                }else{
                    printInfo -info "Connection succesful!" -level "INFO"
                }
                # Ask for credentials
                $Credentials = $host.ui.PromptForCredential("Need credentials for $domain", "Please enter user name and password for $domain.","","$domain")
                $searcherdomain = new-object DirectoryServices.DirectoryEntry("LDAP://$DCIP","$($credentials.username)", "$($Credentials.GetNetworkCredential().password)")
                $search.searchRoot = $searcherdomain
                Write-Debug "Search object loaded:`r`n$search"
            }
        }
        $search.PageSize = 10000
        $OUs = $search.FindAll()
        Write-Debug "Found $($OUs.Count) OUs:$OUs"
        $ACEObject = @()
        foreach($OU in $OUs){
            $ouDN = $OU.Properties["distinguishedName"]
            $adsiOU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ouDN")
            $DN = $adsiou | Select-Object -ExpandProperty distinguishedName
            Write-Debug "OU Distinguishedname: $DN"
            printInfo -info "Searching for ACEs with GenericAll or CreateChild in OU $DN..." -level "INFO"
            $securityDescriptor = $adsiOU.psbase.ObjectSecurity
            Write-Debug "Found $($securityDescriptor.count) Securitydescriptors"
            $acl = $securityDescriptor.Access
            $owner = $securityDescriptor.Owner
            foreach ($ace in $acl) {
                Write-Debug "checking ACE $ace"
                if((($ace.ActiveDirectoryRights -match "CreateChild") -or ($ace.ActiveDirectoryRights -match "GenericAll")) -and ($ace.AccessControlType -match "Allow")){
                    Write-Debug "Found ACE with CreateChild or GenericAll rights"
                    $data = [PSCustomObject]@{
                        OUIdentity = $ace.IdentityReference
                        OUACERight = $ace.ActiveDirectoryRights
                        OUInheritance = $ace.IsInherited
                        OUObjType = $ace.ObjectType
                        OUOwner = $owner
                        OUDistinguishedName = $DN
                    }
                    $ACEObject += $data
                }
            }
        }
        $ACECount = $ACEObject.count 
        printInfo -info "Found $ACECount relevant ACEs in OU $DN" -level "INFO"
        Write-host "Results:`r`n"
        $ACEObject | fl
        if($exportasCSV -eq $true){
            $ExportCSVPath = "$scriptPath\$(Get-Date -Format 'dd_MM_yyyy-HH_mm_ss')"+"-ADSIOrgUnitAuditor-Results.csv"
            $ACEObject | Export-Csv -NoTypeInformation -Path $ExportCSVPath -Force
            printInfo -info "Results exported to $ExportCSVPath" -level "INFO"
        }
        Write-host "############################################################################"
        Write-Debug "Loaded variables: "
        if($DebugPreference -like "Continue"){
            Get-ChildItem variable:
        }
        printInfo -info "Script done." -level "INFO"
        $ErrorLevel = 0        
    } catch {
        printInfo -info "There was an error when running the script. Error:`r`n$_" -level "ERROR"
    }
} # Process

End {
    if ($ErrorLevel -eq "0") {
        printInfo -info "Script ended succesfully" -level "INFO"
    }else{
        printInfo -info "Script ended with ErrorLevel: $ErrorLevel" -level "WARNING"
    }
} # End