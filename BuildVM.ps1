<#
    .NOTES
	===========================================================================
	 Originally Created by:   	Syed Abdul Khader
     changes by:                Richard Tracy
	 Filename:     	            BuildVM.ps1
     Last Updated:              05/16/2019
	===========================================================================
	
    .DESCRIPTION
        Modify VM Advanced Setting 
    . PARAM

    . LINKs


 
#> 
##*===========================================================================
##* FUNCTIONS
##*===========================================================================
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {    
        return $psISE -ne $null;
    }
    catch {
        return $false;
    }
}

Function Get-ScriptPath {
    If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }

    # Makes debugging from ISE easier.
    if ($PSScriptRoot -eq "")
    {
        if (Test-IsISE)
        {
            $psISE.CurrentFile.FullPath
            #$root = Split-Path -Parent $psISE.CurrentFile.FullPath
        }
        else
        {
            $context = $psEditor.GetEditorContext()
            $context.CurrentFile.Path
            #$root = Split-Path -Parent $context.CurrentFile.Path
        }
    }
    else
    {
        #$PSScriptRoot
        $PSCommandPath
        #$MyInvocation.MyCommand.Path
    }
}

Function Format-ElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec.", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec.", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms.", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-DatePrefix{
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
    $CombinedDateTime = "$LogDate $LogTime"
    return ($LogDate + " " + $LogTime)
}

Function Write-LogEntry{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
		[string]$Source = '',
        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
	[int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
	[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
    #  Get the file name of the source script

    Try {
	    If ($script:MyInvocation.Value.ScriptName) {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
	    }
	    Else {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
	    }
    }
    Catch {
	    $ScriptSource = ''
    }
    
    
    If(!$Severity){$Severity = 1}
    $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }
    If($Outhost){
        If($Source){
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$Source,$Message)
        }
        Else{
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$ScriptSource,$Message)
        }

        Switch($Severity){
            0       {Write-Host $OutputMsg -ForegroundColor Green}
            1       {Write-Host $OutputMsg -ForegroundColor Gray}
            2       {Write-Warning $OutputMsg}
            3       {Write-Host $OutputMsg -ForegroundColor Red}
            4       {If($Global:Verbose){Write-Verbose $OutputMsg}}
            default {Write-Host $OutputMsg}
        }
    }
}

function Show-ProgressStatus
{
    <#
    .SYNOPSIS
        Shows task sequence secondary progress of a specific step
    
    .DESCRIPTION
        Adds a second progress bar to the existing Task Sequence Progress UI.
        This progress bar can be updated to allow for a real-time progress of
        a specific task sequence sub-step.
        The Step and Max Step parameters are calculated when passed. This allows
        you to have a "max steps" of 400, and update the step parameter. 100%
        would be achieved when step is 400 and max step is 400. The percentages
        are calculated behind the scenes by the Com Object.
    
    .PARAMETER Message
        The message to display the progress
    .PARAMETER Step
        Integer indicating current step
    .PARAMETER MaxStep
        Integer indicating 100%. A number other than 100 can be used.
    .INPUTS
         - Message: String
         - Step: Long
         - MaxStep: Long
    .OUTPUTS
        None
    .EXAMPLE
        Set's "Custom Step 1" at 30 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 100 -MaxStep 300
    
    .EXAMPLE
        Set's "Custom Step 1" at 50 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 150 -MaxStep 300
    .EXAMPLE
        Set's "Custom Step 1" at 100 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 300 -MaxStep 300
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string] $Message,
        [Parameter(Mandatory=$true)]
        [int]$Step,
        [Parameter(Mandatory=$true)]
        [int]$MaxStep,
        [string]$SubMessage,
        [int]$IncrementSteps,
        [switch]$Outhost
    )

    Begin{

        If($SubMessage){
            $StatusMessage = ("{0} [{1}]" -f $Message,$SubMessage)
        }
        Else{
            $StatusMessage = $Message

        }
    }
    Process
    {
        If($Script:tsenv){
            $Script:TSProgressUi.ShowActionProgress(`
                $Script:tsenv.Value("_SMSTSOrgName"),`
                $Script:tsenv.Value("_SMSTSPackageName"),`
                $Script:tsenv.Value("_SMSTSCustomProgressDialogMessage"),`
                $Script:tsenv.Value("_SMSTSCurrentActionName"),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSNextInstructionPointer")),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSInstructionTableSize")),`
                $StatusMessage,`
                $Step,`
                $Maxstep)
        }
        Else{
            Write-Progress -Activity "$Message ($Step of $Maxstep)" -Status $StatusMessage -PercentComplete (($Step / $Maxstep) * 100) -id 1
        }
    }
    End{
        Write-LogEntry $Message -Severity 1 -Outhost:$Outhost
    }
}

                              
##*===========================================================================
##* VARIABLES
##*===========================================================================
# Use function to get paths because Powershell ISE and other editors have differnt results
$scriptPath = Get-ScriptPath
[string]$scriptDirectory = Split-Path $scriptPath -Parent
[string]$scriptName = Split-Path $scriptPath -Leaf
[string]$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)

## Variables: App Deploy Script Dependency Files
[string]$ConfigDir = Join-Path -Path $scriptDirectory -ChildPath 'Configs'

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path $env:TEMP -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

# If not specified, defaults to ignore 'ISO' datastores
$IgnoreDatastores = "ISO|Templates"
##* ==============================
##* CONFIGS
##* ==============================
#grab variables from xml
$OSBuildConfigs = [Xml] (Get-Content "$ConfigDir\vmbuild.xml")
[System.Management.Automation.PSCredential]$vcsaCreds = Import-Clixml ("$ConfigDir\" + $($OSBuildConfigs.Settings.vcsa_infrastructure.credentials.secure_file))
[string]$vcsaServer       = $OSBuildConfigs.Settings.vcsa_infrastructure.server
[string]$vcsaFolder       = $OSBuildConfigs.Settings.vcsa_infrastructure.folder
[string]$ISOdatastore     = $OSBuildConfigs.Settings.vcsa_infrastructure.iso_datastore
[string]$viewURL          = $OSBuildConfigs.Settings.view_infrastructure.url
[string]$viewPool         = $OSBuildConfigs.Settings.view_infrastructure.pool
[string[]]$vmList         = $OSBuildConfigs.Settings.masterimages.vm
[string]$bootISO          = $OSBuildConfigs.Settings.masterimages.vm.iso

##*===========================================================================
##* MAIN
##*===========================================================================

Import-Module vmware.powercli
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -Scope AllUsers -Confirm:$false

# To connect to multiple vcenters, run Set-PowerCLIConfiguration -DefaultVIServerMode Multiple
Connect-VIServer $vcsaServer -Credential (Import-Clixml C:\vmware_creds.xml)
$SourceVC = Connect-VIServer $vcsaServer -Credential $vcsaCreds

#select source hosts and datastore used to clone template
$VMHosts = Get-VMHost -Server $SourceVC | Where-Object {$_.ConnectionState -match 'Connected' -and $_.PowerState -match 'PoweredOn'}

#get random VMhost
$ResourcePool = $VMHosts[(Get-Random -Maximum ($VMHosts).count)]

#get a datastore related to host
$DatastoreSearch = Get-Datastore -Server $SourceVC -RelatedObject $ResourcePool | Where-Object {$_.Name -match $SourceDatastore -and $_.Name -notmatch $IgnoreDatastores}
$SrcDatastore = $DatastoreSearch[(Get-Random -Maximum ($DatastoreSearch).count)]

#buid new VM
Foreach ($vm in $vmList | Select -ExpandProperty Name) 
{ 
    Try {
        $task = New-VM -Name $vm.Name -VM $TemplateName -ResourcePool $ResourcePool -Datastore $SrcDatastore -DiskStorageFormat Thin -Server $SourceVC -ErrorAction Stop -RunAsync
        Wait-Task -Task $task | Out-Null
        Write-Host ("{0} SUCCESS: Successfully cloned VM [{1}]" -f $SourceVCShortName, $CloneName) -ForegroundColor Green
    }
    Catch {
        Write-Host ("{0} ERROR: Failed to cloned VM [{1}]" -f $SourceVCShortName, $CloneName) -ForegroundColor Red
        Throw $_.Exception.Message
    }

    $date = get-Date -format "ddMMyy_HHmm" 
    Get-VM $vm.id | Get-AdvancedSetting | Select Name, Value | Export-CSV $vm"_Before_$date.csv" 
    
    #ESX/ESXi 4.0 to ESXi 5.0 provide .vmx options for VMCI isolation. As of ESXi 5.1, these options have no effect.
    New-AdvancedSetting -Entity $vm -Name vmci0.unrestricted -Value FALSE -Confirm:$False -Force:$True 

    #Remove unused devices
    New-AdvancedSetting -Entity $vm -Name floppyX.present -Value FALSE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name serialX.present -Value FALSE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name parallelX.present -Value FALSE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name ideX:Y.present -Value FALSE -Confirm:$False -Force:$True

    #STIG ITEMS :: Connecting and modifying devices
    New-AdvancedSetting -Entity $vm -Name isolation.device.connectable.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.device.edit.disable -Value TRUE -Confirm:$False -Force:$True 

    #V-39508
    New-AdvancedSetting -Entity $vm -Name vmsafe.enable -Value FALSE -Confirm:$False -Force:$True

    #Virtual Machine Communication Interface (VMCI)
    New-AdvancedSetting -Entity $vm -Name vmci0.unrestricted -Value FALSE -Confirm:$False -Force:$True

    #STIG ITEMS :: disable Copy and paste feature
    New-AdvancedSetting -Entity $vm -Name isolation.tools.copy.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.paste.disable -Value TRUE -Confirm:$False -Force:$True 
    
    #STIG ITEMS :: Disk shrinking feature
    New-AdvancedSetting -Entity $vm -Name isolation.tools.diskWiper.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.diskShrink.disable -Value TRUE -Confirm:$False -Force:$True 

    #STIG ITEMS :: Disk shrinking feature
    New-AdvancedSetting -Entity $vm -Name isolation.tools.setGUIOptions.enable -Value FALSE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.paste.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.copy.disable -Value TRUE -Confirm:$False -Force:$True 
    
    New-AdvancedSetting -Entity $vm -Name isolation.tools.trashFolderState.disable -Value TRUE -Confirm:$False -Force:$True 
    
    New-AdvancedSetting -Entity $vm -Name isolation.tools.bios.bbs.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.dispTopoRequest.disable -Value TRUE -Confirm:$False -Force:$True 

    New-AdvancedSetting -Entity $vm -Name isolation.tools.ghi.protocolhandler.info.disable -Value TRUE -Confirm:$False -For
    New-AdvancedSetting -Entity $vm -Name isolation.tools.ghi.lunchmenu.disable -Value TRUE -Confirm:$False -Force:$True ce:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.ghi.autologon.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.ghi.trayicon.disable -Value TRUE -Confirm:$False -Force:$True 
    
    #Disable Features not exposed in vSphere that could cause vulnerabilities
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unityInterlockOperation.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unity.taskbar.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unity.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unityActive.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unity.windowsContents.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unity.windows.Contents.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.unity.push.update.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.hgfsServerGet.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.memSchedFakeSampleState.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.getCreds.disable -Value TRUE -Confirm:$False -Force:$True 

    New-AdvancedSetting -Entity $vm -Name isolation.tools.vixMessage.disable -Value TRUE -Confirm:$False -Force:$True
    
    New-AdvancedSetting -Entity $vm -Name isolation.tools.device.connectable.disable -Value TRUE -Confirm:$False -Force:$True
    New-AdvancedSetting -Entity $vm -Name isolation.tools.device.edit.disable -Value TRUE -Confirm:$False -Force:$True

    New-AdvancedSetting -Entity $vm -Name isolation.tools.autoInstall.disable -Value TRUE -Confirm:$False -Force:$True 

    New-AdvancedSetting -Entity $vm -Name isolation.tools.vmx.DnDVersionGet.disable -Value TRUE -Confirm:$False -Force:$True 

    New-AdvancedSetting -Entity $vm -Name isolation.tools.guestDndVersionGet.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.tools.vmxDnDVersionGet.disable -Value TRUE -Confirm:$False -Force:$True 

    New-AdvancedSetting -Entity $vm -Name isolation.ghi.host.shellAction.disable -Value TRUE -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name isolation.bios.bbs.disable -Value TRUE -Confirm:$False -Force:$True
    
    #Set VMX file size
    New-AdvancedSetting -Entity $vm -Name tools.setinfo.sizeLimit -Value '1048576' -Confirm:$False -Force:$True
    
    #Disable Sending performance counters into PerfMon
    New-AdvancedSetting -Entity $vm -Name tools.guestlib.enableHostInfo -Value FALSE -Confirm:$False -Force:$True

    New-AdvancedSetting -Entity $vm -Name RemoteDisplay.maxConnections -Value '1' -Confirm:$False -Force:$True 
    New-AdvancedSetting -Entity $vm -Name RemoteDisplay.vnc.enable -Value FALSE -Confirm:$False -Force:$True 


    #$date = get-Date -format "ddMMyy_HHmm" 
    #Get-VM $vm| Get-AdvancedSetting | Select Name, Value | Export-CSV $vm"_After_$date.csv" 
    Start-VM -VM $vm 
}