


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
$VMImages     = $OSBuildConfigs.Settings.masterimages
#[string]$bootISO     = $OSBuildConfigs.Settings.masterimage.vm.iso

##*===========================================================================
##* MAIN
##*===========================================================================

Import-Module vmware.powercli
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -Scope AllUsers -Confirm:$false


# To connect to multiple vcenters, run Set-PowerCLIConfiguration -DefaultVIServerMode Multiple
#Connect-VIServer vcsamgmt.s3i.org -Credential (Import-Clixml C:\vmware_creds.xml)
$SourceVC = Connect-VIServer $vcsaServer -Credential $vcsaCreds


#For each vm in list; Get VM details
foreach ($vm in $VMImages.vm) {
    #check if master image exists
    $masterVM = Get-VM -Name $vm.name -Server $vcsaServer -ErrorAction SilentlyContinue
    
    
    

    #Found vm in venter: do action
    If($masterVM)
    {
        #make sure the state of the VM is off
        If($masterVM.PowerState -eq 'PoweredOn'){
            #shutdown VM gracefully of VMtools installed
            if ( (Get-VMGuest -VM $masterVM).State -eq 'NotRunning') {
                $masterVM | Stop-VM -Confirm:$false
            }
            Else{
                $masterVM | Shutdown-VMGuest -confirm:$false
            }
        }

        ## get the .NET View object for the VM, with a couple of select properties
        $viewVM = Get-VM $masterVM | Get-View

        switch($vm.bootup){
            
            "ISO"       {
                        If( $vm.iso -ne $null ){
                            #get ISO
                            $bootISO = $vm.iso

                            #grab the iso from the datastore
                            Get-Datastore -Server $vcsaServer -Name $ISOdatastore | where{$_.State -eq 'Available'} | %{
                                New-PSDrive -Location $_ -Name ds -PSProvider VimDatastore -Root '\' > $null
                                $ISODatastorePath = Get-ChildItem -Path ds: -Recurse -Filter *.iso | Where {$_.Name -eq $bootISO}
                            }

                            If($ISODatastorePath){
                                Get-CDDrive -VM $masterVM | Set-CDDrive -IsoPath $ISODatastorePath.DatastoreFullPath –StartConnected $True -Connected:$true -Confirm:$false
                                ## bootable CDROM device (per the docs, the first CDROM with bootable media found is used)
                                $strFirstBootDeviceName = New-Object -Type VMware.Vim.VirtualMachineBootOptionsBootableCdromDevice
                            }
                            Else{
                                write-host ("Unable to mount ISO to VM; ISO [{0}] does not exist in datastore." -f $bootISO)
                                $strFirstBootDeviceName = $null
                            }

                        }
                        Else{
                            write-host ("ISO property not specified." -f $bootISO)
                            $strFirstBootDeviceName = $null
                        }
            }

            "Network"   {
            
                        $strBootNICDeviceName = "Network adapter 1"
                        ## get the VirtualEthernetCard device, and then grab its Key (DeviceKey, used later)
                        $intNICDeviceKey = ($viewVM.Config.Hardware.Device | ?{$_.DeviceInfo.Label -eq $strBootNICDeviceName}).Key
                        ## bootable NIC BootOption device, for use in setting BootOrder (the corresponding VirtualEthernetCard device on the VM has PXE enabled, assumed)
                        $strFirstBootDeviceName = New-Object -TypeName VMware.Vim.VirtualMachineBootOptionsBootableEthernetDevice -Property @{"DeviceKey" = $intNICDeviceKey}
            }

        }# end switch
       
        ## the device name of the hard disk to which to boot
        $strBootHDiskDeviceName = "Hard disk 1"     
 
        ## get the VirtualDisk device, then grab its Key (DeviceKey, used later)
        $intHDiskDeviceKey = ($viewVM.Config.Hardware.Device | ?{$_.DeviceInfo.Label -eq $strBootHDiskDeviceName}).Key
        ## bootable Disk BootOption device, for use in setting BootOrder (the corresponding VirtualDisk device is bootable, assumed)
        $oBootableHDisk = New-Object -TypeName VMware.Vim.VirtualMachineBootOptionsBootableDiskDevice -Property @{"DeviceKey" = $intHDiskDeviceKey}

        ## create the VirtualMachineConfigSpec with which to change the VM's boot order
        $spec = New-Object VMware.Vim.VirtualMachineConfigSpec -Property @{
            "BootOptions" = New-Object VMware.Vim.VirtualMachineBootOptions -Property @{
                ## set the boot order in the spec as desired
                BootOrder = $strFirstBootDeviceName, $oBootableHDisk 
            }
        }

        ## reconfig the VM to use the spec with the new BootOrder
        $viewVM.ReconfigVM_Task($spec)

        #configure to boot into BIOS
        $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $spec.BootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
        $spec.BootOptions.EnterBIOSSetup = $true
        $masterVM.ExtensionData.ReconfigVM($spec)

        #Refresh VM details
        $masterVM = Get-VM -Name $masterimage -Server $vcsaServer

        #turn VM is on
        If($masterVM.PowerState -eq 'PoweredOff'){
            $masterVM | Start-VM -Confirm:$false
        }

    }
    Else{
        write-host ("Master image named [{0}] does not exist" -f $vm.name)
    }
}

Remove-PSDrive -Name ds -Confirm:$false

Disconnect-VIServer $vcsaServer -Force -Confirm:$false

