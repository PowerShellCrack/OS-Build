<#
   	.NOTES
	===========================================================================
     Author:   Richard Tracy
	 Filename:     	           CreateISO.ps1
     Last Updated:              03/22/2019
     Thanks to:                 
	===========================================================================
    .PARAMETER ImageName

    .PARAMETER WIMSourceRoot
    
    .PARAMETER StagingPath
    
    .PARAMETER ISOPath
    
    .PARAMETER OscdimgPath

    .PARAMETER Bootable
    
    .PARAMETER BootFilePath

    .PARAMETER EFIBootFilePath

    .PARAMETER SplitISO

    .EXAMPLE
        Sample Using MDT parameters
        .\createISO.ps1 -ImageName %TaskSequenceName% -WIMSourceRoot %BackupFile% -StagingPath .\SourceFiles\%TaskSequenceName% -ISOPath "\\filer.s3i.org\s3isoftware\Software\Microsoft\ISOs\PATCHED_ISO" -Bootable

        Sample Using normal parameters
        .\createISO.ps1 -ImageName WIN101809X64 -WIMSourceRoot "D:\DeploymentShare\Captures" -StagingPath "D:\DeploymentShare\Scripts\Custom\OS-ISOBuild\SourceFiles\WIN101809X64" -ISOPath "\\filer.s3i.org\s3isoftware\Software\Microsoft\ISOs\PATCHED_ISO" -Bootable -Comparedby Hash

    .LINKS
    https://deploymentresearch.com/Research/Post/399/How-to-REALLY-create-a-Windows-10-ISO-no-3rd-party-tools-needed

#>
param(
    [string]$ImageName,
    
    [string]$WIMSourceRoot,
    
    [string]$StagingPath,
    
    [string]$ISOPath,
    
    [string]$OscdimgPath,

    [switch]$Bootable,

    [string]$BootFilePath,

    [string]$EFIBootFilePath,

    [switch]$SplitISO
)

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

Function Get-SMSTSENV{
    param([switch]$LogPath,[switch]$NoWarning)
    
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
            #test if variables exist
            $tsenv.GetVariables()  #| % { Write-Output "$ScriptName - $_ = $($tsenv.Value($_))" }
        }
        catch{
            If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
            If(!$NoWarning){Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode." -f $prefix)}
            
            #set variable to null
            $Script:tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($tsenv){
                #grab the progress UI
                $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path
                #$UseLogPath = $tsenv.Value("LogPath")
                $UseLogPath = $tsenv.Value("_SMSTSLogPath")

                # Convert all of the variables currently in the environment to PowerShell variables
                $tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
            }
            Else{
                $UseLogPath = $env:Temp
            }
        }
    }
    End{
        If($LogPath){return $UseLogPath}
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


function Get-FileMD5 {
    Param(
        [string]$file
        )
    Begin
    {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process
    {
        $mode = [System.IO.FileMode]("open")
        $access = [System.IO.FileAccess]("Read")
        $md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
        $fs = New-Object System.IO.FileStream($file,$mode,$access)
        Write-LogEntry ("Checking Hash value for [{0}]. This can take a while..." -f $file) -Severity 1 -Source ${CmdletName} -Outhost
        $Hash = $md5.ComputeHash($fs)
        $fs.Close()
    }
    End {
        [string]$Hash = $Hash
        Write-LogEntry ("Hash is: [{0}]" -f $Hash) -Severity 4 -Source ${CmdletName} -Outhost
        Return $Hash
    }
}

function Copy-LatestFile{
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        $SourceFile,
        $DestFile,
        [ValidateSet("Hash","Date","Size")]
        [string]$Compareby
    )

    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }
    }
    Process
    {
        
        #if Source path doesn't exist unable to do anything
        If(-not(Test-Path $SourceFile)){
            Write-LogEntry ("Source files doesn't exist; Unable to compare or copy anything to") -Severity 3 -Source ${CmdletName} -Outhost
            Return
        }

        #only compare source and destination if they already exists
        ElseIf( (Test-Path $SourceFile) -and (Test-Path $DestFile) ){
            #grab the file name form the full path
            $SrcFileName = Split-Path $SourceFile -Leaf
            $DestFileName = Split-Path $DestFile -Leaf

            switch($Compareby){
                "Date" {
                            
                            $SourceCompare = (Get-Item $SourceFile).LastWriteTimeUTC
                            $DestCompare = (Get-Item $DestFile).LastWriteTimeUTC
                       }

                "Size" {
                            
                            $SourceCompare = (Get-Item $SourceFile).Length
                            $DestCompare = (Get-Item $DestFile).Length
                       }

                "Hash" {
                            $SourceCompare = Get-FileMD5 $SourceFile
                            $DestCompare = Get-FileMD5 $DestFile
                        }

            }

            if( $SourceCompare -ne $DestCompare )
            {
                Write-LogEntry ("{2} Comparison [{0}] is different than [{1}]. Overwriting destination file with source file..." -f $SrcFileName,$DestFileName,$Compareby) -Severity 1 -Source ${CmdletName} -Outhost
                Copy-File -Path $SourceFile -Destination $DestFile -Force -whatif:$WhatIfPreference
            }
            else
            {
                #Hash or date match, not overrighting file
                Write-LogEntry ("{2} Comparison [{0}] matches destination file [{1}]" -f $SrcFileName,$DestFileName,$Compareby) -Severity 1 -Source ${CmdletName} -Outhost
            }
        }

        #otherwise just copy the file
        Else{
            Write-LogEntry ("No destination file to compare; Copying [{0}] to [{1}]..." -f $SourceFile,(Split-Path $DestFile -Parent)) -Severity 1 -Source ${CmdletName} -Outhost
            Copy-File -Path $SourceFile -Destination $DestFile -Force -whatif:$WhatIfPreference
            #Import-Module BitsTransfer
            #Start-BitsTransfer -Source $Source -Destination $Destination -Description "Backup" -DisplayName "Backup"
        }
    }
    End {
        #Write-Host $Output
    }
}



function Copy-File {
    [CmdletBinding(SupportsShouldProcess = $True)]
    param( 
        [Alias("Source","Path")]
        [string]$from,

        [Alias("Destination","Dest")]
        [string]$to,

        [switch]$force
        )
   
    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }
    }
    Process
    {
        If($force){Remove-Item $to -Force -ErrorAction SilentlyContinue -WhatIf:$WhatIfPreference | Out-Null}

        If(!$WhatIfPreference){
            $ffile = [io.file]::OpenRead($from)
            $tofile = [io.file]::OpenWrite($to)
            $srcFile = Split-Path $from -Leaf

            #Create progress bar 
            Write-Progress -Activity "Copying file" -status "Copying $srcFile" -PercentComplete 0
            
            #Begine file transfer with progress by bytes
            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew();
                [byte[]]$buff = new-object byte[] (4096*1024)
                [long]$total = [long]$count = 0
                do {
                    $count = $ffile.Read($buff, 0, $buff.Length)
                    $tofile.Write($buff, 0, $count)
                    $total += $count
                    [int]$pctcomp = ([int]($total/$ffile.Length* 100));
                    [int]$secselapsed = [int]($sw.elapsedmilliseconds.ToString())/1000;
                    if ( $secselapsed -ne 0 ) {
                        [single]$xferrate = (($total/$secselapsed)/1mb);
                    } else {
                        [single]$xferrate = 0.0
                    }
                    if ($total % 1mb -eq 0) {
                        if($pctcomp -gt 0)`
                            {[int]$secsleft = ((($secselapsed/$pctcomp)* 100)-$secselapsed);
                            } else {
                            [int]$secsleft = 0};
                        Write-Progress -Activity ($pctcomp.ToString() + "% Copying file @ " + "{0:n2}" -f $xferrate + " MB/s") -status "Copying $srcFile" -PercentComplete $pctcomp -SecondsRemaining $secsleft;
                    }
                } while ($count -gt 0)
            $sw.Stop();
            $sw.Reset();
            }
            finally {
                Write-LogEntry ($srcFile + `
                 " copied in " + $secselapsed + " seconds at " + `
                 "{0:n2}" -f [int](($ffile.length/$secselapsed)/1mb) + " MB/s.") -Severity 1 -Source ${CmdletName} -Outhost
                 $ffile.Close();
                 $tofile.Close();
                }

        }
        Else{
            Write-host ("What if: Performing the operation `"Copy File`" on target `"Item: {0} Destination: {1}." -f $from.$to)
        }
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

[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Get-SMSTSENV -LogPath -NoWarning) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

If(Get-SMSTSENV){
    $FILESHARE_USER = ($tsenv.Value("DomainAdminDomain") + "\" + $tsenv.Value("DomainAdmin"))
    $FILESHARE_PASSWORD = $tsenv.Value("DomainAdminPassword")  
}

##*===========================================================================
##* MAIN
##*===========================================================================
#grab latest wim and its path
If($tsenv -and !$WIMSourceRoot){
    $FindWIM = Get-ChildItem -Path "$($tsenv.Value("DeployRoot"))\Captures" -Filter $ImageName*.wim -Recurse | sort LastWriteTime | Select -First 1
}
Elseif($WIMSourceRoot){
    $FindWIM = Get-ChildItem -Path "$WIMSourceRoot" -Filter $ImageName*.wim -Recurse | sort LastWriteTime | Select -First 1
}
Else{
    $FindWIM = Get-ChildItem -Path "$scriptDirectory\WIM" -Filter $ImageName*.wim -Recurse | sort LastWriteTime | Select -First 1
}

#does captured wim exist
If($FindWIM){
    $WIMPath = $FindWIM.FullName
    $WIMName = ($FindWIM.BaseName -split "_|-|\s+")[0]
    $WIMDate = $FindWIM.LastWriteTime.ToString("yyyy-MM-dd")
    Write-LogEntry ("WIM File used {0}" -f $WIMPath) -Severity 1 -Outhost
    
}
Else{
    Write-LogEntry ("MISSING PREREQS :: WIM File not found") -Severity 3 -Outhost
    $PrereqsReady = $false
}

#Checking for oscdimg.exe. required to create ISO
If(!$OscdimgPath){$OscdimgPath = Join-Path $scriptDirectory -ChildPath "Files";Write-LogEntry ("FOUND PREREQS :: Oscdimg.exe binary was found: {0}" -f $OscdimgPath) -Severity 4 -Outhost}
If(-not(Test-Path $OscdimgPath\oscdimg.exe)){Write-LogEntry ("MISSING PREREQS :: Oscdimg.exe binary not found or not accessible") -Severity 3 -Outhost}
If(-not(Test-Path $StagingPath)){Write-LogEntry ("MISSING PREREQS :: Staging Path not found or not accessible") -Severity 3 -Outhost}

#Determine if ISOPath found and accessible
Try{
    Get-Item $ISOPath -ErrorAction Stop | Out-Null
    
    #Determine if ISOPath is pointing to a directory
    If( (Get-Item $ISOPath) -is [System.IO.DirectoryInfo]){
        #build ISO
        $ISOPath = Join-Path $ISOPath -ChildPath ($WIMName + "_Patched_"+ $WIMDate +".ISO")  
    }
} 
Catch [System.UnauthorizedAccessException] {
    Write-LogEntry ("MISSING PREREQS :: ISO Path is unaccessible") -Severity 3 -Outhost

    If( ($FILESHARE_USER -ne $null) -and ($FILESHARE_PASSWORD -ne $null) ){
        $SecurePassword = ConvertTo-SecureString $FILESHARE_PASSWORD -AsPlainText -Force
        $FileShareCredential = New-Object System.Management.Automation.PSCredential ($FILESHARE_USER, $SecurePassword)
        Try{
	        New-PSDrive -Name $FILESHARE_PS_DRIVE -PSProvider FileSystem -Root $ISOPath -Persist -Credential $FileShareCredential
        }
        Catch{
	        Write-Output "Unable to map drive $FILESHARE_PS_DRIVE to [$ISOPath]; credentials may be invalid"
	        Write-Output $_.Exception
	        $PrereqsReady = $false
        }

        #Determine if ISOPath is pointing to a directory
        If( (Get-Item $ISOPath) -is [System.IO.DirectoryInfo]){
            #build ISO
            $ISOPath = Join-Path $ISOPath -ChildPath ($WIMName + "_Patched_"+ $WIMDate +".ISO")  
        }
    }
    Else{
        $PrereqsReady = $false
    }
} 
Catch [System.Management.Automation.ItemNotFoundException] {
    Write-LogEntry ("MISSING PREREQS :: ISO Path not found:") -Severity 3 -Outhost
    $PrereqsReady = $false
} 
Catch {
    # An unexpected error
    Write-LogEntry $_.Exception -Severity 3 -Outhost
    $Error[0]
    $PrereqsReady = $false
}

##*===========================================================================
##* MAIN
##*===========================================================================
If($PrereqsReady){
    #Copy wim file is hash is different
    Copy-LatestFile -SourceFile $WIMPath -DestFile "$StagingPath\Sources\install.wim" -Compareby Hash
    
    #Use specified Boot files, otherwise default to default Staging paths
    If($BootFilePath -and $EFIBootFilePath){
        $BootFile = "$BootFilePath\etfsboot.com"
        $EFIBootFile = "$EFIBootFilePath\efisys.bin"
    }
    Else{
        $BootFile = "$StagingPath\boot\etfsboot.com"
        $EFIBootFile = "$StagingPath\efi\Microsoft\boot\efisys.bin"
    }

    #if Set to Bootable and required boot files are valid, build boot image
    If($Bootable -and (Test-Path $BootFile) -and (Test-Path $EFIBootFile)){
        #Build bootdata params
        $BootData=('2#p0,e,b"{0}"#pEF,e,b"{1}"' -f $BootFile,$EFIBootFile)
        
        Write-LogEntry ("Building bootable ISO [{0}]" -f $ISOPath) -Severity 2 -Outhost
        Write-Host "RUNNING COMMAND: $OscdimgPath\oscdimg.exe -m -o -h -bootdata:$BootData -u2 -udfver102 '$StagingPath' '$ISOPath'"
        $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList @('-m','-o','-h',"-bootdata:$BootData",'-u2','-udfver102',"-l$ImageName","$StagingPath","$ISOPath") -PassThru -Wait -NoNewWindow

    }
    Else{
        Write-LogEntry ("Building non-bootable ISO [{0}]" -f $ISOPath) -Severity 2 -Outhost
        $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList @('-m','-o','-h','-u2','-udfver102',"-l$ImageName","$StagingPath","$ISOPath") -PassThru -Wait -NoNewWindow
    }


    if($Proc.ExitCode -ne 0)
    {
        Write-LogEntry ("Failed to generate ISO with exitcode: {0}" -f $Proc.ExitCode) -Severity 2 -Outhost
    }
}
Else{
    Write-LogEntry ("Prereqs failed, unable to build ISO. Check log for more details") -Severity 3 -Outhost
}




