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
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [Alias("WIMFile")]
    [string]$WIMSourceRoot,

    [parameter(Mandatory=$false)]
    [Alias("StagingDir")]
    [string]$StagingPath,
    
    [parameter(Mandatory=$false)]
    [Alias("SetupFiles","SourcePath")]
    [string]$SetupSource,

    [parameter(Mandatory=$false)]
    [string]$OscdimgPath,

    [parameter(Mandatory=$false)]
    [string]$ImageName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [Alias("ISOPath")]
    [string]$ISODestPath,

    [parameter(Mandatory=$false)]
    [switch]$SplitISO,

    [parameter(Mandatory=$false)] 
    [switch]$Bootable,

    [parameter(Mandatory=$false)]
    [string]$BootFilePath,

    [parameter(Mandatory=$false)]
    [string]$EFIBootFilePath,

    [parameter(Mandatory=$false)]
    [boolean]$CleanupTemp = $true
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


function Copy-LatestFile{
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Source","Path")]
        $SourceFile,

        [Parameter(Mandatory=$true)]
        [Alias("Destination","Dest")]
        $DestFile,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Hash","Date","Size")]
        [string]$Compareby = "Size"
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
            Write-LogEntry ("Preparing to copy [{0}] to [{1}]..." -f $SourceFile,$DestFile) -Severity 1 -Source ${CmdletName} -Outhost

            #grab the file name form the full path
            $SrcFileName = Split-Path $SourceFile -Leaf
            $DestFileName = Split-Path $DestFile -Leaf

            switch($Compareby){
                "Date" { 
                            Write-LogEntry ("Checking Date for [{0}]." -f $SourceFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $SourceCompare = (Get-Item $SourceFile).LastWriteTimeUTC
                            Write-LogEntry ("Comparing Date with [{0}]." -f $DestFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $DestCompare = (Get-Item $DestFile).LastWriteTimeUTC
                       }

                "Size" {
                            Write-LogEntry ("Checking Size for [{0}]." -f $SourceFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $SourceCompare = (Get-Item $SourceFile).Length
                            Write-LogEntry ("Comparing Size with [{0}]." -f $DestFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $DestCompare = (Get-Item $DestFile).Length
                       }

                "Hash" {
                            Write-LogEntry ("Checking Hash value for [{0}]. This can take a while..." -f $SourceFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $SourceCompare = Get-FileHash -Path $SourceFile -Algorithm MD5
                            Write-LogEntry ("Comparing Hash value with [{0}]. This can take a while..." -f $DestFile) -Severity 1 -Source ${CmdletName} -Outhost
                            $DestCompare = Get-FileHash -Path $DestFile -Algorithm MD5
                        }

            }

            if( $SourceCompare -ne $DestCompare )
            {
                Write-LogEntry ("{2} Comparison [{0}] is different than [{1}]. Overwriting destination file with source file..." -f $SrcFileName,$DestFileName,$Compareby) -Severity 1 -Source ${CmdletName} -Outhost
                Copy-File -Path $SourceFile -Destination $DestFile -Force -whatif:$WhatIfPreference
                #Copy-ItemWithProgress -Source $SourceFile -Destination $DestFile -Force
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
            #Copy-ItemWithProgress -Source $SourceFile -Destination $DestFile -Force
            #Import-Module BitsTransfer
            #Start-BitsTransfer -Source $Source -Destination $Destination -Description "Backup" -DisplayName "Backup"
        }
    }
    End {
        #Write-Host $Output
    }
}

Function Copy-ItemWithProgress
{
    [CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
    [string]$Source,
    [Parameter(Mandatory=$true,Position=1)]
    [string]$Destination,
    [Parameter(Mandatory=$false,Position=2)]
    [string]$Filter,
    [Parameter(Mandatory=$false,Position=3)]
    [switch]$Force
    )

    Begin{
        $Source = $Source
    
        #get the entire folder structure
        $Filelist = Get-Childitem $Source -Recurse -Exclude $filter

        #get the count of all the objects
        $Total = $Filelist.count

        #establish a counter
        $Position = 0
    }
    Process{
        #Stepping through the list of files is quite simple in PowerShell by using a For loop
        foreach ($File in $Filelist)

        {
            #On each file, grab only the part that does not include the original source folder using replace
            $Filename = ($File.Fullname).replace($Source,'')
        
            #rebuild the path for the destination:
            $DestinationFile = ($Destination+$Filename)
        
            #get just the folder path
            $DestinationPath = Split-Path $DestinationFile -Parent

            #show progress
            Show-ProgressStatus -Message "Copying data from $source to $Destination" -Step (($Position/$total)*100) -MaxStep $total

            #create destination directories
            If (-not (Test-Path $DestinationPath) ) {
                New-Item $DestinationPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            }

            #do copy (enforce)
            Try{
                Copy-Item $File.FullName -Destination $DestinationFile -Force:$Force -ErrorAction:$VerbosePreference -Verbose:($PSBoundParameters['Verbose'] -eq $true) | Out-Null
                Write-Verbose ("Copied file [{0}] to [{1}]" -f $File.FullName,$DestinationFile)
            }
            Catch{
                Write-Host ("Unable to copy file in {0} to {1}; Error: {2}" -f $File.FullName,$DestinationFile ,$_.Exception.Message) -ForegroundColor Red
                break
            }
            #bump up the counter
            $Position++
        }
    }
    End{
        Show-ProgressStatus -Message "Copy completed" -Step $total -MaxStep $total
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
                [byte[]]$buff = new-object byte[] (4096)
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
    End{
        Write-Progress -Activity "Copying files" -status "Done copying files" -PercentComplete 100
    }

}

Function Execute-Command ($commandTitle, $commandPath, $commandArguments)
{
  Try {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $commandPath
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $commandArguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    [pscustomobject]@{
        commandTitle = $commandTitle
        stdout = $p.StandardOutput.ReadToEnd()
        stderr = $p.StandardError.ReadToEnd()
        ExitCode = $p.ExitCode
    }
    $p.WaitForExit()
  }
  Catch {
     exit
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
##* PREREQS
##*===========================================================================
$PrereqsReady = $true

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
    Write-LogEntry ("WIM file being used [{0}]" -f $WIMPath) -Severity 1 -Outhost
}
Else{
    Write-LogEntry ("WIM file not found [{0}]" -f $WIMSourceRoot) -Severity 3 -Outhost
    $PrereqsReady = $false
}

#Build path for oscdimg.exe 
If(!$OscdimgPath){$OscdimgPath = Join-Path $scriptDirectory -ChildPath "Files"}

#Checking for oscdimg.exe. required to create ISO
Write-LogEntry ("Validating oscdimg path [{0}]..." -f $OscdimgPath) -Severity 1 -Outhost
If(-not(Test-Path "$OscdimgPath\oscdimg.exe") ){
    Write-LogEntry ("Oscdimg.exe binary not found or not accessible") -Severity 3 -Outhost
    $PrereqsReady = $false
}
Else{
    $OscdimgPath = (Resolve-Path $OscdimgPath).Path
    Write-LogEntry ("Resolved Oscdimg absolute path [{0}]..." -f $OscdimgPath) -Severity 0 -Outhost
}


#If SetupSource is specified, validate it
#if not use temp directory
If($SetupSource){

    Write-LogEntry ("Validating setup source path [{0}]..." -f $SetupSource) -Severity 1 -Outhost
    
    if(-not(Test-Path $SetupSource)){
        Write-LogEntry ("Source path does not exist [{0}]" -f $SetupSource) -Severity 3 -Outhost
        $PrereqsReady = $false
    }
    Else{
        #resolve to absolute path always
        $SetupSource = (Resolve-Path $SetupSource).Path
        Write-LogEntry ("Resolved source absolute path [{0}]..." -f $SetupSource) -Severity 1 -Outhost
    }
}
Else{
    $SetupSource = "$env:Temp\$ImageName"
    Write-LogEntry ("Source path set to [{0}]" -f $SetupSource) -Severity 0 -Outhost
}


#check if staging path is specified, if not use temp directory
If($StagingPath){
    Write-LogEntry ("Validating staging path [{0}]..." -f $StagingPath) -Severity 1 -Outhost

    if(-not(Test-Path $StagingPath)){
        Write-LogEntry ("Staging path not found or not accessible") -Severity 3 -Outhost
        $PrereqsReady = $false
    }
    Else{
        #resolve to absolute path always
        $StagingPath = (Resolve-Path $StagingPath).Path
        Write-LogEntry ("Resolved staging absolute path [{0}]..." -f $StagingPath) -Severity 1 -Outhost
    }
}
Else{
    $StagingPath = "$env:Temp\$ImageName"
    Write-LogEntry ("Staging path set to [{0}]" -f $StagingPath) -Severity 0 -Outhost
}


#check to see if either setup or staging has bootable files
If($Bootable){
     Write-LogEntry ("Validating bootable files...") -Severity 1 -Outhost
    
    #check if staging/source path is bootable and files exist: setup.exe and boot.wim, if not copy
    If( ( (Test-Path "$SetupSource\setup.exe") -and (Test-Path "$SetupSource\sources\boot.wim") ) -and ( (-not(Test-Path "$StagingPath\setup.exe")) -or (-not(Test-Path "$StagingPath\sources\boot.wim")) ) ){
        Write-LogEntry ("Copying source setup files from [{0}] to staging path [{1}]..." -f $SetupSource,$StagingPath) -Severity 1 -Outhost
        Copy-ItemWithProgress -Source $SetupSource -Destination $StagingPath -Force -Filter install.wim
    }
    If( ( (-not(Test-Path "$SetupSource\setup.exe")) -and (-not(Test-Path "$SetupSource\sources\boot.wim")) ) -and ( (-not(Test-Path "$StagingPath\setup.exe")) -or (-not(Test-Path "$StagingPath\sources\boot.wim")) ) ){
        Write-LogEntry ("Nether SetupSource [{0}] nor Staging path [{1}] have bootable files, Please extract a bootable ISO" -f $SetupSource,$StagingPath) -Severity 3 -Outhost
        $PrereqsReady = $false
    }
    Else{
        Write-LogEntry ("Bootable files are found...") -Severity 0 -Outhost
    }
}


#Determine if ISOPath found and accessible
If($ISODestPath){
    Try{
        Write-LogEntry ("Validating ISO destination path [{0}]..." -f $ISODestPath) -Severity 1 -Outhost
        
        if(-not(Test-Path $ISODestPath)){
            Write-LogEntry ("ISO destination path not found or not accessible") -Severity 3 -Outhost
            break
        }
        Else{
            #resolve to absolute path always
            $ISODestPath = (Resolve-Path $ISODestPath).Path
        }

        #Determine if ISOPath is pointing to a directory
        If( (Get-Item $ISODestPath) -is [System.IO.DirectoryInfo]){
            #build ISO
            $ISODestPath = Join-Path $ISODestPath -ChildPath ($WIMName + "_Patched_"+ $WIMDate +".ISO")
            Write-LogEntry ("Resolved ISO destination path [{0}]..." -f $ISODestPath) -Severity 1 -Outhost
        }
    } 
    Catch [System.UnauthorizedAccessException] {
        Write-LogEntry ("ISO destination path is unaccessible") -Severity 3 -Outhost

        If( ($FILESHARE_USER -ne $null) -and ($FILESHARE_PASSWORD -ne $null) ){
            $SecurePassword = ConvertTo-SecureString $FILESHARE_PASSWORD -AsPlainText -Force
            $FileShareCredential = New-Object System.Management.Automation.PSCredential ($FILESHARE_USER, $SecurePassword)
            Try{
	            New-PSDrive -Name $FILESHARE_PS_DRIVE -PSProvider FileSystem -Root $ISODestPath -Persist -Credential $FileShareCredential
            }
            Catch{
	            Write-Output "Unable to map drive $FILESHARE_PS_DRIVE to [$ISODestPath]; credentials may be invalid"
	            Write-Output $_.Exception
	            $PrereqsReady = $false
            }

            #Determine if ISOPath is pointing to a directory
            If( (Get-Item $ISODestPath) -is [System.IO.DirectoryInfo]){
                #build ISO
                $ISODestPath = Join-Path $ISODestPath -ChildPath ($WIMName + "_Patched_"+ $WIMDate +".ISO")  
            }
        }
        Else{
            $PrereqsReady = $false
        }
    } 
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-LogEntry ("ISO destination path not found") -Severity 3 -Outhost
        $PrereqsReady = $false
    } 
    Catch {
        # An unexpected error
        Write-LogEntry $_.Exception -Severity 3 -Outhost
        $Error[0]
        $PrereqsReady = $false
    }
}
Else{
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
        
        Write-LogEntry ("Building bootable ISO [{0}]" -f $ISODestPath) -Severity 2 -Outhost
        Write-Host "OSCDIMG COMMAND: $OscdimgPath\oscdimg.exe -m -o -h -bootdata:$BootData -u2 -udfver102 '$StagingPath' '$ISODestPath'" -Verbose
        $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList @('-m','-o','-h',"-bootdata:$BootData",'-u2','-udfver102',"-l$ImageName","$StagingPath","$ISODestPath") -PassThru -NoNewWindow -RedirectStandardOutput "$env:temp\ocsdimg_stdout.txt" -RedirectStandardError "$env:temp\ocsdimg_stderr.txt"

    }
    Else{
        Write-LogEntry ("Building non-bootable ISO [{0}]" -f $ISODestPath) -Severity 2 -Outhost
        Write-Host "OSCDIMG COMMAND: $OscdimgPath\oscdimg.exe -m -o -h -u2 -u2 -udfver102 '$StagingPath' '$ISODestPath'" -Verbose
        $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList @('-m','-o','-h','-u2','-udfver102',"-l$ImageName","$StagingPath","$ISODestPath") -PassThru -NoNewWindow -RedirectStandardOutput "$env:temp\ocsdimg_stdout.txt" -RedirectStandardError "$env:temp\ocsdimg_stderr.txt"
    }

    #As the ocsdimg is running (in the brackground)
    #Read the output of the oscdimg process to pull the percentage
    While (!($Proc.HasExited)){
        Start-Sleep -Seconds 1
        <#
        Get-Content -Path "$env:temp\ocsdimg_stdout.txt" | ForEach-Object {
            If($_ -like "*% Complete"){
                $status = ($_ -replace "% Complete","")
            }
        }
        #>
        $content = Get-Content -Path "$env:temp\ocsdimg_stderr.txt" -Tail 2
        If($content -like "*% Complete"){
            $status = [int](($content -replace "% Complete","") | Out-String).Trim()
        }
        Show-ProgressStatus -Message ("Creating ISO [{0}]..." -f $ISODestPath) -Step $status -MaxStep 100
    }
    $Proc.ExitCode
    
    <#
    While (!($Proc.HasExited)){

        foreach ($line in [System.IO.File]::ReadLines("$env:temp\ocsdimg_stdout.txt")) {
            Start-Sleep -Seconds 5
            If($line -like "*% Complete"){
                $status = ($line -replace "% Complete","")
            }
        }
        Show-ProgressStatus -Message ("Creating ISO [{0}]..." -f $ISODestPath) -Step $status -MaxStep 100
    }
    #>

    #if process doesn't exist correctly
    if($Proc.ExitCode -ne 0){Write-LogEntry ("Failed to generate ISO with exitcode: {0}" -f $Proc.ExitCode) -Severity 3 -Outhost}

    #cleanup temp location
    If($CleanupTemp){
        If(Test-Path "$env:Temp\$ImageName"){
            Remove-Item "$env:Temp\$ImageName" -Recurse -Force | Out-Null
            Write-LogEntry ("Remove temp directories" -f "$env:Temp\$ImageName") -Severity 2 -Outhost
        }
    }
}
Else{
    Write-LogEntry ("Prereqs failed, unable to build ISO. Check log for more details") -Severity 3 -Outhost
}