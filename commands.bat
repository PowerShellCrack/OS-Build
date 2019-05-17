@ECHO OFF
ECHO Creating ISO
.\CreateISO.ps1 -ImageName WIN101809X64OFF16 -WIMSourceRoot "D:\DeploymentShare\Captures\WIN101809X64OFF16_2019-5-16_0829.wim" -StagingPath .\SourceFiles\WIN101809X64OFF16 -ISOPath "D:\DeploymentShare\ISO" -Bootable