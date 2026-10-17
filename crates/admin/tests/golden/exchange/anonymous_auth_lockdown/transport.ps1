# Currawong transport settings for Exchange Server Subscription Edition.
# Run in the Exchange Management Shell; it is safe to run again. The first run
# saves the current size limits for the rollback script, then Exchange's
# limits are set to Currawong's (25MB).
$backup = Join-Path $env:USERPROFILE "currawong-transport-backup.xml"
$config = Get-TransportConfig
if (-not (Test-Path $backup)) {
    [pscustomobject]@{
        MaxReceiveSize = $config.MaxReceiveSize.ToString()
        MaxSendSize = $config.MaxSendSize.ToString()
    } | Export-Clixml -Path $backup
}
Set-TransportConfig -MaxReceiveSize 25MB -MaxSendSize 25MB
