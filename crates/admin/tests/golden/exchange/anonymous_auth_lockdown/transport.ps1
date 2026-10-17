# Currawong transport settings for Exchange Server Subscription Edition.
# Run in the Exchange Management Shell; it is safe to run again. The first run
# saves the current size limits, and whether mx.gateway.health.example was already on the
# domain secure lists, for the rollback script. Exchange's limits are then
# set to Currawong's (25MB).
$backup = Join-Path $env:USERPROFILE "currawong-transport-backup.xml"
$config = Get-TransportConfig
$receiveSecure = @($config.TLSReceiveDomainSecureList | ForEach-Object { $_.ToString() })
$sendSecure = @($config.TLSSendDomainSecureList | ForEach-Object { $_.ToString() })
if (-not (Test-Path $backup)) {
    [pscustomobject]@{
        MaxReceiveSize = $config.MaxReceiveSize.ToString()
        MaxSendSize = $config.MaxSendSize.ToString()
        ReceiveSecure = $receiveSecure -contains "mx.gateway.health.example"
        SendSecure = $sendSecure -contains "mx.gateway.health.example"
    } | Export-Clixml -Path $backup
}
Set-TransportConfig -MaxReceiveSize 25MB -MaxSendSize 25MB
