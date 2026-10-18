# Currawong transport settings for Exchange Server 2019.
# Run in the Exchange Management Shell; it is safe to run again. The first run
# saves the current size limits, and whether gw.currawong.example was already on the
# domain secure lists, for the rollback script. Exchange's limits are then
# set to Currawong's (50MB).
$backup = Join-Path $env:USERPROFILE "currawong-transport-backup.xml"
$config = Get-TransportConfig
$receiveSecure = @($config.TLSReceiveDomainSecureList | ForEach-Object { $_.ToString() })
$sendSecure = @($config.TLSSendDomainSecureList | ForEach-Object { $_.ToString() })
if (-not (Test-Path $backup)) {
    [pscustomobject]@{
        MaxReceiveSize = $config.MaxReceiveSize.ToString()
        MaxSendSize = $config.MaxSendSize.ToString()
        ReceiveSecure = $receiveSecure -contains "gw.currawong.example"
        SendSecure = $sendSecure -contains "gw.currawong.example"
    } | Export-Clixml -Path $backup
}
Set-TransportConfig -MaxReceiveSize 50MB -MaxSendSize 50MB
# Domain secure (mutual TLS) mail with Currawong.
if ($receiveSecure -notcontains "gw.currawong.example") {
    Set-TransportConfig -TLSReceiveDomainSecureList @{Add="gw.currawong.example"}
}
if ($sendSecure -notcontains "gw.currawong.example") {
    Set-TransportConfig -TLSSendDomainSecureList @{Add="gw.currawong.example"}
}
