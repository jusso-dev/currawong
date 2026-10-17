# Currawong transport settings for Exchange Server 2019.
# Run in the Exchange Management Shell; it is safe to run again. The first run
# saves the current size limits for the rollback script, then Exchange's
# limits are set to Currawong's (50MB).
$backup = Join-Path $env:USERPROFILE "currawong-transport-backup.xml"
$config = Get-TransportConfig
# Domain secure (mutual TLS) mail with Currawong. The backup also records
# whether gw.currawong.example was already on each list, so rollback leaves it if so.
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
if ($receiveSecure -notcontains "gw.currawong.example") {
    Set-TransportConfig -TLSReceiveDomainSecureList @{Add="gw.currawong.example"}
}
if ($sendSecure -notcontains "gw.currawong.example") {
    Set-TransportConfig -TLSSendDomainSecureList @{Add="gw.currawong.example"}
}
