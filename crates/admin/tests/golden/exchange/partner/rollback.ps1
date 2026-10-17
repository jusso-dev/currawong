# Currawong rollback for Exchange Server 2019.
# Point the MX records back at the previous host first, or inbound mail will
# queue at senders. Then run this in the Exchange Management Shell. It
# removes the Currawong connectors and undoes only what the Currawong
# scripts changed, using the copies they saved.
if (Get-ReceiveConnector "EXCH01\Currawong Inbound" -ErrorAction SilentlyContinue) {
    Remove-ReceiveConnector "EXCH01\Currawong Inbound" -Confirm:$false
}
$saved = Join-Path $env:USERPROFILE "currawong-frontend-EXCH01.xml"
if (Test-Path $saved) {
    # Default Frontend was locked down: put back the ranges it had before.
    Set-ReceiveConnector "EXCH01\Default Frontend EXCH01" -RemoteIPRanges (Import-Clixml -Path $saved)
    Remove-Item -Path $saved
}
if (Get-ReceiveConnector "EXCH02\Currawong Inbound" -ErrorAction SilentlyContinue) {
    Remove-ReceiveConnector "EXCH02\Currawong Inbound" -Confirm:$false
}
$saved = Join-Path $env:USERPROFILE "currawong-frontend-EXCH02.xml"
if (Test-Path $saved) {
    # Default Frontend was locked down: put back the ranges it had before.
    Set-ReceiveConnector "EXCH02\Default Frontend EXCH02" -RemoteIPRanges (Import-Clixml -Path $saved)
    Remove-Item -Path $saved
}
if (Get-SendConnector "Currawong Outbound" -ErrorAction SilentlyContinue) {
    Remove-SendConnector "Currawong Outbound" -Confirm:$false
}
$backup = Join-Path $env:USERPROFILE "currawong-transport-backup.xml"
if (Test-Path $backup) {
    # Saved values read like "10 MB (10,485,760 bytes)"; the part before the bracket is enough.
    $previous = Import-Clixml -Path $backup
    Set-TransportConfig -MaxReceiveSize ($previous.MaxReceiveSize -replace '\s*\(.*$', '') -MaxSendSize ($previous.MaxSendSize -replace '\s*\(.*$', '')
    # Take Currawong off a domain secure list only if it was not there before.
    $config = Get-TransportConfig
    if ($previous.ReceiveSecure -eq $false -and @($config.TLSReceiveDomainSecureList | ForEach-Object { $_.ToString() }) -contains "gw.currawong.example") {
        Set-TransportConfig -TLSReceiveDomainSecureList @{Remove="gw.currawong.example"}
    }
    if ($previous.SendSecure -eq $false -and @($config.TLSSendDomainSecureList | ForEach-Object { $_.ToString() }) -contains "gw.currawong.example") {
        Set-TransportConfig -TLSSendDomainSecureList @{Remove="gw.currawong.example"}
    }
    Remove-Item -Path $backup
} else {
    Write-Warning "$backup was not found. Set MaxReceiveSize and MaxSendSize back by hand, and check the domain secure lists."
}
