# Currawong inbound Receive connector for Exchange Server Subscription Edition.
# Run in the Exchange Management Shell. This creates the connector on each
# Mailbox server and is safe to run again. Only Currawong
# (198.51.100.20,2001:db8::25) may use it, over TLS.
# Anonymous usage: Currawong has no client certificate configured, so the
# connector cannot be domain secure. Hosts at these addresses may send
# without one. The RemoteIPRanges restriction is the key control, so keep it
# to Currawong's addresses only. TLS is still required.

if (-not (Get-ReceiveConnector "MBX-SYD01\Currawong Inbound" -ErrorAction SilentlyContinue)) {
    New-ReceiveConnector -Name "Currawong Inbound" -Server MBX-SYD01 -TransportRole FrontendTransport -Usage Custom -Bindings 0.0.0.0:25 -RemoteIPRanges 198.51.100.20,2001:db8::25 -RequireTLS $true -PermissionGroups AnonymousUsers -MaxMessageSize 25MB
}
Set-ReceiveConnector "MBX-SYD01\Currawong Inbound" -RemoteIPRanges 198.51.100.20,2001:db8::25 -MaxMessageSize 25MB -ProtocolLoggingLevel Verbose

# WARNING: optional lock-down. After this, the Default Frontend connector on
# each server accepts mail only from 10.20.0.0/16,192.168.50.0/24.
# Mail from anywhere else, including another gateway or the old MX, is
# refused. List every internal sender (applications, devices, other Exchange
# servers) in these ranges first. The first run saves each connector's
# current ranges; the rollback script puts them back.
$saved = Join-Path $env:USERPROFILE "currawong-frontend-MBX-SYD01.xml"
if (-not (Test-Path $saved)) {
    (Get-ReceiveConnector "MBX-SYD01\Default Frontend MBX-SYD01").RemoteIPRanges | ForEach-Object { $_.ToString() } | Export-Clixml -Path $saved
}
Set-ReceiveConnector "MBX-SYD01\Default Frontend MBX-SYD01" -RemoteIPRanges 10.20.0.0/16,192.168.50.0/24
