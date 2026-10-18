# Currawong inbound Receive connector for Exchange Server 2019.
# Run in the Exchange Management Shell. This creates the connector on each
# Mailbox server and is safe to run again. Only Currawong
# (203.0.113.10,203.0.113.11) may use it, over TLS.
# Partner usage (domain secure): Currawong presents the route's client
# certificate for gw.currawong.example, which the transport script adds to the domain
# secure lists. The certificate must allow client authentication.

if (-not (Get-ReceiveConnector "EXCH01\Currawong Inbound" -ErrorAction SilentlyContinue)) {
    New-ReceiveConnector -Name "Currawong Inbound" -Server EXCH01 -TransportRole FrontendTransport -Usage Partner -Bindings 0.0.0.0:25 -RemoteIPRanges 203.0.113.10,203.0.113.11 -RequireTLS $true -AuthMechanism Tls -PermissionGroups Partners -MaxMessageSize 50MB
}
Set-ReceiveConnector "EXCH01\Currawong Inbound" -RemoteIPRanges 203.0.113.10,203.0.113.11 -MaxMessageSize 50MB -DomainSecureEnabled $true -TlsDomainCapabilities "gw.currawong.example:AcceptCloudServicesMail" -ProtocolLoggingLevel Verbose

if (-not (Get-ReceiveConnector "EXCH02\Currawong Inbound" -ErrorAction SilentlyContinue)) {
    New-ReceiveConnector -Name "Currawong Inbound" -Server EXCH02 -TransportRole FrontendTransport -Usage Partner -Bindings 0.0.0.0:25 -RemoteIPRanges 203.0.113.10,203.0.113.11 -RequireTLS $true -AuthMechanism Tls -PermissionGroups Partners -MaxMessageSize 50MB
}
Set-ReceiveConnector "EXCH02\Currawong Inbound" -RemoteIPRanges 203.0.113.10,203.0.113.11 -MaxMessageSize 50MB -DomainSecureEnabled $true -TlsDomainCapabilities "gw.currawong.example:AcceptCloudServicesMail" -ProtocolLoggingLevel Verbose
