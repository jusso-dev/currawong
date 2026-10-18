# Currawong outbound Send connector for Exchange Server 2019.
# Run in the Exchange Management Shell; it is safe to run again. All outbound
# mail from EXCH01,EXCH02 goes to gw.currawong.example on port 25 over TLS,
# and Exchange checks that Currawong's certificate is valid for gw.currawong.example.
# Currawong trusts these servers' addresses as a relay; no password is sent.
if (-not (Get-SendConnector "Currawong Outbound" -ErrorAction SilentlyContinue)) {
    New-SendConnector -Name "Currawong Outbound" -Usage Custom -AddressSpaces "SMTP:*;1" -IsScopedConnector $false -SourceTransportServers EXCH01,EXCH02 -SmartHosts gw.currawong.example -SmartHostAuthMechanism None -DNSRoutingEnabled $false -RequireTLS $true -TlsAuthLevel DomainValidation -TlsDomain gw.currawong.example -Port 25 -MaxMessageSize 50MB
}
