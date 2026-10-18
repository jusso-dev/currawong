# Currawong outbound Send connector for Exchange Server Subscription Edition.
# Run in the Exchange Management Shell; it is safe to run again. All outbound
# mail from MBX-SYD01 goes to mx.gateway.health.example on port 587 over TLS,
# and Exchange checks that Currawong's certificate is valid for mx.gateway.health.example.
# SMTP AUTH: enter the Currawong relay user name and password when asked.
if (-not (Get-SendConnector "Currawong Outbound" -ErrorAction SilentlyContinue)) {
    New-SendConnector -Name "Currawong Outbound" -Usage Custom -AddressSpaces "SMTP:*;1" -IsScopedConnector $false -SourceTransportServers MBX-SYD01 -SmartHosts mx.gateway.health.example -SmartHostAuthMechanism BasicAuthRequireTLS -AuthenticationCredential (Get-Credential) -DNSRoutingEnabled $false -RequireTLS $true -TlsAuthLevel DomainValidation -TlsDomain mx.gateway.health.example -Port 587 -MaxMessageSize 25MB
}
