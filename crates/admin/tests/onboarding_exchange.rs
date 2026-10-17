//! Golden file tests for the Exchange on-premises onboarding scripts.
//! Regenerate after an intended template change with
//! `UPDATE_GOLDEN=1 cargo test -p currawong-admin --test onboarding_exchange`
//! and review the diff.
use currawong_admin::onboarding::exchange::{render_scripts, ExchangeOnboarding, ExchangeScripts};
use currawong_core::config::{Config, DomainRoute, ExchangeVersion, MailboxPlatform};
use std::path::PathBuf;

/// The issue's example tenant: two Mailbox servers, Partner connector, relay
/// by trusted address on 25.
fn partner_tenant() -> ExchangeOnboarding {
    ExchangeOnboarding {
        version: ExchangeVersion::Ex2019,
        gateway_fqdn: "gw.currawong.example".into(),
        gateway_ips: vec![
            "203.0.113.10".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        ],
        domains: vec!["agency.example".into()],
        servers: vec!["EXCH01".into(), "EXCH02".into()],
        max_message_bytes: 50 * 1024 * 1024,
        domain_secure: true,
        smtp_auth: false,
        lock_down_default_frontend: None,
    }
}

/// No client certificate (so the anonymous connector), SMTP AUTH and the
/// Default Frontend lock-down, with values unlike the issue's examples.
fn locked_down_tenant() -> ExchangeOnboarding {
    ExchangeOnboarding {
        version: ExchangeVersion::Se,
        gateway_fqdn: "mx.gateway.health.example".into(),
        gateway_ips: vec![
            "198.51.100.20".parse().unwrap(),
            "2001:db8::25".parse().unwrap(),
        ],
        domains: vec!["health.example".into(), "clinic.health.example".into()],
        servers: vec!["MBX-SYD01".into()],
        max_message_bytes: 25 * 1024 * 1024,
        domain_secure: false,
        smtp_auth: true,
        lock_down_default_frontend: Some(vec![
            "10.20.0.0/16".parse().unwrap(),
            "192.168.50.0/24".parse().unwrap(),
        ]),
    }
}

fn files(scripts: &ExchangeScripts) -> [(&'static str, &str); 5] {
    [
        ("receive.ps1", &scripts.receive),
        ("send.ps1", &scripts.send),
        ("transport.ps1", &scripts.transport),
        ("rollback.ps1", &scripts.rollback),
        ("dns.txt", &scripts.dns),
    ]
}

fn check_golden(fixture: &str, scripts: &ExchangeScripts) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/exchange")
        .join(fixture);
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    for (name, text) in files(scripts) {
        let path = dir.join(name);
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, text).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        assert_eq!(text, want, "{fixture}/{name} differs from its golden file");
    }
}

fn assert_no_placeholders(scripts: &ExchangeScripts) {
    for (name, text) in files(scripts) {
        for marker in [
            "{{",
            "{%",
            "%}",
            "<",
            ">",
            "TODO",
            "CHANGEME",
            "PLACEHOLDER",
        ] {
            assert!(
                !text.contains(marker),
                "{name} contains {marker:?}:\n{text}"
            );
        }
        assert!(text.ends_with('\n'), "{name} has no final newline");
    }
}

#[test]
fn onboarding_exchange_partner_matches_golden() {
    let scripts = render_scripts(&partner_tenant()).unwrap();
    assert_no_placeholders(&scripts);
    check_golden("partner", &scripts);
    // The issue's cmdlets, with the tenant's values.
    assert!(scripts.receive.contains("New-ReceiveConnector -Name \"Currawong Inbound\" -Server EXCH02 -TransportRole FrontendTransport -Usage Partner -Bindings 0.0.0.0:25 -RemoteIPRanges 203.0.113.10,203.0.113.11 -RequireTLS $true -AuthMechanism Tls -PermissionGroups Partners"));
    assert!(scripts.send.contains("-SourceTransportServers EXCH01,EXCH02 -SmartHosts gw.currawong.example -SmartHostAuthMechanism None"));
    assert!(scripts.send.contains("-Port 25"));
    assert!(scripts
        .transport
        .contains("Set-TransportConfig -MaxReceiveSize 50MB -MaxSendSize 50MB"));
    assert!(!scripts.receive.contains("Default Frontend"));
    // Domain secure, so Currawong goes on the secure lists, once.
    assert!(scripts.receive.contains("-TlsDomainCapabilities"));
    assert!(scripts.receive.contains("-DomainSecureEnabled $true"));
    assert!(scripts.transport.contains(
        "Set-TransportConfig -TLSReceiveDomainSecureList @{Add=\"gw.currawong.example\"}"
    ));
    assert!(scripts
        .transport
        .contains("$receiveSecure -notcontains \"gw.currawong.example\""));
    // Re-runnable: the backup is written once and connectors only created once.
    assert!(scripts.transport.contains("if (-not (Test-Path $backup))"));
    assert!(scripts
        .receive
        .contains("if (-not (Get-ReceiveConnector \"EXCH01\\Currawong Inbound\""));
    assert!(scripts
        .send
        .contains("if (-not (Get-SendConnector \"Currawong Outbound\""));
    // Rollback removes only what the transport script added.
    assert!(scripts
        .rollback
        .contains("if ($previous.ReceiveSecure -eq $false"));
    assert!(scripts
        .rollback
        .contains("Remove-ReceiveConnector \"EXCH01\\Currawong Inbound\""));
    assert!(scripts
        .rollback
        .contains("Remove-SendConnector \"Currawong Outbound\""));
    assert!(scripts
        .dns
        .contains("agency.example. IN MX 10 gw.currawong.example."));
}

#[test]
fn onboarding_exchange_variants_match_golden() {
    let scripts = render_scripts(&locked_down_tenant()).unwrap();
    assert_no_placeholders(&scripts);
    check_golden("anonymous_auth_lockdown", &scripts);
    // Nothing from the issue's example values leaks into another tenant.
    for (name, text) in files(&scripts) {
        for example in ["EXCH01", "203.0.113", "gw.currawong.example", "50MB"] {
            assert!(!text.contains(example), "{name} contains {example}");
        }
    }
    assert!(scripts.receive.contains("-Usage Custom"));
    // No client certificate: nothing domain secure is set up.
    for (name, text) in files(&scripts) {
        for secure in [
            "Partner",
            "DomainSecureList @{Add",
            "DomainSecureEnabled",
            "TlsDomainCapabilities",
        ] {
            assert!(!text.contains(secure), "{name} contains {secure}");
        }
    }
    // The backup still records the secure lists, so rollback does not depend
    // on which mode the wizard is in when it is run.
    assert!(scripts.transport.contains("ReceiveSecure = $receiveSecure"));
    assert!(scripts.rollback.contains("if ($previous.ReceiveSecure -eq $false"));
    // A missing lock-down backup is reported, not skipped silently.
    assert!(scripts
        .rollback
        .contains("Write-Warning \"$saved was not found"));
    assert!(scripts.receive.contains("-PermissionGroups AnonymousUsers"));
    assert!(scripts
        .receive
        .contains("RemoteIPRanges restriction is the key control"));
    assert!(scripts.receive.contains("WARNING"));
    assert!(scripts.receive.contains(
        "Set-ReceiveConnector \"MBX-SYD01\\Default Frontend MBX-SYD01\" -RemoteIPRanges 10.20.0.0/16,192.168.50.0/24"
    ));
    assert!(scripts.send.contains(
        "-SmartHostAuthMechanism BasicAuthRequireTLS -AuthenticationCredential (Get-Credential)"
    ));
    assert!(scripts.send.contains("-Port 587"));
    // The lock-down saves the connector's ranges first; rollback restores them.
    assert!(scripts.receive.contains("Export-Clixml -Path $saved"));
    assert!(scripts.rollback.contains(
        "Set-ReceiveConnector \"MBX-SYD01\\Default Frontend MBX-SYD01\" -RemoteIPRanges (Import-Clixml -Path $saved)"
    ));
    assert!(scripts.dns.contains("ip4:198.51.100.20 ip6:2001:db8::25"));
    assert!(scripts
        .dns
        .contains("clinic.health.example. IN MX 10 mx.gateway.health.example."));
}

#[test]
fn onboarding_exchange_wizard_defaults_come_from_config() {
    let mut cfg = Config::default();
    cfg.gateway.hostname = "gw.currawong.example".into();
    cfg.limits.max_message_bytes = 40 * 1024 * 1024;
    cfg.domains.routes.push(DomainRoute {
        domain: "Agency.Example".into(),
        next_hop: String::new(),
        platform: Some(MailboxPlatform::ExchangeOnPrem {
            version: ExchangeVersion::Ex2016,
            mailbox_hosts: vec![
                "exch01.agency.example".into(),
                "exch02.agency.example:2525".into(),
                "10.1.1.5".into(),
            ],
            tls_cert_name: "mail.agency.example".into(),
            ca_file: None,
            client_cert: None,
            client_key: None,
        }),
    });
    let mut wizard = ExchangeOnboarding::from_config(&cfg, "agency.example").unwrap();
    assert_eq!(wizard.version, ExchangeVersion::Ex2016);
    assert_eq!(wizard.servers, ["EXCH01", "EXCH02"]);
    assert_eq!(wizard.domains, ["agency.example"]);
    assert_eq!(wizard.max_message_bytes, 40 * 1024 * 1024);
    // The admin enters the gateway addresses before anything renders.
    assert!(render_scripts(&wizard).is_err());
    wizard.gateway_ips = vec!["203.0.113.10".parse().unwrap()];
    let scripts = render_scripts(&wizard).unwrap();
    assert!(scripts
        .transport
        .contains("-MaxReceiveSize 40MB -MaxSendSize 40MB"));
    assert!(scripts.receive.contains("Exchange Server 2016"));
    // Config::default has a gateway certificate, but domain secure is opt in:
    // only a client certificate set on the route turns it on.
    assert!(cfg.tls.cert.is_some());
    assert!(!wizard.domain_secure);
    if let Some(MailboxPlatform::ExchangeOnPrem {
        client_cert,
        client_key,
        ..
    }) = &mut cfg.domains.routes[0].platform
    {
        *client_cert = Some("/etc/currawong/exchange-client.pem".into());
        *client_key = Some("/etc/currawong/exchange-client.key".into());
    }
    let wizard = ExchangeOnboarding::from_config(&cfg, "AGENCY.example.").unwrap();
    assert!(wizard.domain_secure);

    assert!(ExchangeOnboarding::from_config(&cfg, "other.example").is_err());
}
