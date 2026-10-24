use currawong_core::{
    config::{ClickConfig, RdapConfig},
    Config,
};
#[test]
fn link_analysis_defaults_are_off_and_unknown_keys_fail() {
    assert!(!RdapConfig::default().enabled);
    assert!(!RdapConfig::default().scan_urls);
    assert!(!ClickConfig::default().fetch.enabled);
    assert!(ClickConfig::default().analyser.url.is_empty());
    assert!(toml::from_str::<ClickConfig>("fetchh = true").is_err());
    assert!(toml::from_str::<ClickConfig>("[fetch]\nenabeld=true").is_err());
    assert!(toml::from_str::<RdapConfig>("positive_ttl_day = 1").is_err());
}
#[test]
fn link_config_rejects_unbounded_limits_and_untrusted_analyser() {
    let mut cfg = Config::default();
    cfg.click.max_hops = 0;
    assert!(cfg.validate().unwrap_err().to_string().contains("click:"));
    cfg.click = ClickConfig::default();
    cfg.click.fetch.ports = vec![0];
    assert!(cfg.validate().unwrap_err().to_string().contains("click:"));
    cfg.click = ClickConfig::default();
    cfg.click.analyser.required = true;
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("required analyser needs an endpoint"));
    cfg.click = ClickConfig::default();
    cfg.rdap.bootstrap_url = "http://data.iana.org/rdap/dns.json".into();
    assert!(cfg.validate().unwrap_err().to_string().contains("rdap:"));
    cfg.rdap = RdapConfig::default();
    cfg.click.analyser.url = "https://service.example.net/analyse".into();
    assert!(cfg.validate().is_err());
}
