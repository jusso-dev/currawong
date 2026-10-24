use currawong_core::{
    config::{Config, OutbreakConfig},
    MessageId, ScanReport,
};

#[test]
fn outbreak_config_disabled_bounds_and_unknown_fields() {
    let cfg = OutbreakConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.retention_days, 14);
    assert_eq!(cfg.hold_minutes, 30);
    assert_eq!(cfg.retain_parts_hours, 0);
    cfg.validate().unwrap();
    assert!(toml::from_str::<OutbreakConfig>("enable = true").is_err());
    for config in [
        OutbreakConfig {
            retention_days: 0,
            ..cfg.clone()
        },
        OutbreakConfig {
            max_messages: 0,
            ..cfg.clone()
        },
        OutbreakConfig {
            hold_types: vec!["typo".into()],
            ..cfg.clone()
        },
        OutbreakConfig {
            retain_parts_hours: 9999,
            ..cfg.clone()
        },
        OutbreakConfig {
            known_clean_sha256: vec!["not hash".into()],
            ..cfg.clone()
        },
    ] {
        assert!(config.validate().is_err());
    }
    let mut cfg = Config::default();
    cfg.outbreak.enabled = true;
    cfg.scanner.enabled = false;
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("outbreak requires scanner"));
}

#[test]
fn old_report_without_outbreak_still_deserialises() {
    let mut json = serde_json::to_value(ScanReport::new(MessageId("one".into()))).unwrap();
    json.as_object_mut().unwrap().remove("outbreak");
    let report: ScanReport = serde_json::from_value(json).unwrap();
    assert!(report.outbreak.is_none());
}
