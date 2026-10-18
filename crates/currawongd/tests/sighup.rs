//! End to end: the real `currawongd` binary swaps its TLS certificate on
//! SIGHUP while the listener keeps accepting and open sessions carry on.
#![cfg(unix)]
use rcgen::generate_simple_self_signed;
use std::{
    net::{SocketAddr, TcpListener as StdListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

const WAIT: Duration = Duration::from_secs(60);

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Write a fresh self-signed pair for `localhost` through rename, the way
/// an operator or certbot hook replaces files. Returns the certificate DER.
fn install_cert(dir: &Path) -> Vec<u8> {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for (name, body) in [
        ("key.pem", key_pair.serialize_pem()),
        ("cert.pem", cert.pem()),
    ] {
        let tmp = dir.join(format!("{name}.new"));
        std::fs::write(&tmp, body).unwrap();
        std::fs::rename(&tmp, dir.join(name)).unwrap();
    }
    cert.der().to_vec()
}

/// Trust any certificate but record it: the test compares the leaf the
/// daemon presents, not a chain.
#[derive(Debug)]
struct Record(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for Record {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

struct Session {
    tls: BufReader<TlsStream<TcpStream>>,
    leaf: Vec<u8>,
}

impl Session {
    async fn open(addr: SocketAddr) -> std::io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Record(provider)))
            .with_no_client_auth();
        let sock = TcpStream::connect(addr).await?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                sock,
            )
            .await?;
        let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
        let mut session = Self {
            tls: BufReader::new(tls),
            leaf,
        };
        let greeting = session.reply().await;
        assert!(greeting.starts_with("220"), "{greeting}");
        Ok(session)
    }

    /// Read a whole reply, multi-line included.
    async fn reply(&mut self) -> String {
        let mut reply = String::new();
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(WAIT, self.tls.read_line(&mut line))
                .await
                .expect("reply timed out")
                .unwrap();
            assert!(read > 0, "connection closed after {reply:?}");
            reply.push_str(&line);
            if line.as_bytes().get(3) != Some(&b'-') {
                return reply;
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> String {
        self.tls
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        self.reply().await
    }
}

fn hangup(daemon: &Daemon) {
    // Safety: plain kill(2) on our own child's pid.
    let rc = unsafe { libc::kill(daemon.0.id() as libc::pid_t, libc::SIGHUP) };
    assert_eq!(rc, 0, "kill -HUP failed");
}

/// Connect until the daemon presents `want`. Every attempt must connect and
/// handshake: a refused connection means the listener went away.
async fn wait_for_leaf(addr: SocketAddr, want: &[u8], daemon: &mut Daemon) -> Session {
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(daemon.0.try_wait().unwrap().is_none(), "currawongd exited");
        let session = Session::open(addr)
            .await
            .expect("listener refused a connection during reload");
        if session.leaf == want {
            return session;
        }
        assert!(Instant::now() < deadline, "certificate was never swapped");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn sighup_swaps_the_certificate_without_dropping_the_listener() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let cert_a = install_cert(root);
    let smtps: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let metrics = format!("127.0.0.1:{}", free_port());
    let s = |name: &str| state.join(name).display().to_string();
    let config = format!(
        r#"
[metrics]
listen = "{metrics}"

[spool]
dir = "{spool}"

[[listeners]]
name = "submissions"
bind = "{smtps}"
mode = "implicit"
role = "inbound"

[tls]
cert = "{cert}"
key = "{key}"

[scanner]
enabled = false

[residency]
report_dir = "{residency}"

[delivery]
tls_database = "{tls_db}"

[checks]
greylist_database = "{greylist}"

[relay]
database = "{relay}"

[dkim]
database = "{dkim}"
kek_path = "{kek}"

[classify]
enabled = false
bayes_database = "{bayes}"
history_database = "{history}"
"#,
        spool = s("spool"),
        cert = root.join("cert.pem").display(),
        key = root.join("key.pem").display(),
        residency = s("residency"),
        tls_db = s("tls.sqlite"),
        greylist = s("greylist.sqlite"),
        relay = s("relay.sqlite"),
        dkim = s("dkim.sqlite"),
        kek = s("dkim.kek"),
        bayes = s("bayes.sqlite"),
        history = s("history.sqlite"),
    );
    let config_path = root.join("currawong.toml");
    std::fs::write(&config_path, config).unwrap();
    let log = std::fs::File::create(root.join("currawongd.log")).unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_currawongd"))
            .arg("--config")
            .arg(&config_path)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let logs = || std::fs::read_to_string(root.join("currawongd.log")).unwrap_or_default();

    // Wait for the listener.
    let deadline = Instant::now() + WAIT;
    let mut held = loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            panic!("currawongd exited with {status}:\n{}", logs());
        }
        if let Ok(session) = Session::open(smtps).await {
            break session;
        }
        assert!(Instant::now() < deadline, "no listener:\n{}", logs());
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(held.leaf, cert_a);

    // New pair on disk, then SIGHUP: new handshakes see it.
    let cert_b = install_cert(root);
    assert_ne!(cert_a, cert_b);
    hangup(&daemon);
    let mut fresh = wait_for_leaf(smtps, &cert_b, &mut daemon).await;
    assert!(fresh.cmd("EHLO client.test").await.starts_with("250"));

    // The session opened before the reload still works.
    let ehlo = held.cmd("EHLO client.test").await;
    assert!(ehlo.starts_with("250"), "{ehlo}");
    assert!(held.cmd("QUIT").await.starts_with("221"));

    // A broken file is refused and the loaded certificate stays in use.
    std::fs::write(root.join("cert.pem"), "not a certificate").unwrap();
    hangup(&daemon);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !logs().contains("SIGHUP certificate reload failed") {
        assert!(
            Instant::now() < deadline,
            "no reload error logged:\n{}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let after = Session::open(smtps).await.expect("listener still up");
    assert_eq!(after.leaf, cert_b);
    assert!(daemon.0.try_wait().unwrap().is_none(), "currawongd exited");
}
