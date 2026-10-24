#![allow(dead_code)]
//! In-process HTTP fake shared by scan and daemon integration tests.
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[derive(Clone, Debug)]
pub struct Request {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Response {
    pub fn json(value: serde_json::Value) -> Self {
        Self::bytes(serde_json::to_vec(&value).unwrap())
    }
    pub fn bytes(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.into(),
        }
    }
}
pub struct Server {
    pub url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    job: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Server {
    pub async fn start(reply: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let reply = Arc::new(reply);
        let job = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let reply = reply.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut block = [0; 8192];
                    let end = loop {
                        let n = stream.read(&mut block).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&block[..n]);
                        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        assert!(bytes.len() < 65536);
                    };
                    let text = String::from_utf8(bytes[..end].to_vec()).unwrap();
                    let mut lines = text.split("\r\n");
                    let path = lines
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .to_string();
                    let headers: Vec<_> = lines
                        .filter_map(|l| {
                            l.split_once(':')
                                .map(|(n, v)| (n.to_string(), v.trim().to_string()))
                        })
                        .collect();
                    let len = headers
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    assert!(len < 64 * 1024 * 1024);
                    while bytes.len() < end + len {
                        let n = stream.read(&mut block).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&block[..n]);
                    }
                    let request = Request {
                        path,
                        headers,
                        body: bytes[end..end + len].to_vec(),
                    };
                    let response = reply(&request);
                    recorded.lock().unwrap().push(request);
                    let declared = response
                        .headers
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));
                    let mut head =
                        format!("HTTP/1.1 {} Test\r\nConnection: close\r\n", response.status);
                    if !declared {
                        head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
                    }
                    for (n, v) in response.headers {
                        head.push_str(&format!("{n}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&response.body).await;
                });
            }
        });
        Self { url, requests, job }
    }
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}
pub async fn unavailable_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}
