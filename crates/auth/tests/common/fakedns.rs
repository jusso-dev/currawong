//! Minimal UDP DNS server for tests: answers TXT queries from a map, NXDOMAIN
//! for unknown names, SERVFAIL for names marked failing. Shared with the
//! currawongd tests through `#[path]`.
#![allow(dead_code)]
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::UdpSocket;

#[derive(Default)]
struct Zone {
    txt: HashMap<String, Vec<String>>,
    servfail: HashSet<String>,
    queries: Vec<String>,
}

#[derive(Clone)]
pub struct FakeDns {
    pub addr: SocketAddr,
    zone: Arc<Mutex<Zone>>,
}

impl FakeDns {
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let zone = Arc::new(Mutex::new(Zone::default()));
        let served = Arc::clone(&zone);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if let Some(reply) = answer(&buf[..len], &served) {
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        });
        Self { addr, zone }
    }

    pub fn txt(&self, name: &str, value: &str) {
        self.zone
            .lock()
            .unwrap()
            .txt
            .entry(canonical(name))
            .or_default()
            .push(value.into());
    }

    pub fn servfail(&self, name: &str) {
        self.zone.lock().unwrap().servfail.insert(canonical(name));
    }

    pub fn queries(&self, name: &str) -> usize {
        let name = canonical(name);
        self.zone
            .lock()
            .unwrap()
            .queries
            .iter()
            .filter(|item| **item == name)
            .count()
    }
}

fn canonical(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn answer(query: &[u8], zone: &Mutex<Zone>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut index = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query.get(index)? as usize;
        index += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(query.get(index..index + len)?).to_ascii_lowercase());
        index += len;
    }
    let qtype = u16::from_be_bytes([*query.get(index)?, *query.get(index + 1)?]);
    let question_end = index + 4;
    let name = labels.join(".");
    let mut zone = zone.lock().unwrap();
    zone.queries.push(name.clone());
    let (rcode, records) = if zone.servfail.contains(&name) {
        (2u8, Vec::new())
    } else {
        match zone.txt.get(&name) {
            Some(values) if qtype == 16 => (0, values.clone()),
            Some(_) => (0, Vec::new()),
            None => (3, Vec::new()),
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.push(0x81 | (query[2] & 0x01));
    out.push(0x80 | rcode);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..question_end]);
    for value in records {
        let mut rdata = Vec::new();
        for chunk in value.as_bytes().chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
        out.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1]);
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}
