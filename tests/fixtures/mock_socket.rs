#![allow(dead_code)]

use ipv6_router_advertisement::InterfaceIndex;
use ipv6_router_advertisement::icmpv6_socket::Icmpv6Socket;
use std::collections::VecDeque;
use std::io;
use std::net::Ipv6Addr;
use std::sync::Mutex;
use tokio::sync::Notify;

#[derive(Default)]
pub struct MockIcmpv6Socket {
    incoming: Mutex<VecDeque<(InterfaceIndex, Ipv6Addr, Vec<u8>)>>,
    sent: Mutex<Vec<(InterfaceIndex, Ipv6Addr, Vec<u8>)>>,
    notify: Notify,
}

impl MockIcmpv6Socket {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject_ra(&self, ifindex: InterfaceIndex, router_ip: Ipv6Addr, payload: Vec<u8>) {
        self.incoming
            .lock()
            .unwrap()
            .push_back((ifindex, router_ip, payload));
        self.notify.notify_one();
    }

    pub fn sent_packets(&self) -> Vec<(InterfaceIndex, Ipv6Addr, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Icmpv6Socket for MockIcmpv6Socket {
    async fn receive(&self) -> io::Result<(InterfaceIndex, Ipv6Addr, Vec<u8>)> {
        loop {
            if let Some(pkt) = self.incoming.lock().unwrap().pop_front() {
                return Ok(pkt);
            }
            self.notify.notified().await;
        }
    }

    fn send(
        &self,
        ifindex: InterfaceIndex,
        destination: Ipv6Addr,
        payload: &[u8],
    ) -> io::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((ifindex, destination, payload.to_vec()));
        Ok(())
    }
}
