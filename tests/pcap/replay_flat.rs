#![allow(dead_code)]

use super::RaFrame;
use crate::fixtures::mock_socket::MockIcmpv6Socket;

pub async fn replay(socket: &MockIcmpv6Socket, frames: impl IntoIterator<Item = RaFrame>) {
    for frame in frames {
        socket.inject_ra(frame.ifindex, frame.src, frame.payload);
        tokio::task::yield_now().await;
    }
}
