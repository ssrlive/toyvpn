use futures::StreamExt;
use packet::ip::Packet;
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

extern crate tun;
use tun::AsyncDevice;

use std::env;

pub struct Server {
    pub socket: UdpSocket,
    secret: String,
    parameters: String,
}

struct ClientNode {
    iface: AsyncDevice,
    verified: bool,
}

impl Server {
    async fn run(self) -> Result<(), io::Error> {
        let mut clients = HashMap::new();

        let mut buf = vec![0; 0x1_0000];

        loop {
            let (data_size, addr) = self.socket.recv_from(&mut buf).await?;
            if data_size == 0 {
                continue;
            }

            let client_node = clients.entry(addr).or_insert_with(|| ClientNode {
                iface: Server::create_interface(),
                verified: false,
            });
            if !client_node.verified {
                if Server::verify_package(&buf, &self.secret) {
                    client_node.verified = true;

                    let res = Server::build_parameters_vec(&self.parameters);
                    self.socket.send_to(&res, addr).await?;

                    println!("incoming node {}", addr);
                }
                continue;
            }

            if buf[0] == 0 {
                self.socket.send_to(&buf[..data_size], addr).await?;
                continue;
            }

            // write package to TUN interface
        }
    }

    fn create_interface() -> AsyncDevice {
        let mut config = tun::Configuration::default();

        config
            .address((10, 0, 0, 2))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 1))
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });

        return tun::create_as_async(&config).unwrap();
    }

    fn verify_package(pkg: &Vec<u8>, secret: &str) -> bool {
        if pkg.get(0) != Some(&0) {
            return false;
        }
        let s = match String::from_utf8(pkg[1..].to_vec()) {
            Ok(v) => v,
            Err(_) => "".to_string(),
        };
        if !secret.eq(&s) {
            return false;
        }
        return true;
    }

    fn build_parameters_vec(param: &String) -> Vec<u8> {
        let mut res = param.as_bytes().to_owned();
        res[0] = 0;
        return res;
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8088".to_string());

    let socket = UdpSocket::bind(&addr).await?;
    println!("Udp listening on: {}", socket.local_addr()?);

    let server = Server {
        socket,
        secret: "test".to_string(),
        parameters: " m,1400 a,10.10.0.2,32 d,8.8.8.8 r,0.0.0.0,0".to_string(),
    };

    // This starts the server task.
    server.run().await?;

    Ok(())
}

/*
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut config = tun::Configuration::default();

    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create_as_async(&config).unwrap();
    let sock = UdpSocket::bind("0.0.0.0:8082").await?;
    let remote_addr = "127.0.0.1:8081".parse::<SocketAddr>().unwrap();
    sock.connect(remote_addr).await?;
    let mut outlet = UdpOutlet::new(sock);
    println!("started");
    let (u, d) = tokio::io::copy_bidirectional(&mut outlet, &mut dev).await?;
    println!("up: {}, down: {}", u, d);
    Ok(())
}
// */

/*
fn main() {
    let mut config = tun::Configuration::default();
    config.address((10, 0, 0, 1))
           .netmask((255, 255, 255, 0))
           .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create(&config).unwrap();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        println!("{:?}", &buf[0 .. amount]);
    }
}
// */
