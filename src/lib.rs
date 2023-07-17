use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use pso2packetlib::protocol::Packet;
use pso2packetlib::Connection;

pub async fn handle_con_ex(
    in_stream: std::net::TcpStream,
    address: SocketAddr,
    to_open: Arc<Mutex<Vec<(SocketAddr, u16)>>>,
) {
    handle_con(in_stream, address, to_open).await.unwrap();
    println!("Closed connection");
}

pub async fn handle_con(
    in_stream: std::net::TcpStream,
    address: SocketAddr,
    to_open: Arc<Mutex<Vec<(SocketAddr, u16)>>>,
) -> io::Result<()> {
    println!("Got connection");
    in_stream.set_nonblocking(true)?;
    in_stream.set_nodelay(true)?;
    in_stream.set_ttl(100)?;
    let callback_ip = match in_stream.local_addr()?.ip() {
        std::net::IpAddr::V4(x) => x,
        std::net::IpAddr::V6(_) => unimplemented!(),
    };
    let mut client_stream =
        Connection::new(in_stream, true, Some("client_privkey.pem".into()), None);
    let serv_stream = std::net::TcpStream::connect(address)?;
    serv_stream.set_nonblocking(true)?;
    serv_stream.set_nodelay(true)?;
    serv_stream.set_ttl(100)?;
    let mut serv_stream = Connection::new(
        serv_stream,
        true,
        Some("client_privkey.pem".into()),
        Some("server_pubkey.pem".into()),
    );

    let mut file = File::create(format!(
        "captures/{}-{}.pak",
        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S"),
        address.port()
    ))?;
    file.write_all(b"PPAC")?;
    file.write_all(&2u8.to_ne_bytes())?;
    loop {
        match client_stream.read_packet() {
            Ok(mut packet) => {
                parse_paket(&mut packet, &mut file, 0, &to_open, callback_ip)?;
                match serv_stream.write_packet(&packet) {
                    Ok(_) => {}
                    Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
                    Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                        println!("Server disconnect");
                        return Ok(());
                    }
                    Err(x) => return Err(x),
                }
            }
            Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
            Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                println!("Client disconnect");
                return Ok(());
            }
            Err(x) => return Err(x),
        }
        match serv_stream.read_packet() {
            Ok(mut packet) => {
                parse_paket(&mut packet, &mut file, 1, &to_open, callback_ip)?;
                match client_stream.write_packet(&packet) {
                    Ok(_) => {}
                    Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
                    Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                        println!("Client disconnect");
                        return Ok(());
                    }
                    Err(x) => return Err(x),
                }
            }
            Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
            Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                println!("Server disconnect");
                return Ok(());
            }
            Err(x) => return Err(x),
        }
        match client_stream.flush() {
            Ok(_) => {}
            Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
            Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                println!("Client disconnect");
                return Ok(());
            }
            Err(x) => return Err(x),
        }
        match serv_stream.flush() {
            Ok(_) => {}
            Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
            Err(x) if x.kind() == io::ErrorKind::ConnectionAborted => {
                println!("Server disconnect");
                return Ok(());
            }
            Err(x) => return Err(x),
        }
    }
}

fn parse_paket(
    packet: &mut Packet,
    file: &mut impl Write,
    dir: u8,
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    write_packet(file, &packet.write(true), dir)?;
    if let Packet::Unknown(data) = packet {
        let id = data.0.id;
        let sub_id = data.0.subid;
        match (id, sub_id) {
            (0x11, 0x2c) => replace_balance(&mut data.1[..], to_open, callback_ip)?,
            (0x11, 0x13) => replace_pso2(&mut data.1[..], to_open, callback_ip)?,
            (0x11, 0x17) => replace_pq(&mut data.1[..], to_open, callback_ip)?,
            _ => {}
        }
    } else if let Packet::ShipList(ships) = packet {
        for ship in &mut ships.ships {
            let ip = ship.ip;
            let port = (12181 + (100 * (ship.id / 1000 - 1))) as u16;
            to_open
                .lock()
                .unwrap()
                .push((SocketAddr::from((ip, port)), port));
            ship.ip = callback_ip;
        }
    }
    // write_packet(file, &packet.write(true), dir)?;
    Ok(())
}

fn write_packet(file: &mut impl Write, buff: &[u8], flags: u8) -> io::Result<()> {
    if buff.is_empty() {
        return Ok(());
    }
    let dir = if flags == 0 { "C->S" } else { "S->C" };
    let (id, subid) = (buff[5], u16::from_le_bytes(buff[6..=7].try_into().unwrap()));
    println!("{dir}: {id:X}, {subid:X}");
    let time: u128 = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_nanos(),
        Err(..) => 0,
    };
    file.write_all(&time.to_le_bytes())?;
    file.write_all(&flags.to_le_bytes())?;
    file.write_all(&(buff.len() as u64).to_le_bytes())?;
    file.write_all(buff)?;
    Ok(())
}

fn replace_balance(
    buff: &mut [u8],
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    let mut change_data = Cursor::new(buff);
    let mut ip = [0u8; 4];
    let mut port = [0u8; 2];
    change_data.set_position(0x60);
    change_data.read_exact(&mut ip)?;
    change_data.seek(SeekFrom::Current(-4))?;
    change_data.write_all(&callback_ip.octets())?;
    change_data.read_exact(&mut port)?;
    let port = u16::from_le_bytes(port);
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&(port + 1000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 1000));
    Ok(())
}

fn replace_pso2(
    buff: &mut [u8],
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    let mut change_data = Cursor::new(buff);
    let mut ip = [0u8; 4];
    let mut port = [0u8; 2];
    change_data.set_position(0xC);
    change_data.read_exact(&mut ip)?;
    change_data.seek(SeekFrom::Current(-4))?;
    change_data.write_all(&callback_ip.octets())?;
    change_data.read_exact(&mut port)?;
    let port = u16::from_le_bytes(port);
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&(port + 1000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 1000));
    Ok(())
}

fn replace_pq(
    buff: &mut [u8],
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    let mut change_data = Cursor::new(buff);
    let mut ip = [0u8; 4];
    let mut port = [0u8; 2];
    change_data.set_position(0x18);
    change_data.read_exact(&mut ip)?;
    change_data.seek(SeekFrom::Current(-4))?;
    change_data.write_all(&callback_ip.octets())?;
    change_data.set_position(0x20);
    change_data.read_exact(&mut port)?;
    let port = u16::from_le_bytes(port);
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&(port + 1000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 1000));
    Ok(())
}
