use pso2packetlib::ppac::Direction;
use pso2packetlib::protocol::{Packet, PacketType};
use pso2packetlib::Connection;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

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
    let mut client_stream = Connection::new(
        in_stream,
        PacketType::NGS,
        Some("client_privkey.pem".into()),
        None,
    );
    let serv_stream = std::net::TcpStream::connect(address)?;
    serv_stream.set_nonblocking(true)?;
    serv_stream.set_nodelay(true)?;
    serv_stream.set_ttl(100)?;
    let mut serv_stream = Connection::new(
        serv_stream,
        PacketType::NGS,
        Some("client_privkey.pem".into()),
        Some("server_pubkey.pem".into()),
    );

    serv_stream.create_ppac(
        format!(
            "captures/{}-{}.pak",
            chrono::Local::now().format("%Y-%m-%d_%H-%M-%S"),
            address.port()
        ),
        Direction::ToServer,
    )?;

    loop {
        match client_stream.read_packet() {
            Ok(mut packet) => {
                parse_paket(&mut packet, 0, &to_open, callback_ip)?;
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
                parse_paket(&mut packet, 1, &to_open, callback_ip)?;
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
    dir: u8,
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    if let Packet::Unknown(data) = packet {
        let id = data.0.id;
        let sub_id = data.0.subid;
        write_packet(id, sub_id, dir);
        match (id, sub_id) {
            (0x11, 0x2c) => replace_balance(&mut data.1[..], to_open, callback_ip)?,
            (0x11, 0x13) => replace_pso2(&mut data.1[..], to_open, callback_ip)?,
            (0x11, 0x17) => replace_pq(&mut data.1[..], to_open, callback_ip)?,
            (0x11, 0x4F) => replace_aq(&mut data.1[..], to_open, callback_ip)?,
            //creative space
            (0x11, 0x121) => replace_cc(&mut data.1[..], to_open, callback_ip)?,
            //shared ship
            (0x11, 0x21) => replace_shareship(&mut data.1[..], to_open, callback_ip)?,
            _ => {}
        }
    } else if let Packet::ShipList(ships) = packet {
        for ship in &mut ships.ships {
            let ip = ship.ip;
            // In JP version, port distribution is from 12000 (i.e. Ship 10) to 12900 (for Ship 9) so the formula need change to something like
            // let port = (12000 + (100 * (ship.id / 1000 % 10) )) as u16;
            let port = (12181 + (100 * (ship.id / 1000 - 1))) as u16;
            to_open
                .lock()
                .unwrap()
                .push((SocketAddr::from((ip, port)), port));
            ship.ip = callback_ip;
        }
    }
    Ok(())
}

fn write_packet(id: u8, subid: u16, flags: u8) {
    let dir = if flags == 0 { "C->S" } else { "S->C" };
    println!("{dir}: {id:X}, {subid:X}");
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
    change_data.write_all(&(port + 2000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 2000));
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
    change_data.write_all(&(port + 2000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 2000));
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
    change_data.write_all(&(port + 2000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 2000));
    Ok(())
}

fn replace_aq(
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
    change_data.write_all(&(port + 2000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 2000));
    Ok(())
}

fn replace_cc(
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
    change_data.write_all(&(port + 2000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 2000));
    Ok(())
}

fn replace_shareship(
    buff: &mut [u8],
    to_open: &Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    let mut change_data = Cursor::new(buff);
    let mut ip = [0u8; 4];
    let mut port = [0u8; 2];
    change_data.set_position(0x0);
    change_data.read_exact(&mut ip)?;
    change_data.seek(SeekFrom::Current(-4))?;
    change_data.write_all(&callback_ip.octets())?;
    change_data.read_exact(&mut port)?;
    let port = u16::from_le_bytes(port);
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&(port + 3000).to_le_bytes())?;
    to_open
        .lock()
        .unwrap()
        .push((SocketAddr::from((ip, port)), port + 3000));
    Ok(())
}
