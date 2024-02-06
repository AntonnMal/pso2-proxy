use parking_lot::Mutex;
use pso2packetlib::{
    ppac::Direction,
    protocol::{PacketType, ProxyPacket},
    PrivateKey, ProxyConnection, PublicKey,
};
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    ship_ip: String,
    capture_folder: String,
    sega_key: String,
    user_key: String,
    #[serde(skip)]
    ip: SocketAddr,
}

impl Settings {
    async fn load(path: &str) -> Result<Settings, Box<dyn Error>> {
        let string = match tokio::fs::read_to_string(path).await {
            Ok(s) => s,
            Err(_) => {
                let settings = Settings::default();
                tokio::fs::write(path, toml::to_string_pretty(&settings)?).await?;
                return Ok(settings);
            }
        };
        Ok(toml::from_str(&string)?)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ship_ip: "gs0100.westus2.cloudapp.azure.com:12180".into(),
            capture_folder: "captures".into(),
            sega_key: "server_pubkey.pem".into(),
            user_key: "client_privkey.pem".into(),
            ip: "40.91.76.146:12180".parse().unwrap(),
        }
    }
}

#[derive(Default)]
struct Listeners {
    to_open: Vec<(SocketAddr, u16)>,
    open: Vec<SocketAddr>,
    opened_ports: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub ip: Ipv4Addr,
    pub key: Vec<u8>,
}

pub async fn run() -> Result<(), Box<dyn Error>> {
    let mut settings = Settings::load("proxy.toml").await?;
    settings.ip = tokio::net::lookup_host(&settings.ship_ip)
        .await?
        .next()
        .unwrap();
    match std::fs::create_dir(&settings.capture_folder) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    };
    match std::fs::metadata(&settings.user_key) {
        Ok(..) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("No client keyfile found, creating...");
            let mut rand_gen = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rand_gen, 1024)?;
            key.write_pkcs8_pem_file(&settings.user_key, rsa::pkcs8::LineEnding::default())?;
        }
        Err(e) => {
            return Err(e.into());
        }
    }
    match std::fs::metadata(&settings.sega_key) {
        Ok(..) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("{} not found", &settings.sega_key);
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
    }
    let settings = Arc::new(settings);
    let listeners = Arc::new(Mutex::new(Listeners::default()));
    create_ship_listeners(listeners.clone(), settings.clone()).await?;
    tokio::spawn(make_keys(settings.clone()));

    loop {
        for ip in listeners.lock().to_open.drain(..) {
            create_listener(listeners.clone(), settings.clone(), ip.0, ip.1).await?;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn create_ship_listeners(
    sockets: Arc<Mutex<Listeners>>,
    settings: Arc<Settings>,
) -> Result<(), Box<dyn Error>> {
    let mut listeners = vec![];
    for i in 0..10 {
        // jp ports
        listeners.push(TcpListener::bind(("0.0.0.0", 12099 + (i * 100))).await?);
        // global ports
        listeners.push(TcpListener::bind(("0.0.0.0", 12080 + (i * 100))).await?);
    }
    for listener in listeners {
        let sockets = sockets.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((s, _)) => {
                        tokio::spawn(handle_con(
                            s.into_std().unwrap(),
                            settings.clone(),
                            settings.ip,
                            sockets.clone(),
                        ));
                    }
                    Err(e) => {
                        eprintln!("Failed to accept connection: {e}");
                        return;
                    }
                }
            }
        });
    }

    Ok(())
}

async fn create_listener(
    sockets: Arc<Mutex<Listeners>>,
    settings: Arc<Settings>,
    ip: SocketAddr,
    port: u16,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(handle_con(
                        s.into_std().unwrap(),
                        settings.clone(),
                        ip,
                        sockets.clone(),
                    ));
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {e}");
                    return;
                }
            }
        }
    });
    Ok(())
}

async fn make_keys(settings: Arc<Settings>) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", 11000)).await?;
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                let _ = send_keys(s, settings.clone());
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                return Err(e);
            }
        }
    }
}

async fn handle_con(
    in_stream: std::net::TcpStream,
    settings: Arc<Settings>,
    address: SocketAddr,
    sockets: Arc<Mutex<Listeners>>,
) -> io::Result<()> {
    println!("Got connection");
    in_stream.set_nonblocking(true)?;
    in_stream.set_nodelay(true)?;
    in_stream.set_ttl(100)?;
    let callback_ip = match in_stream.local_addr()?.ip() {
        std::net::IpAddr::V4(x) => x,
        std::net::IpAddr::V6(_) => unimplemented!(),
    };
    let mut client_stream = ProxyConnection::new(
        in_stream,
        PacketType::NGS,
        PrivateKey::Path((&settings.user_key).into()),
        PublicKey::None,
    );
    let serv_stream = std::net::TcpStream::connect(address)?;
    serv_stream.set_nonblocking(true)?;
    serv_stream.set_nodelay(true)?;
    serv_stream.set_ttl(100)?;
    let mut serv_stream = ProxyConnection::new(
        serv_stream,
        PacketType::NGS,
        PrivateKey::Path((&settings.user_key).into()),
        PublicKey::Path((&settings.sega_key).into()),
    );

    serv_stream.create_ppac(
        format!(
            "{}/{}-{}.pak",
            settings.capture_folder,
            chrono::Local::now().format("%Y-%m-%d_%H-%M-%S"),
            address.port()
        ),
        Direction::ToServer,
    )?;

    loop {
        match read_packet(
            &mut client_stream,
            &mut serv_stream,
            Direction::ToServer,
            &sockets,
            callback_ip,
        )
        .await
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                println!("User disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        match read_packet(
            &mut serv_stream,
            &mut client_stream,
            Direction::ToClient,
            &sockets,
            callback_ip,
        )
        .await
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                println!("User disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let _ = client_stream.flush();
        let _ = serv_stream.flush();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn read_packet(
    in_conn: &mut ProxyConnection,
    out_conn: &mut ProxyConnection,
    dir: Direction,
    sockets: &Mutex<Listeners>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    match in_conn.read_packet() {
        Ok(mut packet) => {
            parse_packet(&mut packet, dir, sockets, callback_ip)?;
            match out_conn.write_packet(&packet) {
                Ok(_) => {}
                Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
                Err(x) => return Err(x),
            }
        }
        Err(x) if x.kind() == io::ErrorKind::WouldBlock => {}
        Err(x) => return Err(x),
    }
    Ok(())
}

fn parse_packet(
    packet: &mut ProxyPacket,
    dir: Direction,
    sockets: &Mutex<Listeners>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    if let ProxyPacket::Unknown(data) = packet {
        let id = data.0.id;
        let sub_id = data.0.subid;
        write_packet(id, sub_id, dir);
        match (id, sub_id) {
            // block balance
            (0x11, 0x2C) => replace_balance(&mut data.1[..], sockets, callback_ip)?,
            // block switch packet
            (0x11, 0x13) => replace_pso2(&mut data.1[..], sockets, callback_ip)?,
            // personal quarters
            (0x11, 0x17) => replace_pq(&mut data.1[..], sockets, callback_ip)?,
            // alliance quarters
            (0x11, 0x4F) => replace_aq(&mut data.1[..], sockets, callback_ip)?,
            // creative space
            (0x11, 0x121) => replace_cc(&mut data.1[..], sockets, callback_ip)?,
            // shared ship
            (0x11, 0x21) => replace_shareship(&mut data.1[..], sockets, callback_ip)?,
            _ => {}
        }
    } else if let ProxyPacket::ShipList(ships) = packet {
        for ship in &mut ships.ships {
            let ip = ship.ip;
            let ship_id = ship.id / 1000;
            let port_offset = match ship_id {
                1..=9 => ship_id * 100,
                10 => 0,
                _ => continue,
            };
            let global_port = (12081 + port_offset) as u16;
            push_listener(sockets, SocketAddr::from((ip, global_port)));
            let jp_port = (12000 + port_offset) as u16;
            push_listener(sockets, SocketAddr::from((ip, jp_port)));
            ship.ip = callback_ip;
        }
    }
    Ok(())
}

fn push_listener(sockets: &Mutex<Listeners>, address: SocketAddr) {
    let mut lock = sockets.lock();
    if !lock.open.contains(&address) {
        lock.to_open.push((address, address.port()));
        lock.open.push(address);
        lock.opened_ports.push(address.port());
    }
}
fn push_listener_var(sockets: &Mutex<Listeners>, address: SocketAddr) -> u16 {
    let mut lock = sockets.lock();
    if !lock.open.contains(&address) {
        let mut port = address.port();
        loop {
            if !lock.opened_ports.contains(&port) {
                break;
            }
            port += 1;
        }
        lock.to_open.push((address, port));
        lock.open.push(address);
        lock.opened_ports.push(port);
        port
    } else {
        let (pos, _) = lock
            .open
            .iter()
            .enumerate()
            .find(|(_, &a)| a == address)
            .unwrap();
        lock.opened_ports[pos]
    }
}

fn write_packet(id: u8, subid: u16, dir: Direction) {
    let dir = match dir {
        Direction::ToServer => "C->S",
        Direction::ToClient => "S->C",
    };
    println!("{dir}: {id:X}, {subid:X}");
}

fn replace_balance(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn replace_pso2(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn replace_pq(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn replace_aq(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn replace_cc(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn replace_shareship(
    buff: &mut [u8],
    sockets: &Mutex<Listeners>,
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port)));
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

fn send_keys(stream: TcpStream, settings: Arc<Settings>) -> Result<(), Box<dyn Error>> {
    let mut stream = stream.into_std()?;
    stream.set_nodelay(true)?;
    let IpAddr::V4(ip) = stream.local_addr()?.ip() else {
        unimplemented!()
    };
    let key = RsaPrivateKey::read_pkcs8_pem_file(&settings.user_key)?;
    let n = key.n().to_bytes_le();
    let e = key.e().to_bytes_le();
    let mut data = vec![];
    {
        let mut key = vec![0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00];
        key.append(&mut b"RSA1".to_vec());
        key.append(&mut (n.len() as u32 * 8).to_le_bytes().to_vec());
        let mut e = e;
        e.resize(4, 0);
        key.append(&mut e);
        key.append(&mut n.to_vec());
        data.push(Keys { ip, key })
    }
    let mut data = rmp_serde::to_vec(&data)?;
    let mut out_data = Vec::with_capacity(data.len());
    out_data.append(&mut (data.len() as u32).to_le_bytes().to_vec());
    out_data.append(&mut data);
    stream.write_all(&out_data)?;
    Ok(())
}
