#![allow(clippy::await_holding_lock)]
use pso2packetlib::{
    ppac::Direction,
    protocol::{PacketType, ProxyPacket},
    PrivateKey, ProxyConnection, ProxyRead, ProxyWrite, PublicKey,
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
use tokio::sync::Mutex;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    ship_ip: String,
    capture_folder: String,
    sega_key: String,
    user_key: String,
    log_level: log::LevelFilter,
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
            log_level: log::LevelFilter::Debug,
            ip: "40.91.76.146:12180".parse().unwrap(),
        }
    }
}

struct Listeners {
    to_open: Sender<(SocketAddr, u16)>,
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
    {
        use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
        TermLogger::init(
            settings.log_level,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap();
    }
    settings.ip = match tokio::net::lookup_host(&settings.ship_ip).await?.next() {
        Some(ip) => ip,
        None => {
            return Err("No address found for the ship ip!".into());
        }
    };
    match std::fs::create_dir(&settings.capture_folder) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    };
    match std::fs::metadata(&settings.user_key) {
        Ok(..) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log::info!("No client keyfile found, creating...");
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
            log::error!("{} not found", &settings.sega_key);
            return Ok(());
        }
        Err(e) => {
            return Err(e.into());
        }
    }
    let settings = Arc::new(settings);
    let (send, mut recv) = tokio::sync::mpsc::channel(10);
    let listeners = Arc::new(Mutex::new(Listeners {
        to_open: send,
        open: vec![],
        opened_ports: vec![],
    }));
    create_ship_listeners(listeners.clone(), settings.clone()).await?;
    tokio::spawn(make_keys(settings.clone()));
    log::info!("Proxy started");

    while let Some((ip, port)) = recv.recv().await {
        create_listener(listeners.clone(), settings.clone(), ip, port).await?;
    }
    Ok(())
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
                        tokio::spawn(connection_handler(
                            s,
                            settings.clone(),
                            settings.ip,
                            sockets.clone(),
                        ));
                    }
                    Err(e) => {
                        log::error!("Failed to accept connection: {e}");
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
                    tokio::spawn(connection_handler(s, settings.clone(), ip, sockets.clone()));
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {e}");
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
                let _ = send_keys(s, settings.clone()).await;
            }
            Err(e) => {
                log::error!("Failed to accept connection: {e}");
                return Err(e);
            }
        }
    }
}

async fn connection_handler(
    in_stream: TcpStream,
    settings: Arc<Settings>,
    address: SocketAddr,
    sockets: Arc<Mutex<Listeners>>,
) -> io::Result<()> {
    log::info!("Got connection");
    in_stream.set_nodelay(true)?;
    in_stream.set_ttl(100)?;
    let local_ip = match in_stream.local_addr()?.ip() {
        std::net::IpAddr::V4(x) => x,
        std::net::IpAddr::V6(_) => unimplemented!(),
    };
    let client_stream = ProxyConnection::new_async(
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
    let (client_read, client_write) = client_stream.into_split()?;
    let (server_read, server_write) = serv_stream.into_split()?;

    tokio::spawn(handle_loop(
        client_read,
        server_write,
        Direction::ToServer,
        sockets.clone(),
        local_ip,
    ));
    tokio::spawn(handle_loop(
        server_read,
        client_write,
        Direction::ToClient,
        sockets,
        local_ip,
    ));

    Ok(())
}

async fn handle_loop(
    mut read: ProxyRead,
    mut write: ProxyWrite,
    dir: Direction,
    sockets: Arc<Mutex<Listeners>>,
    callback_ip: Ipv4Addr,
) {
    loop {
        let read_future = read_packet(&mut read, &mut write, dir, &sockets, callback_ip);

        // this future has a timeout so we can flush the data periodically
        match tokio::time::timeout(Duration::from_millis(10000), read_future).await {
            Ok(Ok(_)) => {}
            Err(_) => {}
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                ) =>
            {
                if matches!(dir, Direction::ToClient) {
                    log::info!("User disconnected");
                }
                return;
            }
            Ok(Err(e)) => {
                log::error!("Failed to read data: {e}");
                return;
            }
        }
        let _ = write.flush_async().await;
    }
}

async fn read_packet(
    in_conn: &mut ProxyRead,
    out_conn: &mut ProxyWrite,
    dir: Direction,
    sockets: &Mutex<Listeners>,
    callback_ip: Ipv4Addr,
) -> io::Result<()> {
    match in_conn.read_packet_async().await {
        Ok(mut packet) => {
            parse_packet(&mut packet, dir, sockets, callback_ip).await?;
            match out_conn.write_packet_async(&packet).await {
                Ok(_) => {}
                Err(x) => return Err(x),
            }
        }
        Err(x) => return Err(x),
    }
    Ok(())
}

async fn parse_packet(
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
            (0x11, 0x2C) => replace_balance(&mut data.1[..], sockets, callback_ip).await?,
            // block switch packet
            (0x11, 0x13) => replace_pso2(&mut data.1[..], sockets, callback_ip).await?,
            // personal quarters
            (0x11, 0x17) => replace_pq(&mut data.1[..], sockets, callback_ip).await?,
            // alliance quarters
            (0x11, 0x4F) => replace_aq(&mut data.1[..], sockets, callback_ip).await?,
            // creative space
            (0x11, 0x121) => replace_cc(&mut data.1[..], sockets, callback_ip).await?,
            // shared ship
            (0x11, 0x21) => replace_shareship(&mut data.1[..], sockets, callback_ip).await?,
            _ => {}
        }
    } else if let ProxyPacket::ShipList(ships) = packet {
        log::debug!("Got ship list");
        for ship in &mut ships.ships {
            let ip = ship.ip;
            log::trace!("Parsing ship with id: {}, ip: {ip}", ship.id);
            let ship_id = ship.id / 1000;
            let port_offset = match ship_id {
                1..=9 => ship_id * 100,
                10 => 0,
                _ => continue,
            };
            let global_port = (12081 + port_offset) as u16;
            push_listener(sockets, SocketAddr::from((ip, global_port))).await;
            let jp_port = (12000 + port_offset) as u16;
            push_listener(sockets, SocketAddr::from((ip, jp_port))).await;
            ship.ip = callback_ip;
        }
    }
    Ok(())
}

async fn push_listener(sockets: &Mutex<Listeners>, address: SocketAddr) {
    let mut lock = sockets.lock().await;
    if !lock.open.contains(&address) {
        log::debug!("Mapping {}:{}", address.ip(), address.port());
        let _ = lock.to_open.send((address, address.port())).await;
        lock.open.push(address);
        lock.opened_ports.push(address.port());
    }
}
async fn push_listener_var(sockets: &Mutex<Listeners>, address: SocketAddr) -> u16 {
    let mut lock = sockets.lock().await;
    if !lock.open.contains(&address) {
        let mut port = address.port();
        loop {
            if !lock.opened_ports.contains(&port) {
                break;
            }
            port += 1;
        }
        log::debug!("Mapping {}:{} <-> {port}", address.ip(), address.port());
        let _ = lock.to_open.send((address, port)).await;
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
        let port = lock.opened_ports[pos];
        log::debug!(
            "Already mapped: {port} <-> {}:{}",
            address.ip(),
            address.port()
        );
        port
    }
}

fn write_packet(id: u8, subid: u16, dir: Direction) {
    let dir = match dir {
        Direction::ToServer => "C->S",
        Direction::ToClient => "S->C",
    };
    log::info!("{dir}: {id:X}, {subid:X}");
}

async fn replace_balance(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn replace_pso2(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn replace_pq(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn replace_aq(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn replace_cc(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn replace_shareship(
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
    let port = push_listener_var(sockets, SocketAddr::from((ip, port))).await;
    change_data.seek(SeekFrom::Current(-2))?;
    change_data.write_all(&port.to_le_bytes())?;
    Ok(())
}

async fn send_keys(mut stream: TcpStream, settings: Arc<Settings>) -> Result<(), Box<dyn Error>> {
    use tokio::io::AsyncWriteExt;
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
    let mut out_data = Vec::with_capacity(data.len() + 4);
    out_data.append(&mut (data.len() as u32).to_le_bytes().to_vec());
    out_data.append(&mut data);
    stream.write_all(&out_data).await?;
    Ok(())
}
