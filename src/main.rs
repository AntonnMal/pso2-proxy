use proxy::{handle_con, handle_con_ex};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::error;
use std::io;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::{
    collections::{hash_map, HashMap},
    net::SocketAddr,
};

fn main() -> Result<(), Box<dyn error::Error>> {
    match std::fs::create_dir("captures") {
        Ok(()) => {}
        Err(x) if x.kind() == io::ErrorKind::AlreadyExists => {}
        Err(x) => return Err(x.into()),
    };
    match std::fs::metadata("client_privkey.pem") {
        Ok(..) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("No client keyfile found, creating...");
            let mut rand_gen = rand::thread_rng();
            let key = RsaPrivateKey::new(&mut rand_gen, 1024)?;
            key.write_pkcs8_pem_file("client_privkey.pem", rsa::pkcs8::LineEnding::default())?;
        }
        Err(e) => {
            return Err(e.into());
        }
    }
    match std::fs::metadata("server_pubkey.pem") {
        Ok(..) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("server_pubkey.pem not found");
        }
        Err(e) => {
            return Err(e.into());
        }
    }
    let mut info_listeners: Vec<TcpListener> = Vec::new();
    let mut server_listeners: HashMap<u16, (TcpListener, SocketAddr)> = HashMap::new();
    let to_open = Arc::new(Mutex::new(Vec::<(SocketAddr, u16)>::new()));
    info_listeners.push(TcpListener::bind("0.0.0.0:12199")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12180")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12280")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12299")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12194")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12294")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12394")?);
    info_listeners.push(TcpListener::bind("0.0.0.0:12494")?);
    info_listeners
        .iter_mut()
        .map(|x| x.set_nonblocking(true).unwrap())
        .count();

    let rt = tokio::runtime::Runtime::new()?;

    loop {
        for info_listener in &info_listeners {
            'outer_loop: for stream in info_listener.incoming() {
                match stream {
                    Ok(s) => {
                        let _guard = rt.enter();
                        tokio::spawn(handle_con(
                            s,
                            SocketAddr::new([40, 91, 76, 146].into(), 12199),
                            Arc::clone(&to_open),
                        ));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        break 'outer_loop;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
            let mut to_open_local = Vec::<(SocketAddr, u16)>::new();
            {
                to_open_local.append(&mut to_open.lock().unwrap());
            }
            for ip in to_open_local {
                if let hash_map::Entry::Vacant(entry) = server_listeners.entry(ip.1) {
                    let bind = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], ip.1)))?;
                    bind.set_nonblocking(true).unwrap();
                    entry.insert((bind, ip.0));
                }
            }
        }
        for (server_listener, ip) in server_listeners.values() {
            'outer_loop: for stream in server_listener.incoming() {
                match stream {
                    Ok(s) => {
                        let _guard = rt.enter();
                        let port = ip.port();
                        tokio::spawn(handle_con_ex(
                            s,
                            SocketAddr::new(ip.ip(), port),
                            Arc::clone(&to_open),
                        ));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        break 'outer_loop;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
