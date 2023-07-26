use chrono::TimeZone;
use chrono::Utc;
use ppak_reader::PpacReader;
use pso2packetlib::protocol::Packet;
use std::{env, fs::File, io::Write};

fn main() {
    let mut args = env::args();
    args.next();
    let filename = args.next().unwrap();
    let mut text = filename.clone();
    let out_dir = filename.replace(".", "");
    let _ = std::fs::create_dir(&out_dir);
    let mut objects = out_dir.clone();
    objects.push_str("/objects");
    let _ = std::fs::create_dir(&objects);
    let mut npcs = out_dir.clone();
    npcs.push_str("/npcs");
    let _ = std::fs::create_dir(&npcs);
    text.push_str(".txt");
    let mut ppac = PpacReader::new(File::open(&filename).unwrap()).unwrap();
    let mut out_file = File::create(&text).unwrap();
    while let Ok(packet) = ppac.read() {
        let dir = match ppac.dir & 1 {
            0 => "(C -> S)",
            _ => "(S -> C)",
        };
        let timestamp = Utc.timestamp(
            (ppac.time / 1000000000) as i64,
            (ppac.time % 1000000000) as u32,
        );
        match packet {
            Packet::Unknown((header, data)) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} {{ id: {:X}, subid: {:X}, flags: {:?} }}",
                    timestamp.format("%Y-%m-%d_%H-%M-%S%.f"),
                    header.id,
                    header.subid,
                    header.flag
                )
                .unwrap();
                let out_name =
                    format!("{out_dir}/{}_{:X}_{:X}", ppac.time, header.id, header.subid);
                File::create(out_name).unwrap().write_all(&data).unwrap();
            }
            Packet::LoadItemAttributes(_) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} FileTransfer",
                    timestamp.format("%Y-%m-%d_%H-%M-%S%.f")
                )
                .unwrap();
            }
            Packet::ObjectSpawn(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} ObjectSpawn({p:?})",
                    timestamp.format("%Y-%m-%d_%H-%M-%S%.f")
                )
                .unwrap();
                let out_name = format!("{objects}/{}_{}.txt", p.object.id, ppac.time);
                File::create(out_name)
                    .unwrap()
                    .write_all(&serde_json::to_string_pretty(&p).unwrap().as_bytes())
                    .unwrap();
            }
            Packet::NPCSpawn(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} NPCSpawn({p:?})",
                    timestamp.format("%Y-%m-%d_%H-%M-%S%.f")
                )
                .unwrap();
                let out_name = format!("{npcs}/{}_{}.txt", p.object.id, ppac.time);
                File::create(out_name)
                    .unwrap()
                    .write_all(&serde_json::to_string_pretty(&p).unwrap().as_bytes())
                    .unwrap();
            }
            Packet::None => break,
            x => writeln!(
                &mut out_file,
                "{dir} {} {x:?}",
                timestamp.format("%Y-%m-%d_%H-%M-%S%.f")
            )
            .unwrap(),
        }
    }
}
