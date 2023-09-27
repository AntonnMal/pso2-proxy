use chrono::TimeZone;
use chrono::Utc;
use pso2packetlib::{
    ppac::{Direction, OutputType, PPACReader, PacketData},
    protocol::Packet,
};
use std::{env, fs::File, io::Write};

fn main() {
    let mut args = env::args();
    args.next();
    let filename = args.next().unwrap();

    let mut text = filename.clone();
    let mut map_data: Option<ppak_reader::MapData> = None;
    let out_dir = filename.replace(".", "");
    let _ = std::fs::create_dir(&out_dir);
    let mut objects = out_dir.clone();
    objects.push_str("/objects");
    let _ = std::fs::create_dir(&objects);
    let mut npcs = out_dir.clone();
    npcs.push_str("/npcs");
    let _ = std::fs::create_dir(&npcs);
    let mut dmg_text = text.clone();
    dmg_text.push_str("dmg.txt");
    text.push_str(".txt");
    let mut ppac = PPACReader::open(File::open(&filename).unwrap()).unwrap();
    ppac.set_out_type(OutputType::Both);
    let mut out_file = File::create(&text).unwrap();
    let mut dmg_out_file = File::create(&dmg_text).unwrap();
    while let Ok(Some(PacketData {
        time,
        direction,
        packet,
        data,
        ..
    })) = ppac.read()
    {
        let packet = match packet {
            Some(x) => x,
            None => pso2packetlib::protocol::Packet::Raw(data.unwrap()),
        };
        let time = time.as_nanos();
        let dir = match direction {
            Direction::ToServer => "(C -> S)",
            Direction::ToClient => "(S -> C)",
        };
        let timestamp = Utc
            .timestamp_opt((time / 1000000000) as i64, (time % 1000000000) as u32)
            .unwrap();
        match packet {
            Packet::None => break,
            Packet::Unknown((header, data)) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} {{ id: {:X}, subid: {:X}, flags: {:?} }}",
                    timestamp.format("%H-%M-%S"),
                    header.id,
                    header.subid,
                    header.flag
                )
                .unwrap();
                if header.id == 3 && header.subid == 0 {
                    if let Some(data) = map_data {
                        let out_name =
                            format!("{out_dir}/map_{}_{}.json", time, data.map_data.unk7.clone());
                        serde_json::to_writer_pretty(&File::create(out_name).unwrap(), &data)
                            .unwrap();
                        map_data = None;
                    }
                }
                let out_name = format!("{out_dir}/{}_{:X}_{:X}", time, header.id, header.subid);
                File::create(out_name).unwrap().write_all(&data).unwrap();
            }
            Packet::Raw(data) => {
                let header = u32::from_be_bytes(data[4..8].try_into().unwrap());
                writeln!(
                    &mut out_file,
                    "{dir} {} RAW {{ header: {:X} }}",
                    timestamp.format("%H-%M-%S"),
                    header
                )
                .unwrap();
                let out_name = format!("{out_dir}/{}_{:X}", time, header);
                File::create(out_name).unwrap().write_all(&data).unwrap();
            }
            Packet::LoadLevel(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} LoadLevel({p:?})",
                    timestamp.format("%H-%M-%S")
                )
                .unwrap();
                if let Some(data) = map_data {
                    let out_name =
                        format!("{out_dir}/map_{}_{}.json", time, data.map_data.unk7.clone());
                    serde_json::to_writer_pretty(&File::create(out_name).unwrap(), &data).unwrap();
                }
                map_data = Some(ppak_reader::MapData {
                    map_data: p,
                    objects: vec![],
                    npcs: vec![],
                    default_location: Default::default(),
                });
            }
            Packet::LoadItemAttributes(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} LoadItemAttributes(id: {})",
                    timestamp.format("%H-%M-%S"),
                    p.id
                )
                .unwrap();
                let out_name = format!("{out_dir}/item_attr_{}.bin", time);
                File::create(out_name).unwrap().write_all(&p.data).unwrap();
            }
            Packet::ObjectSpawn(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} ObjectSpawn({p:?})",
                    timestamp.format("%H-%M-%S")
                )
                .unwrap();
                if let Some(ref mut data) = map_data {
                    data.objects.push(p.clone());
                }
                let out_name = format!("{objects}/{}_{}.txt", p.object.id, time);
                File::create(out_name)
                    .unwrap()
                    .write_all(&serde_json::to_string_pretty(&p).unwrap().as_bytes())
                    .unwrap();
            }
            Packet::NPCSpawn(p) => {
                writeln!(
                    &mut out_file,
                    "{dir} {} NPCSpawn({p:?})",
                    timestamp.format("%H-%M-%S")
                )
                .unwrap();
                if let Some(ref mut data) = map_data {
                    data.npcs.push(p.clone());
                }
                let out_name = format!("{npcs}/{}_{}.txt", p.object.id, time);
                File::create(out_name)
                    .unwrap()
                    .write_all(&serde_json::to_string_pretty(&p).unwrap().as_bytes())
                    .unwrap();
            }
            Packet::ClientPing(_) => {}
            Packet::ClientPong(_) => {}
            x => {
                writeln!(
                    &mut out_file,
                    "{dir} {} {x:?}",
                    timestamp.format("%H-%M-%S")
                )
                .unwrap();
                if let Packet::DealDamage(p) = &x {
                    writeln!(&mut dmg_out_file, "{} {p:?}", timestamp.format("%H-%M-%S")).unwrap()
                }
                if let Packet::DamageReceive(p) = &x {
                    writeln!(&mut dmg_out_file, "{} {p:?}", timestamp.format("%H-%M-%S")).unwrap()
                }
            }
        }
    }
    if let Some(data) = map_data {
        let out_name = format!("{out_dir}/map_final_{}.json", data.map_data.unk7.clone());
        serde_json::to_writer_pretty(&File::create(out_name).unwrap(), &data).unwrap();
    }
}
