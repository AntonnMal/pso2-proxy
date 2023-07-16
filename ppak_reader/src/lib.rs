use std::{fs::File, time::Duration, io::ErrorKind, io::{Read, Seek, SeekFrom}};

use byteorder::{ReadBytesExt, LittleEndian};
use pso2packetlib::protocol::Packet;

pub struct ppac_reader {
    file: File,
    pub time: u128,
    pub data: Vec<u8>,
    pub dir: u8,
    packets: Vec<Packet>
}
impl ppac_reader {
    pub fn new(mut file: File) -> std::io::Result<Self> {
        let mut buf = [0u8; 4];
        file.read_exact(&mut buf)?;
        if &buf != b"PPAC" {
            return Err(ErrorKind::Other.into());
        }
        file.seek(SeekFrom::Current(1))?;
        Ok(Self { file: file, time: 0, data: vec![], dir: 0, packets: vec![] })
    }

    pub fn read(&mut self) -> std::io::Result<Packet> {
        if !self.packets.is_empty() {
            return Ok(self.packets.drain(0..1).next().unwrap())
        }
        let time = match self.file.read_u128::<LittleEndian>() {
            Ok(x) => x,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(Packet::None),
            Err(e) => return Err(e),
        };
        self.time = time;
        self.dir = self.file.read_u8()?;
        let len = self.file.read_u64::<LittleEndian>()?;
        let mut data = vec![];
        self.file.by_ref().take(len).read_to_end(&mut data)?;
        self.packets.append(&mut Packet::read(&data, true).unwrap());
        self.data = data;
        Ok(self.packets.drain(0..1).next().unwrap())
    }
}