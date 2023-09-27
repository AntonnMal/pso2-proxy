use pso2packetlib::protocol::{
    server::LoadLevelPacket,
    spawn::{NPCSpawnPacket, ObjectSpawnPacket},
};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct MapData {
    pub map_data: LoadLevelPacket,
    pub objects: Vec<ObjectSpawnPacket>,
    pub npcs: Vec<NPCSpawnPacket>,
    pub default_location: pso2packetlib::protocol::models::Position,
}
