#include <std/mem.pat>
#include <std/string.pat>
#include <std/time.pat>
#pragma pattern_limit 100000000
#pragma array_limit 100000000
struct Header {
    char Magic[4];
    if (Magic != "\x50\x50\x41\x43") {
        return 1;
    }
    u8 Ver;
};

bitfield flags {
    dir: 1 [[format("getdir")]]; 
    enc_type: 2 [[format("getenc")]];
    is_comp: 1;
    padding: 4;
};

struct Packet_header_v1 {
    u64 timestamp [[format("gettime")]];
    u8 dir [[format("getdir")]];
    u64 len;
};

struct Packet_header_v2 {
    u128 timestamp [[format("gettime_m")]];
    flags flags ;
    u64 len;
};

struct Packet_v1 {
    Packet_header_v1 packet_header;
    u8 data[packet_header.len] [[color("00008F")]];
};

struct Packet_v2 {
    Packet_header_v2 packet_header;
    u8 data[packet_header.len] [[color("00008F")]];
};

struct file {
    Header header;
    if (header.Ver == 3) {
    u8 is_ngs;
    }
    if (header.Ver == 1) {
        Packet_v1 packet[while(!std::mem::eof())];
    }
    if (header.Ver == 2 || header.Ver == 3) {
        Packet_v2 packet[while(!std::mem::eof())];
    }
};

fn gettime(u64 timestamp) {
    return std::time::format(std::time::to_local(timestamp), "%Y-%m-%d %H:%M:%S");
};

fn gettime_m(u128 timestamp) {
    u64 time_low = timestamp / 1000000000;
    u64 time_high = timestamp % 1000000000;
    str time_str = std::time::format(std::time::to_local(time_low), "%Y-%m-%d %H:%M:%S");
    time_str += ".";
    time_str += std::string::to_string(time_high);
    return time_str;
};

fn getdir(u8 dir) {
    if (dir == 0) {return "To server";}
    else if (dir == 1) {return "To client";}
};
fn getenc(u8 enc) {
    if (enc == 0) {return "None";}
    else if (enc == 1) {return "AES (NGS)";}
    else if (enc == 3) {return "RC4";}
};
file header @ 0x0;