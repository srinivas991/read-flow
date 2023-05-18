use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::format;
use std::process::exit;
use std::{env};
use std::fs::{File};
use std::io::{prelude::*, BufReader};
use std::time::Instant;

use aws::Root;
use aws::TrafficNode;

extern crate flate2;

mod aws;
mod lib;

#[derive(Eq, Hash, PartialEq, Debug)]
struct Flow {
  Source: TrafficNode,
  SGGroup: TrafficNode,
  Destination: TrafficNode,
}

// define what all is required to parse a specific entry
#[derive(Eq, Hash, PartialEq)]
struct LogEntryStruct {
  source_ip: String,
  source_group: String,
  destination_group: String,
  destination_ip: String,
  destination_port: i32,
  protocol: String
}

impl LogEntryStruct {

  // this should tell us which SG Rule allowed this entry

  // HOW: get the destination interface, get the SGs attached to the destination interface
  // allowed as a CIDR Block, Source SG, ignore sources from other VPCs

  // need to get the SG rules

  // CIDR: check if destination is in the allowed CIDR and the port is also allowed in the rule

  // Source SG: need to get the source interface ID, SGs attached to the interface, check if the SG in the rule
  // is in the set of those interfaces
  pub fn parse_entry(self, dat: &Root, st_final: &mut HashSet<String>) {
    // let xx = format!("{} -> {}", self.source_group, self.destination_group);

    let sgs = aws::get_sgs_on_ip(&self.destination_ip, dat);
    let sgs_src: Option<&Vec<String>> = aws::get_sgs_on_ip(&self.source_ip, dat);
    if sgs.is_none() {
      return;
    }

    let sgs_vec: &Vec<String> = sgs.unwrap();
    for sg_id in sgs_vec {

      let xyz = aws::ip_allowed_in_sg(&self.source_ip, sg_id, dat, sgs_src);
      if xyz.is_some() {
        // let yy = format!("{} -> {}/{} -> {}", self.source_group, sg_id, xyz.unwrap(), self.destination_group);
        let yy = format!("{}/{}, {} -> {}", sg_id, xyz.unwrap(), self.source_group, self.destination_group);
        st_final.insert(yy);
      }
    }
  }
}

// enum for Log type, in AWS VPCs you have different log types
// Simple -> vpc-id version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
// enum FlowLog {
//   Simple(String)
// }

// impl FlowLog {
//   pub fn get_entry(self, dat: &Root) -> LogEntryStruct {
//     match self {
//       FlowLog::Simple(value) => {
//         let split_vec: Vec<String> = value.split(" ").map(|s| s.to_string()).collect();
//         LogEntryStruct {
//           source_ip:        aws::get_sourcegroup_from_iip(&split_vec[19], dat),
//           destination_ip:   aws::get_sourcegroup_from_iip(&split_vec[5], dat),
//           source_port:      split_vec[20].parse().unwrap(),
//           destination_port: split_vec[6].parse().unwrap(),
//           protocol:         split_vec[17].to_string(),
//         }
//       }
//     }
//   }
// }

// fn create_entry(log_entry: &str, dat: &Root, st_final: &mut HashSet<Flow>, st_entries: &mut HashSet<String>) {
//   let tmp: String = log_entry.to_string();
//   let flow_log = FlowLog::Simple(tmp);
//   let entrystruct = flow_log.get_entry(dat);
//   st_entries.insert(entrystruct);
//   // entrystruct.parse_entry(dat, st_final);
// }

fn parse_files(files: Vec<&str>) {
  for j in files {
    parse_file(j)
  }
}

// TODO: Pre process flow logs to reduce the number of entries
// done by replacing IP with Group and have only relevant fields
fn parse_file(file_name: &str) {
// simply bypass if the line entry contains "REJECT"
  let ret: aws::Root = aws::init();
  let mut st_final: HashSet<String> = HashSet::new();
  let mut st_entries: HashSet<String> = HashSet::new();

  // read file line by line
  let lines = read_gz_lines(file_name);
  // println!("{}", lines.len());
  for j in lines {
    st_entries.insert(j);
  }

  let vv = [80,443,53,2020,8080,8181,9091,9100,9253,9256, 9620, 10249, 10250, 10256, 30081, 30082, 30083, 30084, 31002, 32081, 32082, 32083, 61678];

  // println!("{}", st_entries.len());
  for j in st_entries {
    let split_vec: Vec<String> = j.split(" ").map(|s| s.to_string()).collect();
    let dst_port = split_vec[4].to_string().parse().unwrap();
    if vv.contains(&dst_port) {
    let les = LogEntryStruct {
      source_ip: split_vec[0].to_string(),
      source_group: split_vec[1].to_string(),
      destination_ip: split_vec[2].to_string(),
      destination_group: split_vec[3].to_string(),
      destination_port: split_vec[4].parse().unwrap(),
      protocol: split_vec[5].to_string()
    };
    les.parse_entry(&ret, &mut st_final);}
  }

  for j in st_final {
    println!("{}", j)
  }
}

fn read_gz_lines(filename: &str) -> Vec<String> {
  let f = File::open(filename);
  let decoder_new = flate2::read::GzDecoder::new(f.unwrap());

  let reader = BufReader::new(decoder_new);

  let mut ret = Vec::new();
  for line in reader.lines() {
      match line {
          Ok(v) => {
              ret.push(v);
          },
          Err(e) => println!("{}", e),
      }
  }
  ret
}

fn main() {
  let args: Vec<String> = env::args().collect();
  let file_name = &args[1];

  let start_time = Instant::now();
  parse_file(file_name);
  let end_time = Instant::now();
  let elapsed_time = end_time - start_time;
  println!("Time taken: {:?}", elapsed_time);
}
