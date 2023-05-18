use std::fs::File;
use std::io::prelude::*;
use std::process::exit;
use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use ipnetwork::Ipv4Network;

pub fn is_this_ip_in_this_cidr(ip: &str, cidr: &str) -> bool {
  let net: Ipv4Network = cidr.parse().unwrap();
  let net2 = ip.parse().unwrap();
  net.contains(net2)
}

pub fn init() -> Root {
  let file = File::open("./data.json");

  if file.is_err() {
    println!("error1");
    exit(1)
  }

  let mut file_data = file.unwrap();

  let mut contents = String::new();
  file_data.read_to_string(&mut contents);
  
  let dat: Result<Root, serde_json::Error> = serde_json::from_str(&contents);
  if dat.is_err() {
    println!("{:#?}", dat.err());
    exit(1)
  }
  // println!("{:#?}", dat.unwrap());
  return dat.unwrap();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    #[serde(rename = "Interfaces")]
    pub interfaces: Interfaces,
    #[serde(rename = "IPToInterface")]
    pub ipto_interface: IptoInterface,
    #[serde(rename = "SecurityGroups")]
    pub security_groups: SecurityGroups,
    #[serde(rename = "ITToGroup")]
    pub iptosgs: IptoSGs
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Interfaces {
  #[serde(flatten)]
  pub interface_id: std::collections::HashMap<String, Interface>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Interface {
    #[serde(rename = "interface_type")]
    pub interface_type: String,
    #[serde(rename = "security_groups")]
    pub security_groups: Vec<String>,
    pub requester_id: String,
    pub interface_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IptoInterface {
    #[serde(flatten)]
    pub iptointerface: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IptoSGs {
  #[serde(flatten)]
  pub iptosgs: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityGroups {
    #[serde(flatten)]
    pub sgrules: std::collections::HashMap<String, Vec<SecurityGroupRule>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityGroupRule {
  #[serde(flatten)]
    pub rule: Rule,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(rename = "SecurityGroupRuleId")]
    pub security_group_rule_id: String,
    #[serde(rename = "GroupId")]
    pub group_id: String,
    #[serde(rename = "GroupOwnerId")]
    pub group_owner_id: String,
    #[serde(rename = "IsEgress")]
    pub is_egress: bool,
    #[serde(rename = "IpProtocol")]
    pub ip_protocol: String,
    #[serde(rename = "FromPort")]
    pub from_port: i64,
    #[serde(rename = "ToPort")]
    pub to_port: i64,
    #[serde(rename = "CidrIpv4")]
    pub cidr_ipv4: Option<String>,
    #[serde(rename = "ReferencedGroupInfo")]
    pub referenced_group_info: Option<ReferencedGroupInfo>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Tags")]
    pub tags: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReferencedGroupInfo {
    #[serde(rename = "GroupId")]
    pub group_id: String,
    #[serde(rename = "UserId")]
    pub user_id: String,
}

pub fn get_int_id_from_ip<'a>(ip_addr: &'a str, dat: &'a Root) -> Option<&'a String> {
  let iptointerface = &dat.ipto_interface.iptointerface;
  iptointerface.get(ip_addr)
}

pub fn get_sgs_attached<'a>(int_id: &'a str, dat: &'a Root) -> Option<&'a Interface> {
  let x = &dat.interfaces.interface_id;
  x.get(int_id)
}

pub fn get_sgs_on_ip<'a>(int_ip: &'a str, dat: &'a Root) -> Option<&'a Vec<String>> {
  let x = &dat.iptosgs.iptosgs;
  x.get(int_ip)
}

pub fn ip_allowed_in_sg(int_ip: &str, sg_id: &str, dat: &Root, sgs_vec: Option<&Vec<String>>) -> Option<String> {
  let x = &dat.security_groups.sgrules;
  let sgrules_vec_opt = x.get(sg_id);

  if sgrules_vec_opt.is_some() {
    let sgrules_vec = sgrules_vec_opt.unwrap();

    for rule in sgrules_vec {
      // let rule_tmp = rule.rule;
      if rule.rule.cidr_ipv4.is_some() {
        let source_ipv4 = rule.rule.cidr_ipv4.as_ref().unwrap();
        if is_this_ip_in_this_cidr(int_ip, &source_ipv4) {
          return Some(rule.rule.security_group_rule_id.to_string());
        }
      } else if rule.rule.referenced_group_info.is_some() {
        let source_sg = rule.rule.referenced_group_info.as_ref().unwrap();
        let source_sg_name = source_sg.group_id.to_string();

        if sgs_vec.is_some(){
          let tmp = sgs_vec.unwrap();
          for j in tmp {
            if j.to_string() == source_sg_name {
              return Some(rule.rule.security_group_rule_id.to_string());
            }
          }
        }
      }
    }
  }

  None
}

pub fn get_rules_from_sg<'a>(sg_id: &'a str, dat: &'a Root) -> Option<&'a Vec<SecurityGroupRule>> {
  let x = &dat.security_groups.sgrules;
  x.get(sg_id)
}

pub fn get_sourcegroup_from_iip(int_ip: &str, dat: &Root) -> String {
  let k = dat.ipto_interface.iptointerface.get(int_ip);
  if k.is_some() {
    let interface_id = k.unwrap();
    let x = &dat.interfaces.interface_id;
    x.get(interface_id).unwrap().interface_name.to_string()
  } else {
    "dontknow".to_string()
  }
}

pub fn get_int_type_from_id<'a>(int_id: &'a str, dat: &'a Root) -> String {
  let x = &dat.interfaces.interface_id;

  let interface_type = &x.get(int_id).unwrap().interface_type;
  let requester_id = &x.get(int_id).unwrap().requester_id;

  if interface_type == "interface" && requester_id == "aws-elb" {
    "aws-elb".to_string()
  } else if interface_type == "network_load_balancer" {
    "aws-nlb".to_string()
  } else if interface_type == "interface" {
    "aws-ec2".to_string()
  } else {
    "junk".to_string()
  }
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum TrafficNode {
  LoadBalancer(String),
  EC2(String),
  SecurityGroup(String),
  Other(String)
}

impl TrafficNode {
  pub fn is_other(self) -> bool {
    match self {
      TrafficNode::Other(_) => true,
      TrafficNode::EC2(_) => false,
      TrafficNode::SecurityGroup(_) => false,
      TrafficNode::LoadBalancer(_) => false,
    }
  }
}
