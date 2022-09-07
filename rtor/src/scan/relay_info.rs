use std::{net::SocketAddr, hash::Hash};
use anyhow::{Result, anyhow};
use serde::{Serialize, Serializer, ser::SerializeStruct, Deserialize};
use tor_guardmgr::fallback::FallbackDir;
use tor_guardmgr::fallback::FallbackDirBuilder;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::Relay;
use tor_netdoc::doc::netstatus::RelayFlags;
use tor_linkspec::HasRelayIds;
// use tor_linkspec::HasRelayIdsLegacy;
use tor_linkspec::HasAddrs;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayInfo {
    pub id: Ed25519Identity,
    pub rsa_id: RsaIdentity,
    pub addrs: Vec<SocketAddr>,
    pub flags: RelayFlagsInfo,
}

impl RelayInfo {
    pub fn is_flagged_guard(&self) -> bool {
        self.flags.0.contains(RelayFlags::GUARD)
    }
}

impl TryFrom<Relay<'_>> for RelayInfo {
    type Error = anyhow::Error;

    fn try_from(relay: Relay<'_>) -> Result<Self, Self::Error> {
        Ok(Self { 
            id: relay.id().clone(),
            rsa_id: relay.rsa_identity().ok_or_else(||anyhow!("no rsa_identity"))?.clone(),
            addrs: relay.rs().addrs().into(),
            flags: RelayFlagsInfo(*relay.rs().flags()),
        })
    }
}

// impl From<Relay<'_>> for RelayInfo {
//     fn from(relay: Relay<'_>) -> Self {
//         Self { 
//             id: relay.id().clone(),
//             ed_id: relay.ed_identity().clone(),
//             addrs: relay.rs().addrs().into(),
//             flags: RelayFlagsInfo(*relay.rs().flags()),
//         }
//     }
// }

impl From<&FallbackDir> for RelayInfo {
    fn from(relay: &FallbackDir) -> Self {
        Self { 
            id: relay.ed_identity().expect("fallback dir has no ed-id").clone(),
            rsa_id: relay.rsa_identity().expect("fallback dir has no rsa_identity").clone(),
            addrs: relay.addrs().into(),
            flags: RelayFlagsInfo(RelayFlags::HSDIR),
        }
    }
}

impl From<&RelayInfo> for FallbackDirBuilder {
    fn from(relay: &RelayInfo) -> Self {
        let mut bld = FallbackDir::builder();
        bld
        .rsa_identity(relay.rsa_id.clone())
        .ed_identity(relay.id.clone());

        relay.addrs.iter()
        .for_each(|p| {
                bld.orports().push(p.clone());
        });

        bld
    }
}

impl From<RelayInfo> for FallbackDirBuilder {
    fn from(relay: RelayInfo) -> Self {
        let mut bld = FallbackDir::builder();
        bld
        .rsa_identity(relay.rsa_id)
        .ed_identity(relay.id);

        relay.addrs.into_iter()
        .for_each(|p| {
                bld.orports().push(p);
        });

        bld
    }
}



impl<'a> GetAddrs<'a> for RelayInfo {
    type Iter = std::slice::Iter<'a, SocketAddr>;
    fn get_addrs(&'a self) -> Self::Iter {
        self.addrs.iter()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelayFlagsInfo(pub RelayFlags);

impl Serialize for RelayFlagsInfo
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let number = self.0.bits();
        let desc = format!("{:?}", self.0);
        let mut serial = serializer.serialize_struct("flags", 2)?;
        serial.serialize_field("num", &number)?;
        serial.serialize_field("desc", &desc)?;
        serial.end()
    }
}


use serde::de::{self, Deserializer, Visitor, MapAccess};

use super::tcp_scan::GetAddrs;

impl<'de> Deserialize<'de> for RelayFlagsInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Num, Desc }

        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = RelayFlagsInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct RelayFlagsInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RelayFlagsInfo, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut num = None;
                let mut desc: Option<String> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Num => {
                            if num.is_some() {
                                return Err(de::Error::duplicate_field("num"));
                            }
                            num = Some(map.next_value()?);
                        }
                        Field::Desc => {
                            if desc.is_some() {
                                return Err(de::Error::duplicate_field("desc"));
                            }
                            desc = Some(map.next_value()?);
                        }
                    }
                }
                let num = num.ok_or_else(|| de::Error::missing_field("num"))?;
                let flags = RelayFlags::from_bits(num).ok_or_else(|| de::Error::invalid_value(de::Unexpected::Other("invalid num of flags"), &self))?;
                Ok(RelayFlagsInfo(flags))
            }
        }


        const FIELDS: &'static [&'static str] = &["secs", "nanos"];
        deserializer.deserialize_struct("Duration", FIELDS, ValueVisitor)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRelay(pub RelayInfo);

impl Hash for HashRelay {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.id.hash(state);
    }
}

impl PartialEq for HashRelay {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for HashRelay {}


// pub(crate) fn make_test_relay_info() -> RelayInfo {
//     use std::net::{IpAddr, Ipv4Addr};
//     RelayInfo {
//         id: Ed25519Identity::new([1; 32]),
//         addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)],
//         flags: RelayFlagsInfo(RelayFlags::EXIT | RelayFlags::GUARD),
//     }
// }

#[test]
fn test_relay_info() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr};
    let relay = RelayInfo {
        id: Ed25519Identity::new([1; 32]),
        rsa_id: RsaIdentity::from_hex("EF18418EE9B5E5CCD0BB7546869AC10BA625BAC8").expect("wrong hex"),
        addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)],
        flags: RelayFlagsInfo(RelayFlags::EXIT | RelayFlags::GUARD),
    };
    let json_str = serde_json::to_string(&relay)?;
    let de_relay: RelayInfo = serde_json::from_str(&json_str)?;
    assert_eq!(relay, de_relay);
    Ok(())
}


