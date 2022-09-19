use std::convert::TryFrom;
use std::sync::Arc;
use std::{net::SocketAddr, hash::Hash};
use anyhow::{Result, anyhow};
use serde::{Serialize, Serializer, ser::SerializeStruct, Deserialize};
use tor_guardmgr::fallback::FallbackDir;
use tor_guardmgr::fallback::FallbackDirBuilder;
use tor_linkspec::ChanTarget;
use tor_linkspec::CircTarget;
use tor_linkspec::RelayIdRef;
use tor_linkspec::RelayIdType;
use tor_linkspec::RelayIds;
use tor_llcrypto::pk;
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

    pub fn is_flagged_exit(&self) -> bool {
        self.flags.0.contains(RelayFlags::EXIT)
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



impl<'a> AddrsIter<'a> for RelayInfo {
    type Iter = std::slice::Iter<'a, SocketAddr>;
    fn addrs_iter(&'a self) -> Self::Iter {
        self.addrs.iter()
    }
}

impl HasRelayIds for RelayInfo {
    fn identity(&self, key_type: tor_linkspec::RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 => Some(RelayIdRef::Ed25519(&self.id)),
            RelayIdType::Rsa => Some(RelayIdRef::Rsa(&self.rsa_id)),
            _ => None,
        }
    }
}

impl HasAddrs for RelayInfo {
    fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

impl ChanTarget for RelayInfo {}

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

use super::tcp_scan::AddrsIter;

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


        const FIELDS: &'static [&'static str] = &["num", "desc"];
        deserializer.deserialize_struct("RelayFlagsInfo", FIELDS, ValueVisitor)
    }
}


// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct HashRelay(pub RelayInfo);

// impl Hash for HashRelay {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         self.0.id.hash(state);
//     }
// }

// impl PartialEq for HashRelay {
//     fn eq(&self, other: &Self) -> bool {
//         self.0.id == other.0.id
//     }
// }

// impl Eq for HashRelay {}

// impl From<RelayInfo> for HashRelay {
//     fn from(src: RelayInfo) -> Self {
//         Self(src)
//     }
// }

pub trait ToDebug<'a> {
    type Output: std::fmt::Debug;
    fn to_debug(&'a self) -> Self::Output;
}

impl<'a> ToDebug<'a> for Relay<'a> {
    type Output = RelayDebug<'a>;
    fn to_debug(&'a self) -> Self::Output {
        RelayDebug(self)
    }
}

pub struct RelayDebug<'a>(&'a Relay<'a>);

impl<'a> std::fmt::Debug for RelayDebug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
        .field("id", self.0.id())
        .field("rsa_id", self.0.rsa_id())
        .field("addrs", &self.0.addrs())
        .field("flags", self.0.rs().flags())
        .finish()
        // f.debug_tuple("RelayDebug").field(&self.0).finish()
    }
}

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


#[derive(Debug, Clone)]
pub struct OwnedRelay {
    addrs: Vec<SocketAddr>,
    ids: RelayIds,
    ntor_onion_key: pk::curve25519::PublicKey,
    protovers: tor_protover::Protocols,
    flags: RelayFlagsInfo,
}

impl OwnedRelay {
    pub fn get_id(&self) -> Result<&Ed25519Identity> {
        self.ed_identity().ok_or_else(||anyhow!("relay has no ed_identity"))
    }

    pub fn own_id(&self) -> Result<Ed25519Identity> {
        self.get_id().map(|v|v.clone())
    }

    pub fn flags(&self) -> RelayFlags {
        self.flags.0
    }

    pub fn is_flagged_guard(&self) -> bool {
        self.flags.0.contains(RelayFlags::GUARD)
    }

    pub fn is_flagged_exit(&self) -> bool {
        self.flags.0.contains(RelayFlags::EXIT)
    }
}

// impl OwnedRelay {
//     pub fn from_circ_target<C>(target: &C) -> Self
//     where
//         C: CircTarget + ?Sized,
//     {
//         OwnedRelay {
//             addrs: target.addrs().into(),
//             ids: RelayIds::from_relay_ids(target),
//             ntor_onion_key: *target.ntor_onion_key(),
//             protovers: target.protovers().clone(),
//         }
//     }
// }

// impl From<Relay<'_>> for OwnedRelay {
//     fn from(src: Relay<'_>) -> Self {
//         Self::from_circ_target(&src)
//     }
// }

// impl From<&Relay<'_>> for OwnedRelay {
//     fn from(src: &Relay<'_>) -> Self {
//         Self::from_circ_target(src)
//     }
// }

impl TryFrom<Relay<'_>> for OwnedRelay {
    type Error = anyhow::Error;

    fn try_from(src: Relay<'_>) -> Result<Self, Self::Error> {
        OwnedRelay::try_from(&src)
    }
}

impl TryFrom<&Relay<'_>> for OwnedRelay {
    type Error = anyhow::Error;

    fn try_from(src: &Relay<'_>) -> Result<Self, Self::Error> {
        let self0 = Self {
            addrs: src.addrs().into(),
            ids: RelayIds::from_relay_ids(src),
            ntor_onion_key: *src.ntor_onion_key(),
            protovers: src.protovers().clone(),
            flags: RelayFlagsInfo(*src.rs().flags()),
        };
        self0.ed_identity().ok_or_else(||anyhow!("relay has no ed_identity"))?;
        Ok(self0)
    }
}


impl From<&FallbackDir> for OwnedRelay {
    fn from(relay: &FallbackDir) -> Self {
        Self {
            addrs: relay.addrs().into(),
            ids: RelayIds::new(
                relay.ed_identity().expect("fallback dir has no ed-id").clone(), 
                relay.rsa_identity().expect("fallback dir has no rsa_identity").clone()
            ),
            // ntor_onion_key: todo!(),
            // protovers: todo!(), 

            // dummy
            ntor_onion_key: [99; 32].into(),
            protovers: "FlowCtrl=7".parse().expect("protovers impossible fail"),
            flags: RelayFlagsInfo(RelayFlags::HSDIR),
        }
    }
}

impl From<&OwnedRelay> for FallbackDirBuilder {
    fn from(relay: &OwnedRelay) -> Self {
        let mut bld = FallbackDir::builder();
        bld
        .rsa_identity(relay.rsa_identity().expect("has no rsa id").clone())
        .ed_identity(relay.ed_identity().expect("has no ed id").clone());

        relay.addrs.iter()
        .for_each(|p| {
                bld.orports().push(p.clone());
        });

        bld
    }
}

impl From<&OwnedRelay> for Arc<OwnedRelay> {
    fn from(relay: &OwnedRelay) -> Self {
        Arc::new(relay.clone())
    }
}

// impl From<OwnedRelay> for Arc<OwnedRelay> {
//     fn from(relay: OwnedRelay) -> Self {
//         Arc::new(relay)
//     }
// }

impl From<OwnedRelay> for (Ed25519Identity, Arc<OwnedRelay>) {
    fn from(relay: OwnedRelay) -> Self {
        (relay.own_id().unwrap(), relay.into())
    }
}


impl<'a> AddrsIter<'a> for OwnedRelay {
    type Iter = std::slice::Iter<'a, SocketAddr>;
    fn addrs_iter(&'a self) -> Self::Iter {
        self.addrs.iter()
    }
}

impl<'a> AddrsIter<'a> for Arc<OwnedRelay> {
    type Iter = std::slice::Iter<'a, SocketAddr>;
    fn addrs_iter(&'a self) -> Self::Iter {
        self.addrs.iter()
    }
}


impl HasAddrs for OwnedRelay {
    fn addrs(&self) -> &[SocketAddr] {
        &self.addrs[..]
    }
}

impl HasRelayIds for OwnedRelay {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.ids.identity(key_type)
    }
}

impl ChanTarget for OwnedRelay {}

impl CircTarget for OwnedRelay {
    fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
        &self.ntor_onion_key
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        &self.protovers
    }
}

impl std::fmt::Display for OwnedRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[")?;
        match &*self.addrs {
            [] => write!(f, "?")?,
            [a] => write!(f, "{}", a)?,
            [a, ..] => write!(f, "{}+", a)?,
        };
        for ident in self.identities() {
            write!(f, " {}", ident)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl Serialize for OwnedRelay
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut serial = serializer.serialize_struct("OwnedRelay", 5)?;
        serial.serialize_field("addrs", &self.addrs)?;
        serial.serialize_field("ids", &self.ids)?;
        serial.serialize_field("ntor_onion_key", self.ntor_onion_key.as_bytes())?;
        serial.serialize_field("protovers", &self.protovers.to_string())?;
        serial.serialize_field("flags", &self.flags)?;
        serial.end()
    }
}


impl<'de> Deserialize<'de> for OwnedRelay {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        // #[serde(field_identifier, rename_all = "lowercase")]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { Addrs, Ids, NtorOnionKey, Protovers, Flags}

        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = OwnedRelay;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct OwnedRelay")
            }

            fn visit_map<V>(self, mut map: V) -> Result<OwnedRelay, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut addrs = None;
                let mut ids = None;
                let mut ntor_onion_key: Option<[u8; 32]> = None;
                let mut protovers: Option<String> = None;
                let mut flags: Option<RelayFlagsInfo> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Addrs => {
                            if addrs.is_some() {
                                return Err(de::Error::duplicate_field("addrs"));
                            }
                            addrs = Some(map.next_value()?);
                        }
                        Field::Ids => {
                            if ids.is_some() {
                                return Err(de::Error::duplicate_field("ids"));
                            }
                            ids = Some(map.next_value()?);
                        }
                        Field::NtorOnionKey => {
                            if ntor_onion_key.is_some() {
                                return Err(de::Error::duplicate_field("ntor_onion_key"));
                            }
                            ntor_onion_key = Some(map.next_value()?);
                        }
                        Field::Protovers => {
                            if protovers.is_some() {
                                return Err(de::Error::duplicate_field("protovers"));
                            }
                            protovers = Some(map.next_value()?);
                        }
                        Field::Flags => {
                            if flags.is_some() {
                                return Err(de::Error::duplicate_field("flags"));
                            }
                            flags = Some(map.next_value()?);
                        }
                    }
                }
                let addrs = addrs.ok_or_else(|| de::Error::missing_field("addrs"))?;
                let ids = ids.ok_or_else(|| de::Error::missing_field("ids"))?;
                let ntor_onion_key = ntor_onion_key.ok_or_else(|| de::Error::missing_field("ntor_onion_key"))?;
                let protovers = protovers.ok_or_else(|| de::Error::missing_field("protovers"))?;
                let flags = flags.ok_or_else(|| de::Error::missing_field("flags"))?;

                let ntor_onion_key = pk::curve25519::PublicKey::from(ntor_onion_key);
                let protovers: tor_protover::Protocols = protovers.parse().map_err(|_e: tor_protover::ParseError|de::Error::invalid_value(de::Unexpected::Other("invalid protovers"), &self))?;

                Ok(OwnedRelay{
                    addrs,
                    ids,
                    ntor_onion_key,
                    protovers,
                    flags,
                })
            }
        }


        const FIELDS: &'static [&'static str] = &["addrs", "ids", "ntor_onion_key", "protovers"];
        deserializer.deserialize_struct("OwnedRelay", FIELDS, ValueVisitor)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRelay(pub Arc<OwnedRelay>);

impl Hash for HashRelay
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if let Some(id) = self.0.ed_identity() {
            id.hash(state);
        }
    }
}

impl PartialEq for HashRelay
{
    fn eq(&self, other: &Self) -> bool {
        self.0.ed_identity() == other.0.ed_identity()
    }
}

impl Eq for HashRelay {}

impl From<Arc<OwnedRelay>> for HashRelay {
    fn from(src: Arc<OwnedRelay>) -> Self {
        Self(src)
    }
}

impl From<OwnedRelay> for HashRelay {
    fn from(src: OwnedRelay) -> Self {
        Self(Arc::new(src))
    }
}



#[test]
fn test_owned_relay() -> Result<()> {
    use tor_protover::Protocols;
    let protos1: Protocols = "Link=1,2,3 Foobar=7 Relay=2".parse()?;
    assert_eq!(format!("{}", protos1), "Foobar=7 Link=1-3 Relay=2");

    let protos2: Protocols = protos1.to_string().parse()?;
    assert_eq!(protos1, protos2);

    
    let ct = OwnedRelay{
        addrs: vec!["127.0.0.1:11".parse()?],
        ids: RelayIds::new([42; 32].into(), [45; 20].into()),
        ntor_onion_key: [99; 32].into(),
        protovers: "FlowCtrl=7".parse()?,
        flags: RelayFlagsInfo(RelayFlags::HSDIR),
    };
    
    assert_eq!(ct.ntor_onion_key().as_bytes(), &[99; 32]);
    assert_eq!(&ct.protovers().to_string(), "FlowCtrl=7");

    // {
    //     let ct2 = OwnedRelay::from_circ_target(&ct);
    //     assert_eq!(format!("{:?}", ct), format!("{:?}", ct2));
    //     assert_eq!(format!("{:?}", ct), format!("{:?}", ct.clone()));
    // }

    {
        let s = serde_json::to_string(&ct)?;
        println!("OwnedRelay json = [{}]", s);
        let ct3: OwnedRelay = serde_json::from_str(&s)?;
        assert_eq!(format!("{:?}", ct), format!("{:?}", ct3));
    }

    
    Ok(())
}

