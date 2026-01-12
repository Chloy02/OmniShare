pub mod quick_share {
    include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
}

pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

pub mod ukey2_engine;
