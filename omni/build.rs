use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["src/proto/quick_share.proto", "src/proto/ukey2.proto"], &["src/"])?;
    Ok(())
}
