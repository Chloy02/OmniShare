use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &["src/proto/quick_share.proto", "src/proto/ukey2.proto", "src/proto/securemessage.proto", "src/proto/securegcm.proto", "src/proto/wire_format.proto"],
        &["src/proto/"]
    )?;
    Ok(())
}
