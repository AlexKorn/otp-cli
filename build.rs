use protobuf_codegen::Codegen;
use protoc_bin_vendored;

fn main() {
    Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .cargo_out_dir("proto")
        .include("src/proto")
        .input("src/proto/google_auth.proto")
        .run_from_script();
}
