# Install

Rust toolchain: https://github.com/zkMIPS/toolchain/releases

# Test

```
RUST_LOG=debug ZKM_DEV=true FRI_QUERIES=1 cargo test -r test_zkm2_groth16
```

```
cargo test -r test_zkm2_verify_ark_groth16
```
