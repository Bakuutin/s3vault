# s3vault-keyd: a static binary in an empty image (no shell, no package manager).
# Build the binary first: cargo build --release -p s3vault-keyd --target x86_64-unknown-linux-musl
# and copy it to bin/s3vault-keyd next to this file.
FROM scratch
COPY bin/s3vault-keyd /s3vault-keyd
USER 0:0
ENTRYPOINT ["/s3vault-keyd"]
