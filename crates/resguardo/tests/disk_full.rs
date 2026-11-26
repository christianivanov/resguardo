//! Annex G.3, "disk full while writing the receipt": 503 AUDIT_UNAVAILABLE and nothing leaves
//! (ADR 0015). A real `resguardo run` gets a file size limit (`ulimit -f`), so writing the
//! audit log fails the way it does on a full disk.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use resguardo_audit::SigningKey;
use resguardo_core::VirtualKey;
use resguardo_mock_upstream::MockUpstream;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn g3_a_receipt_that_cannot_be_written_blocks_the_request() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("disk-full-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    SigningKey::create_files(&dir.join("signing.key"), &dir.join("signing.pub")).unwrap();
    let mock = MockUpstream::start(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let key = VirtualKey::from_random_bytes(&[7; 32]);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = format!(
        r#"
[server]
listen = "127.0.0.1:{port}"

[audit]
path = "{dir}/audit.jsonl"
signing_key = "{dir}/signing.key"
public_key = "{dir}/signing.pub"

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"

[[upstream]]
provider = "openai_compatible"
base_url = "{base}"
allow_insecure_upstream = true

[[principal]]
id = "bot"
key_sha256 = "{hash}"
models.openai_compatible = ["llama-3"]
"#,
        dir = dir.display(),
        base = mock.base_url(),
        hash = key.hash().as_str(),
    );
    let config_path = dir.join("resguardo.toml");
    std::fs::write(&config_path, config).unwrap();

    // 2 blocks of 512 bytes: room for the first entries only. SIGXFSZ is ignored so the
    // write fails with an error, as on a full disk, instead of killing the process.
    let _server = Server(
        Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"ulimit -f 2; trap "" XFSZ; exec "$0" run --config "$1""#)
            .arg(env!("CARGO_BIN_EXE_resguardo"))
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let url = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..100 {
        if client.get(format!("{url}/healthz")).send().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "resguardo run did not start");

    let body = r#"{"model":"llama-3","messages":[{"role":"user","content":"hola"}]}"#;
    let mut sent = 0;
    let mut refused = None;
    for _ in 0..20 {
        let reply = client
            .post(format!("{url}/v1/chat/completions"))
            .header("authorization", format!("Bearer {}", key.expose_secret()))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        let status = reply.status().as_u16();
        let json: serde_json::Value =
            serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
        if status == 503 {
            refused = Some(json);
            break;
        }
        assert_eq!(status, 200, "{json}");
        sent += 1;
    }
    let refused = refused.expect("a request was refused once the log could not grow");
    assert_eq!(refused["error"]["code"], "AUDIT_UNAVAILABLE");
    // Only the requests whose receipt was written reached the provider.
    assert_eq!(mock.requests().len(), sent);
    let health = client.get(format!("{url}/healthz")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 503);
}
