//! Optional interoperability with the OS DNS client; no public network required.
#![cfg(all(windows, feature = "std"))]
use recurse_x::{Resolver, ResolverConfig, Server};
use std::process::Command;

#[test]
#[ignore = "explicit Windows nslookup interoperability check"]
fn windows_nslookup_reads_udp_and_tcp_answers() {
    let mut config = ResolverConfig::default();
    config.engine.root_servers = vec!["127.0.0.1:1".parse().unwrap()];
    config.engine.timeout_ms = 50;
    config.engine.query_budget_ms = 100;
    config
        .dns
        .hosts
        .insert("interop.example.test", &["192.0.2.44".parse().unwrap()])
        .unwrap();
    let resolver = Resolver::new(config);
    let server = Server::new(resolver.clone());
    // This Windows nslookup build did not send to the selected custom port.
    // This opt-in check therefore requires a free standard loopback DNS port.
    let address = server.bind_udp("127.0.0.1:53".parse().unwrap()).unwrap();
    server.bind_tcp(address).unwrap();
    let mut results = Vec::new();
    for tcp in [false, true] {
        let mut command = Command::new("nslookup.exe");
        command.args([
            format!("-port={}", address.port()),
            "-timeout=2".into(),
            "-retry=1".into(),
            "-type=A".into(),
        ]);
        if tcp {
            command.arg("-vc");
        }
        results.push((
            tcp,
            command
                .args(["interop.example.test.", "127.0.0.1"])
                .output(),
        ));
    }
    server.shutdown();
    resolver.shutdown();
    server.join();
    for (tcp, output) in results {
        let output = output.expect("Windows nslookup must be installed");
        let stdout = format!(
            "{} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "tcp={tcp}: {stdout}");
        assert!(stdout.contains("192.0.2.44"), "tcp={tcp}: {stdout}");
        println!(
            "Windows nslookup {} received configured A answer 192.0.2.44",
            if tcp { "TCP" } else { "UDP" }
        );
    }
}
