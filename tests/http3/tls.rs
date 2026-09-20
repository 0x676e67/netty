use std::sync::Arc;

use quic::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;

pub fn config() -> (
    rcgen::CertifiedKey<rcgen::KeyPair>,
    quinn::ServerConfig,
    quic::ClientConfig,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h3".to_vec()];
    let server =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap()));
    let client = client_crypto(&cert);
    let client = quic::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client).unwrap()));
    (cert, server, client)
}

pub fn client_crypto(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"h3".to_vec()];
    client
}
