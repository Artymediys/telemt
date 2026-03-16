use super::*;
use crate::crypto::sha256_hmac;
use std::time::Duration;

fn make_valid_tls_handshake(secret: &[u8], timestamp: u32) -> Vec<u8> {
    let session_id_len: usize = 32;
    let len = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + session_id_len;
    let mut handshake = vec![0x42u8; len];

    handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = session_id_len as u8;
    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);

    let computed = sha256_hmac(secret, &handshake);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg
}

#[test]
fn test_generate_tg_nonce() {
    let client_dec_key = [0x42u8; 32];
    let client_dec_iv = 12345u128;
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _tg_enc_key, _tg_enc_iv, _tg_dec_key, _tg_dec_iv) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_dec_key,
        client_dec_iv,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    assert_eq!(nonce.len(), HANDSHAKE_LEN);

    let tag_bytes: [u8; 4] = nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().unwrap();
    assert_eq!(ProtoTag::from_bytes(tag_bytes), Some(ProtoTag::Secure));
}

#[test]
fn test_encrypt_tg_nonce() {
    let client_dec_key = [0x42u8; 32];
    let client_dec_iv = 12345u128;
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_dec_key,
        client_dec_iv,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let encrypted = encrypt_tg_nonce(&nonce);

    assert_eq!(encrypted.len(), HANDSHAKE_LEN);
    assert_eq!(&encrypted[..PROTO_TAG_POS], &nonce[..PROTO_TAG_POS]);
    assert_ne!(&encrypted[PROTO_TAG_POS..], &nonce[PROTO_TAG_POS..]);
}

#[test]
fn test_handshake_success_drop_does_not_panic() {
    let success = HandshakeSuccess {
        user: "test".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Secure,
        dec_key: [0xAA; 32],
        dec_iv: 0xBBBBBBBB,
        enc_key: [0xCC; 32],
        enc_iv: 0xDDDDDDDD,
        peer: "127.0.0.1:1234".parse().unwrap(),
        is_tls: true,
    };

    assert_eq!(success.dec_key, [0xAA; 32]);
    assert_eq!(success.enc_key, [0xCC; 32]);

    drop(success);
}

#[test]
fn test_generate_tg_nonce_enc_dec_material_is_consistent() {
    let client_dec_key = [0x12u8; 32];
    let client_dec_iv = 0x11223344556677889900aabbccddeeffu128;
    let client_enc_key = [0x34u8; 32];
    let client_enc_iv = 0xffeeddccbbaa00998877665544332211u128;
    let rng = SecureRandom::new();

    let (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv) = generate_tg_nonce(
        ProtoTag::Secure,
        7,
        &client_dec_key,
        client_dec_iv,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

    let mut expected_tg_enc_key = [0u8; 32];
    expected_tg_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut expected_tg_enc_iv_arr = [0u8; IV_LEN];
    expected_tg_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let expected_tg_enc_iv = u128::from_be_bytes(expected_tg_enc_iv_arr);

    let mut expected_tg_dec_key = [0u8; 32];
    expected_tg_dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut expected_tg_dec_iv_arr = [0u8; IV_LEN];
    expected_tg_dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let expected_tg_dec_iv = u128::from_be_bytes(expected_tg_dec_iv_arr);

    assert_eq!(tg_enc_key, expected_tg_enc_key);
    assert_eq!(tg_enc_iv, expected_tg_enc_iv);
    assert_eq!(tg_dec_key, expected_tg_dec_key);
    assert_eq!(tg_dec_iv, expected_tg_dec_iv);
    assert_eq!(
        i16::from_le_bytes([nonce[DC_IDX_POS], nonce[DC_IDX_POS + 1]]),
        7,
        "Generated nonce must keep target dc index in protocol slot"
    );
}

#[test]
fn test_generate_tg_nonce_fast_mode_embeds_reversed_client_enc_material() {
    let client_dec_key = [0x22u8; 32];
    let client_dec_iv = 0x0102030405060708090a0b0c0d0e0f10u128;
    let client_enc_key = [0xABu8; 32];
    let client_enc_iv = 0x11223344556677889900aabbccddeeffu128;
    let rng = SecureRandom::new();

    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        9,
        &client_dec_key,
        client_dec_iv,
        &client_enc_key,
        client_enc_iv,
        &rng,
        true,
    );

    let mut expected = Vec::with_capacity(KEY_LEN + IV_LEN);
    expected.extend_from_slice(&client_enc_key);
    expected.extend_from_slice(&client_enc_iv.to_be_bytes());
    expected.reverse();

    assert_eq!(&nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN], expected.as_slice());
}

#[test]
fn test_encrypt_tg_nonce_with_ciphers_matches_manual_suffix_encryption() {
    let client_dec_key = [0x42u8; 32];
    let client_dec_iv = 12345u128;
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_dec_key,
        client_dec_iv,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let (encrypted, _, _) = encrypt_tg_nonce_with_ciphers(&nonce);

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let mut expected_enc_key = [0u8; 32];
    expected_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut expected_enc_iv_arr = [0u8; IV_LEN];
    expected_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let expected_enc_iv = u128::from_be_bytes(expected_enc_iv_arr);

    let mut manual_encryptor = AesCtr::new(&expected_enc_key, expected_enc_iv);
    let manual = manual_encryptor.encrypt(&nonce);

    assert_eq!(encrypted.len(), HANDSHAKE_LEN);
    assert_eq!(&encrypted[..PROTO_TAG_POS], &nonce[..PROTO_TAG_POS]);
    assert_eq!(
        &encrypted[PROTO_TAG_POS..],
        &manual[PROTO_TAG_POS..],
        "Encrypted nonce suffix must match AES-CTR output with derived enc key/iv"
    );
}

#[tokio::test]
async fn tls_replay_second_identical_handshake_is_rejected() {
    let secret = [0x11u8; 16];
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "127.0.0.1:44321".parse().unwrap();
    let handshake = make_valid_tls_handshake(&secret, 0);

    let first = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(first, HandshakeResult::Success(_)));

    let second = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(second, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn invalid_tls_probe_does_not_pollute_replay_cache() {
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "127.0.0.1:44322".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    let before = replay_checker.stats();
    let result = handle_tls_handshake(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    let after = replay_checker.stats();

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(before.total_additions, after.total_additions);
    assert_eq!(before.total_hits, after.total_hits);
}

#[tokio::test]
async fn empty_decoded_secret_is_rejected() {
    let config = test_config_with_secret_hex("");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "127.0.0.1:44323".parse().unwrap();
    let handshake = make_valid_tls_handshake(&[], 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn wrong_length_decoded_secret_is_rejected() {
    let config = test_config_with_secret_hex("aa");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "127.0.0.1:44324".parse().unwrap();
    let handshake = make_valid_tls_handshake(&[0xaau8], 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn invalid_mtproto_probe_does_not_pollute_replay_cache() {
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "127.0.0.1:44325".parse().unwrap();
    let handshake = [0u8; HANDSHAKE_LEN];

    let before = replay_checker.stats();
    let result = handle_mtproto_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    let after = replay_checker.stats();

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(before.total_additions, after.total_additions);
    assert_eq!(before.total_hits, after.total_hits);
}

#[tokio::test]
async fn mixed_secret_lengths_keep_valid_user_authenticating() {
    let good_secret = [0x22u8; 16];
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config
        .access
        .users
        .insert("broken_user".to_string(), "aa".to_string());
    config
        .access
        .users
        .insert("valid_user".to_string(), "22222222222222222222222222222222".to_string());
    config.access.ignore_time_skew = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "127.0.0.1:44326".parse().unwrap();
    let handshake = make_valid_tls_handshake(&good_secret, 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
}

#[test]
fn secure_tag_requires_tls_mode_on_tls_transport() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = false;
    config.general.modes.secure = true;
    config.general.modes.tls = false;

    assert!(
        !mode_enabled_for_proto(&config, ProtoTag::Secure, true),
        "Secure tag over TLS must be rejected when tls mode is disabled"
    );

    config.general.modes.tls = true;
    assert!(
        mode_enabled_for_proto(&config, ProtoTag::Secure, true),
        "Secure tag over TLS must be accepted when tls mode is enabled"
    );
}

#[test]
fn secure_tag_requires_secure_mode_on_direct_transport() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = false;
    config.general.modes.secure = false;
    config.general.modes.tls = true;

    assert!(
        !mode_enabled_for_proto(&config, ProtoTag::Secure, false),
        "Secure tag without TLS must be rejected when secure mode is disabled"
    );

    config.general.modes.secure = true;
    assert!(
        mode_enabled_for_proto(&config, ProtoTag::Secure, false),
        "Secure tag without TLS must be accepted when secure mode is enabled"
    );
}
