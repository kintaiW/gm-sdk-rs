// SM2签名验签测试

use gm_sdk::sm2_generate_keypair;
use gm_sdk::sm2_sign;
use gm_sdk::sm2_verify;

#[test]
fn test_sm2_sign_verify() {
    // 测试签名验签功能
    let (private_key, public_key) = sm2_generate_keypair();
    let message = b"Hello SM2 Signature";
    let signature = sm2_sign(&private_key, message);
    let result = sm2_verify(&public_key, message, &signature);
    assert!(result);
}

#[test]
fn test_sm2_sign_verify_tampered_message() {
    // 测试篡改消息的验签失败
    let (private_key, public_key) = sm2_generate_keypair();
    let message = b"Hello SM2 Signature";
    let tampered_message = b"Hello SM2 Signature Tampered";
    let signature = sm2_sign(&private_key, message);
    let result = sm2_verify(&public_key, tampered_message, &signature);
    assert!(!result);
}

#[test]
fn test_sm2_sign_verify_tampered_signature() {
    // 测试篡改签名的验签失败
    let (private_key, public_key) = sm2_generate_keypair();
    let message = b"Hello SM2 Signature";
    let mut signature = sm2_sign(&private_key, message);
    // 篡改签名
    signature[0] ^= 0xFF;
    let result = sm2_verify(&public_key, message, &signature);
    assert!(!result);
}
