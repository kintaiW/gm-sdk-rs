// SM2/3/4性能测试

use gm_sdk::sm2::{sm2_generate_keypair, sm2_sign, sm2_verify, sm2_encrypt, sm2_decrypt};
use gm_sdk::sm3::sm3_hash;
use gm_sdk::sm4::{sm4_encrypt_cbc, sm4_decrypt_cbc};
use std::time::Instant;

#[test]
fn test_sm2_performance() {
    println!("=== SM2 性能测试 ===");
    
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for performance testing.";
    
    // 测试签名性能
    let start = Instant::now();
    let mut signature = [0u8; 64];
    for _ in 0..100 {
        signature = sm2_sign(&private_key, message);
    }
    let duration = start.elapsed();
    println!("SM2签名 100次耗时: {:?}", duration);
    println!("SM2签名 单次耗时: {:?}", duration / 100);
    
    // 测试验签性能
    let start = Instant::now();
    for _ in 0..100 {
        let result = sm2_verify(&public_key, message, &signature);
        assert!(result);
    }
    let duration = start.elapsed();
    println!("SM2验签 100次耗时: {:?}", duration);
    println!("SM2验签 单次耗时: {:?}", duration / 100);
    
    // 测试加密性能
    let start = Instant::now();
    let mut ciphertext = Vec::new();
    for _ in 0..100 {
        ciphertext = sm2_encrypt(&public_key, message);
    }
    let duration = start.elapsed();
    println!("SM2加密 100次耗时: {:?}", duration);
    println!("SM2加密 单次耗时: {:?}", duration / 100);
    
    // 测试解密性能
    let start = Instant::now();
    for _ in 0..100 {
        let result = sm2_decrypt(&private_key, &ciphertext);
        assert!(result.is_some());
    }
    let duration = start.elapsed();
    println!("SM2解密 100次耗时: {:?}", duration);
    println!("SM2解密 单次耗时: {:?}", duration / 100);
}

#[test]
fn test_sm3_performance() {
    println!("=== SM3 性能测试 ===");
    
    // 测试消息
    let message = b"Hello, SM3! This is a test message for performance testing.";
    
    // 测试哈希性能
    let start = Instant::now();
    for _ in 0..1000 {
        let hash = sm3_hash(message);
        assert_eq!(hash.len(), 32);
    }
    let duration = start.elapsed();
    println!("SM3哈希 1000次耗时: {:?}", duration);
    println!("SM3哈希 单次耗时: {:?}", duration / 1000);
}

#[test]
fn test_sm4_performance() {
    println!("=== SM4 性能测试 ===");
    
    // 测试密钥和IV
    let key = [0u8; 16];
    let iv = [0u8; 16];
    
    // 测试消息（16字节对齐）
    let message = b"Hello, SM4! This is a test message for performance testing.0123456789ABCDEF";
    let mut ciphertext = vec![0u8; message.len()];
    let mut plaintext = vec![0u8; message.len()];
    
    // 测试加密性能
    let start = Instant::now();
    for _ in 0..1000 {
        sm4_encrypt_cbc(&key, &iv, message, &mut ciphertext);
    }
    let duration = start.elapsed();
    println!("SM4加密 1000次耗时: {:?}", duration);
    println!("SM4加密 单次耗时: {:?}", duration / 1000);
    
    // 测试解密性能
    let start = Instant::now();
    for _ in 0..1000 {
        sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut plaintext);
    }
    let duration = start.elapsed();
    println!("SM4解密 1000次耗时: {:?}", duration);
    println!("SM4解密 单次耗时: {:?}", duration / 1000);
}
