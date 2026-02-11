// SM2 关键操作基准测试

use rand::Rng;
use gm_sdk::sm2::{sm2_sign, sm2_verify, sm2_generate_keypair};
use std::time::Instant;

#[test]
fn bench_sm2_sign() {
    println!("=== 测试 sm2_sign 性能 ===");
    
    // 生成密钥对
    let (private_key, _) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2!";
    
    // 测试签名性能
    let start = Instant::now();
    for _ in 0..10 {
        let signature = sm2_sign(&private_key, message);
        assert!(!signature.iter().all(|&x| x == 0));
    }
    let duration = start.elapsed();
    println!("sm2_sign 10次耗时: {:?}", duration);
    println!("sm2_sign 单次耗时: {:?}", duration / 10);
}

#[test]
fn bench_sm2_verify() {
    println!("=== 测试 sm2_verify 性能 ===");
    
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2!";
    
    // 生成签名
    let signature = sm2_sign(&private_key, message);
    
    // 测试验签性能
    let start = Instant::now();
    for _ in 0..10 {
        let result = sm2_verify(&public_key, message, &signature);
        assert!(result);
    }
    let duration = start.elapsed();
    println!("sm2_verify 10次耗时: {:?}", duration);
    println!("sm2_verify 单次耗时: {:?}", duration / 10);
}
