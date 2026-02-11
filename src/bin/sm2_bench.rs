// SM2 性能基准测试

use gm_sdk::sm2::{sm2_sign, sm2_verify, sm2_generate_keypair};
use std::time::Instant;

fn main() {
    println!("=== SM2 性能基准测试 ===");
    
    // 生成密钥对
    println!("生成密钥对...");
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for performance benchmarking.";
    
    // 测试签名性能
    println!("\n测试签名性能...");
    let start = Instant::now();
    let signature = sm2_sign(&private_key, message);
    let duration = start.elapsed();
    println!("签名耗时: {:?}", duration);
    
    // 测试验签性能
    println!("\n测试验签性能...");
    let start = Instant::now();
    let result = sm2_verify(&public_key, message, &signature);
    let duration = start.elapsed();
    println!("验签耗时: {:?}", duration);
    println!("验签结果: {:?}", result);
    
    println!("\n测试完成!");
}
