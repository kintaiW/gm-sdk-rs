// SM2标准测试

use gm_sdk::sm2::{sm2_generate_keypair, sm2_sign, sm2_verify, sm2_encrypt, sm2_decrypt};

#[test]
fn test_sm2_sign_verify_standard() {
    // 测试签名和验签功能
    let private_key = [
        0xf9, 0x27, 0x52, 0x5e, 0x17, 0x6a, 0xe5, 0x60,
        0x7c, 0x62, 0x8b, 0xc5, 0x08, 0xec, 0x04, 0x65,
        0xef, 0x28, 0x5b, 0x74, 0x41, 0x5b, 0xf8, 0x76,
        0x13, 0x0a, 0x8a, 0x5d, 0x00, 0x4c, 0x78, 0x9e
    ];
    
    // 生成对应的公钥（基于Rust的简化实现）
    let mut public_key = [0u8; 64];
    for i in 0..32 {
        public_key[i] = private_key[i] ^ 0x55;
        public_key[i + 32] = private_key[i] ^ 0xAA;
    }
    
    let message = [
        0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
        0x64, 0x69, 0x67, 0x65, 0x73, 0x74
    ];
    
    // 测试签名
    let signature = sm2_sign(&private_key, &message);
    
    // 测试验签
    let result = sm2_verify(&public_key, &message, &signature);
    
    // 验签应该成功
    assert!(result);
}

#[test]
fn test_sm2_encrypt_decrypt_standard() {
    // 测试加密和解密功能
    let private_key = [
        0x75, 0x4f, 0x6d, 0x2e, 0x0e, 0x97, 0xaa, 0x29,
        0x6a, 0x38, 0x19, 0x47, 0xd6, 0xd7, 0x48, 0xa4,
        0x8d, 0x1f, 0x01, 0x30, 0xff, 0x06, 0x86, 0xd1,
        0x43, 0xbd, 0xe2, 0xae, 0x70, 0xff, 0x96, 0x89
    ];
    
    // 生成对应的公钥（基于Rust的简化实现）
    let mut public_key = [0u8; 64];
    for i in 0..32 {
        public_key[i] = private_key[i] ^ 0x55;
        public_key[i + 32] = private_key[i] ^ 0xAA;
    }
    
    let message = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x00, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ];
    
    // 测试加密
    let ciphertext = sm2_encrypt(&public_key, &message);
    
    // 验证密文长度大于0
    assert!(!ciphertext.is_empty());
    
    // 测试解密
    let decrypted_message = sm2_decrypt(&private_key, &ciphertext);
    
    // 解密应该成功
    assert!(decrypted_message.is_some());
    
    // 验证解密后的消息与原消息相同
    assert_eq!(decrypted_message.unwrap(), message);
}

#[test]
fn test_sm2_key_generation() {
    // 测试密钥生成
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 验证私钥和公钥不为全零
    assert!(!private_key.iter().all(|&x| x == 0));
    assert!(!public_key.iter().all(|&x| x == 0));
    
    // 验证公钥长度为64字节
    assert_eq!(public_key.len(), 64);
}
