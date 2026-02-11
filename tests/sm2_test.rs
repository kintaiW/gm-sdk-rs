// SM2测试

use gm_sdk::sm2::{sm2_generate_keypair, sm2_sign, sm2_verify, sm2_encrypt, sm2_decrypt};

#[test]
fn test_sm2_key_generation() {
    // 测试SM2密钥生成
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 验证私钥和公钥不为全零
    assert!(!private_key.iter().all(|&x| x == 0));
    assert!(!public_key.iter().all(|&x| x == 0));
    
    // 验证公钥长度为64字节
    assert_eq!(public_key.len(), 64);
}

#[test]
fn test_sm2_sign_verify() {
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for signature verification.";
    
    // 签名
    let signature = sm2_sign(&private_key, message);
    
    // 验证签名
    let result = sm2_verify(&public_key, message, &signature);
    
    // 验签应该成功
    assert!(result);
}

#[test]
fn test_sm2_verify_invalid_signature() {
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for signature verification.";
    
    // 签名
    let mut signature = sm2_sign(&private_key, message);
    
    // 修改签名使其无效
    signature[0] ^= 0xFF;
    
    // 验证签名
    let result = sm2_verify(&public_key, message, &signature);
    
    // 验签应该失败
    assert!(!result);
}

#[test]
fn test_sm2_encrypt_decrypt() {
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for encryption.";
    
    // 加密
    let ciphertext = sm2_encrypt(&public_key, message);
    
    // 验证密文长度大于0
    assert!(!ciphertext.is_empty());
    
    // 解密
    let decrypted_message = sm2_decrypt(&private_key, &ciphertext);
    
    // 解密应该成功
    assert!(decrypted_message.is_some());
    
    // 验证解密后的消息与原消息相同
    assert_eq!(decrypted_message.unwrap(), message);
}

#[test]
fn test_sm2_decrypt_invalid_ciphertext() {
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    
    // 测试消息
    let message = b"Hello, SM2! This is a test message for encryption.";
    
    // 加密
    let mut ciphertext = sm2_encrypt(&public_key, message);
    
    // 修改密文使其无效
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }
    
    // 解密
    let decrypted_message = sm2_decrypt(&private_key, &ciphertext);
    
    // 解密应该失败
    assert!(decrypted_message.is_none());
}
