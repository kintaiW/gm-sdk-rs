use gm_sdk::sm4::{key_expansion, sm4_encrypt_cbc, sm4_decrypt_cbc};

#[test]
fn test_sm4_debug() {
    // 使用C测试文件中的标准数据
    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ];
    
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    
    let plaintext: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ];
    
    // 测试密钥扩展
    let mut round_keys = [0u32; 32];
    key_expansion(&key, &mut round_keys);
    println!("Round keys:");
    for i in 0..32 {
        println!("rk[{}] = 0x{:08x}", i, round_keys[i]);
    }
    
    // 测试CBC加密
    let mut ciphertext = [0u8; 16];
    sm4_encrypt_cbc(&key, &iv, &plaintext, &mut ciphertext);
    println!("\nCiphertext:");
    for b in &ciphertext {
        print!("0x{:02x}, ", b);
    }
    println!();
    
    // 测试CBC解密
    let mut decrypted_plaintext = [0u8; 16];
    sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut decrypted_plaintext);
    println!("\nDecrypted plaintext:");
    for b in &decrypted_plaintext {
        print!("0x{:02x}, ", b);
    }
    println!();
    
    // 验证解密结果
    assert_eq!(decrypted_plaintext, plaintext, "SM4 解密失败");
}
