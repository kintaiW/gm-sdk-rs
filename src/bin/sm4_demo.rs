fn main() {
    println!("SM4 CBC模式加解密Demo");
    
    use gm_sdk::sm4_encrypt_cbc;
    use gm_sdk::sm4_decrypt_cbc;
    
    // 16字节密钥
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
    // 16字节初始向量
    let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    
    println!("密钥: {:?}", &key[..]);
    println!("初始向量: {:?}", &iv[..]);
    
    // 待加密数据（16字节的倍数）
    let plaintext = b"Hello SM4 CBC Mode Encryption";
    let mut padded_plaintext = Vec::from(plaintext);
    
    // 填充到16字节的倍数
    let padding_needed = 16 - (padded_plaintext.len() % 16);
    if padding_needed < 16 {
        padded_plaintext.extend_from_slice(&vec![padding_needed as u8; padding_needed]);
    }
    
    println!("\n原始明文: {:?}", plaintext);
    println!("填充后明文长度: {} bytes", padded_plaintext.len());
    
    // 加密
    let mut ciphertext = vec![0u8; padded_plaintext.len()];
    sm4_encrypt_cbc(&key, &iv, &padded_plaintext, &mut ciphertext);
    println!("\n加密结果: {:?}", &ciphertext[..]);
    
    // 解密
    let mut decrypted = vec![0u8; ciphertext.len()];
    sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut decrypted);
    
    // 移除填充
    let padding_length = *decrypted.last().unwrap_or(&0) as usize;
    let unpadded_decrypted = &decrypted[..decrypted.len() - padding_length];
    println!("\n解密结果: {:?}", unpadded_decrypted);
    
    // 验证解密结果
    if unpadded_decrypted == plaintext {
        println!("\nSM4 CBC模式加解密成功！");
        println!("解密后的明文与原始明文一致");
    } else {
        println!("\nSM4 CBC模式加解密失败！");
        println!("解密后的明文与原始明文不一致");
    }
}
