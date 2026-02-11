fn main() {
    println!("HMAC_SM3完整性保护Demo");
    
    use gm_sdk::hmac_sm3;
    
    // 密钥
    let key = b"SecretKey1234567890";
    // 原始消息
    let message = b"Hello HMAC_SM3 Integrity Protection";
    
    println!("密钥: {:?}", key);
    println!("原始消息: {:?}", message);
    
    // 生成HMAC标签
    let hmac_tag = hmac_sm3(key, message);
    println!("\n生成的HMAC标签: {:?}", &hmac_tag[..]);
    
    // 验证HMAC标签（正常情况）
    let verify_tag = hmac_sm3(key, message);
    let is_valid = verify_tag == hmac_tag;
    println!("\n验证结果（原始消息）: {}", is_valid);
    
    if is_valid {
        println!("HMAC验证成功，消息完整性得到保护！");
    } else {
        println!("HMAC验证失败，消息可能被篡改！");
    }
    
    // 验证HMAC标签（消息被篡改的情况）
    let tampered_message = b"Hello HMAC_SM3 Integrity Protection (Tampered)";
    let tampered_tag = hmac_sm3(key, tampered_message);
    let is_tampered_valid = tampered_tag == hmac_tag;
    println!("\n验证结果（被篡改的消息）: {}", is_tampered_valid);
    
    if !is_tampered_valid {
        println!("HMAC验证失败，成功检测到消息篡改！");
    } else {
        println!("HMAC验证成功，消息未被篡改！");
    }
    
    // 验证HMAC标签（密钥错误的情况）
    let wrong_key = b"WrongSecretKey123456";
    let wrong_key_tag = hmac_sm3(wrong_key, message);
    let is_wrong_key_valid = wrong_key_tag == hmac_tag;
    println!("\n验证结果（错误密钥）: {}", is_wrong_key_valid);
    
    if !is_wrong_key_valid {
        println!("HMAC验证失败，密钥错误！");
    } else {
        println!("HMAC验证成功，密钥正确！");
    }
    
    println!("\nHMAC_SM3完整性保护Demo完成！");
    println!("此Demo展示了如何使用HMAC_SM3来:");
    println!("1. 为消息生成完整性保护标签");
    println!("2. 验证消息的完整性");
    println!("3. 检测消息篡改");
    println!("4. 验证密钥的正确性");
}
