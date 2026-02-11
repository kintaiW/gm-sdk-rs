fn main() {
    println!("SM2签名验签Demo");
    
    use gm_sdk::sm2_generate_keypair;
    use gm_sdk::sm2_sign;
    use gm_sdk::sm2_verify;
    
    // 生成密钥对
    let (private_key, public_key) = sm2_generate_keypair();
    println!("生成密钥对成功");
    println!("私钥: {:?}", &private_key[..8]);
    println!("公钥: {:?}", &public_key[..8]);
    
    // 待签名消息
    let message = b"Hello SM2 Signature";
    println!("\n待签名消息: {:?}", message);
    
    // 签名
    let signature = sm2_sign(&private_key, message);
    println!("\n签名结果: {:?}", &signature[..8]);
    
    // 验签
    let result = sm2_verify(&public_key, message, &signature);
    println!("\n验签结果: {}", result);
    
    if result {
        println!("SM2签名验签成功！");
    } else {
        println!("SM2签名验签失败！");
    }
}