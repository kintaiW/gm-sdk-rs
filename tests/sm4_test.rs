use gm_sdk::sm4_encrypt_cbc; use gm_sdk::sm4_decrypt_cbc; #[test] fn test_sm4_cbc() {
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
    let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let plaintext = b"Hello SM4 CBC Mode";
    let mut ciphertext = vec![0u8; plaintext.len() + (16 - plaintext.len() % 16) % 16];
    let mut decrypted = vec![0u8; ciphertext.len()];
    
    sm4_encrypt_cbc(&key, &iv, plaintext, &mut ciphertext);
    sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut decrypted);
    
    assert_eq!(&decrypted[0..plaintext.len()], plaintext);
}