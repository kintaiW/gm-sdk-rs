fn u8big_to_u32big(out: &mut [u32; 4], input: &[u8; 16]) {
    out[0] = (input[3] as u32) | ((input[2] as u32) << 8) | ((input[1] as u32) << 16) | ((input[0] as u32) << 24);
    out[1] = (input[7] as u32) | ((input[6] as u32) << 8) | ((input[5] as u32) << 16) | ((input[4] as u32) << 24);
    out[2] = (input[11] as u32) | ((input[10] as u32) << 8) | ((input[9] as u32) << 16) | ((input[8] as u32) << 24);
    out[3] = (input[15] as u32) | ((input[14] as u32) << 8) | ((input[13] as u32) << 16) | ((input[12] as u32) << 24);
}

fn u32big_to_u8big(out: &mut [u8; 16], input: &[u32; 4]) {
    for i in 0..4 {
        out[i * 4] = ((input[i] >> 24) & 0xFF) as u8;
        out[i * 4 + 1] = ((input[i] >> 16) & 0xFF) as u8;
        out[i * 4 + 2] = ((input[i] >> 8) & 0xFF) as u8;
        out[i * 4 + 3] = (input[i] & 0xFF) as u8;
    }
}

fn sm4_rotl(x: u32, n: u8) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn sm4_tao(a: u32) -> u32 {
    let sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ];
    
    let mut t = 0u32;
    for i in (0..32).step_by(8) {
        let m = ((a >> i) & 0xff) as usize;
        t |= (sbox[m] as u32) << i;
    }
    t
}

fn sm4_t(a: u32) -> u32 {
    let t = sm4_tao(a);
    t ^ sm4_rotl(t, 2) ^ sm4_rotl(t, 10) ^ sm4_rotl(t, 18) ^ sm4_rotl(t, 24)
}

fn sm4_t1(a: u32) -> u32 {
    let t = sm4_tao(a);
    t ^ sm4_rotl(t, 13) ^ sm4_rotl(t, 23)
}

pub fn key_expansion(key: &[u8; 16], round_keys: &mut [u32; 32]) {
    let fk = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];
    let ck = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ];
    
    let mut k = [0u32; 4];
    let mut key_u32 = [0u32; 4];
    u8big_to_u32big(&mut key_u32, key);
    
    for i in 0..4 {
        k[i] = key_u32[i] ^ fk[i];
    }
    
    let mut tmp = k[2] ^ k[3];
    let mut t = tmp ^ k[1] ^ ck[0];
    round_keys[0] = k[0] ^ sm4_t1(t);
    t = tmp ^ round_keys[0] ^ ck[1];
    round_keys[1] = k[1] ^ sm4_t1(t);
    
    tmp = round_keys[0] ^ round_keys[1];
    t = tmp ^ k[3] ^ ck[2];
    round_keys[2] = k[2] ^ sm4_t1(t);
    t = tmp ^ round_keys[2] ^ ck[3];
    round_keys[3] = k[3] ^ sm4_t1(t);
    
    for i in (0..27).step_by(2) {
        tmp = round_keys[i + 2] ^ round_keys[i + 3];
        let k0 = tmp ^ round_keys[i + 1] ^ ck[i + 4];
        round_keys[i + 4] = round_keys[i] ^ sm4_t1(k0);
        
        let k1 = tmp ^ round_keys[i + 4] ^ ck[i + 5];
        round_keys[i + 5] = round_keys[i + 1] ^ sm4_t1(k1);
    }
}

fn sm4_en(input: &[u32; 4], output: &mut [u32; 4], round_keys: &[u32; 32]) {
    let mut x = [0u32; 28];
    let mut i = input[2] ^ input[3];
    let mut t = input[1] ^ i ^ round_keys[0];
    x[0] = input[0] ^ sm4_t(t);
    t = i ^ x[0] ^ round_keys[1];
    x[1] = input[1] ^ sm4_t(t);
    
    i = x[0] ^ x[1];
    t = input[3] ^ i ^ round_keys[2];
    x[2] = input[2] ^ sm4_t(t);
    t = i ^ x[2] ^ round_keys[3];
    x[3] = input[3] ^ sm4_t(t);
    
    for i in (0..=22).step_by(2) {
        let t = x[i + 2] ^ x[i + 3];
        x[i + 4] = x[i] ^ sm4_t(t ^ x[i + 1] ^ round_keys[i + 4]);
        x[i + 5] = x[i + 1] ^ sm4_t(t ^ x[i + 4] ^ round_keys[i + 5]);
    }
    
    let t = x[26] ^ x[27];
    output[3] = x[24] ^ sm4_t(t ^ x[25] ^ round_keys[28]);
    output[2] = x[25] ^ sm4_t(t ^ output[3] ^ round_keys[29]);
    let t = output[3] ^ output[2];
    output[1] = x[26] ^ sm4_t(t ^ x[27] ^ round_keys[30]);
    output[0] = x[27] ^ sm4_t(t ^ output[1] ^ round_keys[31]);
}

fn sm4_de(input: &[u32; 4], output: &mut [u32; 4], round_keys: &[u32; 32]) {
    let mut x = [0u32; 28];
    let mut i = input[2] ^ input[3];
    let mut t = input[1] ^ i ^ round_keys[31];
    x[0] = input[0] ^ sm4_t(t);
    t = i ^ x[0] ^ round_keys[30];
    x[1] = input[1] ^ sm4_t(t);
    
    i = x[0] ^ x[1];
    t = input[3] ^ i ^ round_keys[29];
    x[2] = input[2] ^ sm4_t(t);
    t = i ^ x[2] ^ round_keys[28];
    x[3] = input[3] ^ sm4_t(t);
    
    for i in (0..=22).step_by(2) {
        let t = x[i + 2] ^ x[i + 3];
        x[i + 4] = x[i] ^ sm4_t(t ^ x[i + 1] ^ round_keys[27 - i]);
        x[i + 5] = x[i + 1] ^ sm4_t(t ^ x[i + 4] ^ round_keys[26 - i]);
    }
    
    let t = x[26] ^ x[27];
    output[3] = x[24] ^ sm4_t(t ^ x[25] ^ round_keys[3]);
    output[2] = x[25] ^ sm4_t(t ^ output[3] ^ round_keys[2]);
    let t = output[3] ^ output[2];
    output[1] = x[26] ^ sm4_t(t ^ x[27] ^ round_keys[1]);
    output[0] = x[27] ^ sm4_t(t ^ output[1] ^ round_keys[0]);
}

pub fn sm4_encrypt_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8], ciphertext: &mut [u8]) {
    let mut round_keys = [0u32; 32];
    key_expansion(key, &mut round_keys);
    
    let block_count = ciphertext.len() / 16;
    let mut init_vec = [0u32; 4];
    let mut iv_bytes = [0u8; 16];
    iv_bytes.copy_from_slice(iv);
    u8big_to_u32big(&mut init_vec, &iv_bytes);
    
    for i in 0..block_count {
        let start = i * 16;
        let end = start + 16;
        let ciphertext_block = &mut ciphertext[start..end];
        
        // 准备明文块，处理最后一个可能不完整的块
        let mut plaintext_block_bytes = [0u8; 16];
        let plaintext_start = start;
        let plaintext_end = std::cmp::min(plaintext_start + 16, plaintext.len());
        if plaintext_start < plaintext.len() {
            plaintext_block_bytes[..plaintext_end - plaintext_start].copy_from_slice(&plaintext[plaintext_start..plaintext_end]);
        }
        // 填充剩余字节为0
        for j in plaintext_end - plaintext_start..16 {
            plaintext_block_bytes[j] = 0;
        }
        
        let mut t1 = [0u32; 4];
        u8big_to_u32big(&mut t1, &plaintext_block_bytes);
        
        for j in 0..4 {
            t1[j] ^= init_vec[j];
        }
        
        sm4_en(&t1, &mut init_vec, &round_keys);
        
        let mut ciphertext_block_bytes = [0u8; 16];
        u32big_to_u8big(&mut ciphertext_block_bytes, &init_vec);
        ciphertext_block.copy_from_slice(&ciphertext_block_bytes);
    }
}

pub fn sm4_decrypt_cbc(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8], plaintext: &mut [u8]) {
    let mut round_keys = [0u32; 32];
    key_expansion(key, &mut round_keys);
    
    let block_count = ciphertext.len() / 16;
    let mut init_vec = [0u32; 4];
    let mut iv_bytes = [0u8; 16];
    iv_bytes.copy_from_slice(iv);
    u8big_to_u32big(&mut init_vec, &iv_bytes);
    
    for i in 0..block_count {
        let start = i * 16;
        let end = start + 16;
        let ciphertext_block = &ciphertext[start..end];
        let plaintext_block = &mut plaintext[start..end];
        
        let mut t1 = [0u32; 4];
        let mut ciphertext_block_bytes = [0u8; 16];
        ciphertext_block_bytes.copy_from_slice(ciphertext_block);
        u8big_to_u32big(&mut t1, &ciphertext_block_bytes);
        
        let mut t2 = [0u32; 4];
        sm4_de(&t1, &mut t2, &round_keys);
        
        for j in 0..4 {
            t2[j] ^= init_vec[j];
            init_vec[j] = t1[j];
        }
        
        let mut plaintext_block_bytes = [0u8; 16];
        u32big_to_u8big(&mut plaintext_block_bytes, &t2);
        plaintext_block.copy_from_slice(&plaintext_block_bytes);
    }
}