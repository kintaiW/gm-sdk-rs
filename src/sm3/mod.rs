pub fn sm3_hash(data: &[u8]) -> [u8; 32] {
    let mut state = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E];
    let mut buffer = [0u8; 64];
    let len = data.len() as u64 * 8;
    
    let mut pos = 0;
    let data_len = data.len();
    
    while pos < data_len {
        let remain = data_len - pos;
        if remain >= 64 {
            buffer.copy_from_slice(&data[pos..pos+64]);
            compress(&mut state, &buffer);
            pos += 64;
        } else {
            buffer[..remain].copy_from_slice(&data[pos..]);
            buffer[remain] = 0x80;
            for i in remain+1..64 {
                buffer[i] = 0;
            }
            if remain <= 55 {
                for i in 0..8 {
                    buffer[56+i] = ((len >> (56 - i*8)) & 0xFF) as u8;
                }
                compress(&mut state, &buffer);
            } else {
                compress(&mut state, &buffer);
                for i in 0..64 {
                    buffer[i] = 0;
                }
                for i in 0..8 {
                    buffer[56+i] = ((len >> (56 - i*8)) & 0xFF) as u8;
                }
                compress(&mut state, &buffer);
            }
            break;
        }
    }
    
    // 处理正好64字节的情况
    if data_len % 64 == 0 && data_len > 0 {
        buffer[0] = 0x80;
        for i in 1..64 {
            buffer[i] = 0;
        }
        for i in 0..8 {
            buffer[56+i] = ((len >> (56 - i*8)) & 0xFF) as u8;
        }
        compress(&mut state, &buffer);
    }
    
    if data.is_empty() {
        buffer[0] = 0x80;
        for i in 1..64 {
            buffer[i] = 0;
        }
        for i in 0..8 {
            buffer[56+i] = ((len >> (56 - i*8)) & 0xFF) as u8;
        }
        compress(&mut state, &buffer);
    }
    
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i*4] = ((state[i] >> 24) & 0xFF) as u8;
        result[i*4+1] = ((state[i] >> 16) & 0xFF) as u8;
        result[i*4+2] = ((state[i] >> 8) & 0xFF) as u8;
        result[i*4+3] = (state[i] & 0xFF) as u8;
    }
    result
}

pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut ikey = [0u8; 64];
    let mut okey = [0u8; 64];
    
    if key.len() > 64 {
        let hash = sm3_hash(key);
        ikey[..32].copy_from_slice(&hash);
        okey[..32].copy_from_slice(&hash);
    } else {
        ikey[..key.len()].copy_from_slice(key);
        okey[..key.len()].copy_from_slice(key);
    }
    
    for i in 0..64 {
        ikey[i] ^= 0x36;
        okey[i] ^= 0x5C;
    }
    
    let mut inner = vec![0u8; 64 + data.len()];
    inner[..64].copy_from_slice(&ikey);
    inner[64..].copy_from_slice(data);
    let inner_hash = sm3_hash(&inner);
    
    let mut outer = vec![0u8; 64 + 32];
    outer[..64].copy_from_slice(&okey);
    outer[64..].copy_from_slice(&inner_hash);
    sm3_hash(&outer)
}

fn compress(state: &mut [u32; 8], data: &[u8]) {
    let mut w = [0u32; 68];
    let mut w1 = [0u32; 64];
    
    // 初始化w[0..15] - 与C语言实现的U32Small_to_U32Big一致
    for i in 0..16 {
        w[i] = ((data[i*4] as u32) << 24) |
               ((data[i*4+1] as u32) << 16) |
               ((data[i*4+2] as u32) << 8) |
               (data[i*4+3] as u32);
    }
    
    // 计算w[16..67] - 与C语言实现完全一致
    for j in (16..=58).step_by(6) {
        for i in j..j+3 {
            let w_1 = w[i-16] ^ w[i-9] ^ w[i-3].rotate_left(15);
            w[i] = p1(w_1) ^ w[i-13].rotate_left(7) ^ w[i-6];
            let w_1 = w[i-13] ^ w[i-6] ^ w[i].rotate_left(15);
            w[i+3] = p1(w_1) ^ w[i-10].rotate_left(7) ^ w[i-3];
        }
    }
    for i in 64..68 {
        let w_1 = w[i-16] ^ w[i-9] ^ w[i-3].rotate_left(15);
        w[i] = p1(w_1) ^ w[i-13].rotate_left(7) ^ w[i-6];
    }
    
    // 计算w1[0..63]
    for i in 0..64 {
        w1[i] = w[i] ^ w[i+4];
    }
    
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    
    for i in 0..64 {
        // 计算轮常量SS - 与C语言实现完全一致
        let mut ss = if i < 16 {
            0x79CC4519u32.rotate_left(i)
        } else {
            0x7A879D8Au32.rotate_left(if i < 32 { i } else { i - 32 })
        };
        
        // 计算SS1 - 与C语言实现完全一致
        ss = ss.wrapping_add(e).wrapping_add(a.rotate_left(12));
        let ss1 = ss.rotate_left(7);
        
        // 计算TT2 - 与C语言实现完全一致
        let mut tt2 = if i < 16 {
            e ^ f ^ g
        } else {
            (e & f) | ((!e) & g)
        };
        tt2 = tt2.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[i as usize]);
        
        // 计算SS2 - 与C语言实现完全一致
        let ss2 = ss1 ^ a.rotate_left(12);
        
        // 计算TT1 - 与C语言实现完全一致
        let mut tt1 = if i < 16 {
            a ^ b ^ c
        } else {
            (a & b) | (a & c) | (b & c)
        };
        tt1 = tt1.wrapping_add(d).wrapping_add(ss2).wrapping_add(w1[i as usize]);
        
        // 更新状态 - 与C语言实现完全一致
        let old_a = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
        d = c;
        c = b.rotate_left(9);
        b = old_a;
    }
    
    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}
