fn main() {
    use gm_sdk::sm3_hash;
    
    // 测试空输入
    let empty = [];
    let hash_empty = sm3_hash(&empty);
    println!("Empty input hash:");
    for b in &hash_empty {
        print!("{:02x}, ", b);
    }
    println!();
    
    // 测试"hello"输入
    let hello = b"hello";
    let hash_hello = sm3_hash(hello);
    println!("Hello input hash:");
    for b in &hash_hello {
        print!("{:02x}, ", b);
    }
    println!();
}