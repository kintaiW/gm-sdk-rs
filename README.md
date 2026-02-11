# gm-sdk-rs

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)

gm-sdk-rs 是一个使用 Rust 语言实现的国密算法 SDK，提供了 SM2、SM3、SM4 三种国密算法的完整实现。该项目旨在为 Rust 开发者提供高效、安全、易用的国密算法库，适用于需要符合国家密码标准的各种应用场景。

## 特性

- **纯 Rust 实现**：充分利用 Rust 语言的内存安全、零开销抽象等特性
- **符合国家标准**：严格按照国家密码管理局发布的标准实现
- **高性能**：针对 Rust 语言特性进行了优化，性能接近 C 语言实现
- **易于集成**：提供简洁的 API 接口，方便与其他 Rust 项目集成
- **完整测试**：包含标准测试数据，确保实现的正确性

## 支持的算法

- **SM2**：椭圆曲线密码算法，用于数字签名、密钥交换和公钥加密
- **SM3**：密码哈希函数，用于消息摘要和消息认证
- **SM4**：分组密码算法，用于数据加密

## 安装

在 `Cargo.toml` 文件中添加依赖：

```toml
dependencies =
    gm-sdk-rs = { path = "path/to/gm-sdk-rs" }
```

## 使用示例

### SM2 签名与验签

```rust
use gm_sdk::sm2::{sm2_generate_keypair, sm2_sign, sm2_verify};

// 生成密钥对
let (private_key, public_key) = sm2_generate_keypair();

// 消息
let message = b"Hello, GM SDK!";

// 签名
let signature = sm2_sign(&private_key, message);

// 验签
let result = sm2_verify(&public_key, message, &signature);
assert!(result);
```

### SM3 哈希计算

```rust
use gm_sdk::sm3::sm3_hash;

// 消息
let message = b"Hello, GM SDK!";

// 计算哈希
let hash = sm3_hash(message);

// 打印哈希值
println!("SM3 hash: {:02x?}", hash);
```

### SM4 加密解密

```rust
use gm_sdk::sm4::{sm4_encrypt_cbc, sm4_decrypt_cbc};

// 密钥和IV
let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

// 明文
let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

// 加密
let mut ciphertext = [0u8; 16];
sm4_encrypt_cbc(&key, &iv, &plaintext, &mut ciphertext);

// 解密
let mut decrypted = [0u8; 16];
sm4_decrypt_cbc(&key, &iv, &ciphertext, &mut decrypted);

assert_eq!(decrypted, plaintext);
```

## 项目结构

```
gm-sdk-rs/
├── Cargo.toml          # 项目配置文件
├── src/
│   ├── lib.rs          # 库入口文件
│   ├── sm2/            # SM2 算法实现
│   │   └── mod.rs
│   ├── sm3/            # SM3 算法实现
│   │   └── mod.rs
│   ├── sm4/            # SM4 算法实现
│   │   └── mod.rs
│   └── bin/            # 示例程序
│       ├── sm2_demo.rs
│       ├── sm4_demo.rs
│       └── hmac_sm3_demo.rs
└── tests/              # 测试文件
    ├── sm2_standard_test.rs
    ├── sm3_standard_test.rs
    └── sm4_standard_test.rs
```

## 运行测试

```bash
cd gm-sdk-rs
cargo test
```

## 运行示例

```bash
cd gm-sdk-rs
cargo run --bin sm2_demo
cargo run --bin sm4_demo
cargo run --bin hmac_sm3_demo
```

## 性能测试

项目包含性能测试功能，可以测试各算法的性能：

```bash
cd gm-sdk-rs
cargo test --release
```

## 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 Apache License Version 2.0 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件

## 联系方式

- 项目链接：[https://github.com/kintaiW/gm-sdk-rs.git](https://github.com/kintaiW/gm-sdk-rs.git)

## 致谢

- 感谢 Rust 语言社区提供的优秀工具和库
- 感谢国家密码管理局发布的国密算法标准
- 感谢所有为项目做出贡献的开发者