# HUKS部件

  - [简介](#简介)
  - [目录](#目录)
  - [编译构建](#编译构建)
  - [说明](#说明)
  - [相关仓](#相关仓)

## 简介

HUKS（OpenHarmony Universal KeyStore，OpenHarmony通用密钥库系统）向应用提供密钥库能力，包括密钥管理及密钥的密码学操作等功能。HUKS所管理的密钥可以由应用导入或者由应用调用HUKS接口生成。

HUKS模块可以分为如下三大部分：

-   HUKS SDK层：提供HUKS API供应用调用。

-   HUKS Service层：实现HUKS密钥管理、存储等功能。

-   HUKS Core层：HUKS核心模块，负责密钥生成以及加解密等工作。对于标准系统设备，该部分模块在商用场景下必须在安全环境下运行，包括TEE或者具备安全能力的芯片等。由于安全环境需要特定硬件支持，因此在开源代码中为模拟实现。对于小型和轻量系统，HUKS模块仅提供根密钥保护方案的模拟实现，商用场景下必须根据产品能力适配硬件根密钥或者使用其他根密钥保护方案。

HUKS部件架构如下图所示：

<div align=center>

<img src=figures/huks_architecture.png width=80% align=center/>

</div>

## 目录

```
├── build                              # 编译配置文件
├── frameworks                         # 框架代码, 作为基础功能目录, 被interfaces和services使用
│   ├── huks_lite                      # 小型和轻量系统编译脚本
│   └── huks_standard                  # 代码实现
├── interfaces                         # 接口API代码
│   ├── inner_api                      # inner api接口
│   └── kits                           # 对外api接口
├── services                           # 服务框架代码
│   └── huks_standard
│       ├── huks_engine                # HUKS 核心层代码
│       └── huks_service               # HUKS 服务层代码
├── test                               # 测试代码存放目录
└── utils                              # 工具代码存放目录
```

## 编译构建

**单仓编译**

以RK3568为例，以下编译命令可以单独编译HUKS单仓和测试文件：
```
本模块单独编译命令
./build.sh --product-name=rk3568 --build-target out/rk3568/build_configs/security/huks:huks

本模块测试文件单独编译命令
./build.sh --product-name rk3568 --build-target out/rk3568/build_configs/security/huks:huks_test
```

## 说明

### 接口说明

[接口文档](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-universal-keystore-kit/Readme-CN.md)

### 使用说明

[开发指导](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/Readme-CN.md)

<font color = grey> 注：HUKS部件包含密钥管理及密钥的密码学操作等功能，如果仅需要进行密钥的密码学操作而不需要密钥管理，建议使用[加解密算法库框架](https://gitee.com/openharmony/security_crypto_framework)。</font>


## 相关仓

[security_crypto_framework](https://gitee.com/openharmony/security_crypto_framework)

[security_certificate_manager](https://gitee.com/openharmony/security_certificate_manager)

[**security_huks**](https://gitee.com/openharmony/security_huks)

[third_party_openssl](https://gitee.com/openharmony/third_party_openssl)

[third_party_mbedtls](https://gitee.com/openharmony/third_party_mbedtls)