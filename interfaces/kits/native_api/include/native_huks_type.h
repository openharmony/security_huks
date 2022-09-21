/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file native_huks_type.h
 *
 * @brief 提供huks中的枚举变量、结构体定义与宏定义。
 *
 * @since 9
 * @version 1.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef NATIVE_HUKS_TYPE_H
#define NATIVE_HUKS_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Align to 4-tuple。
 *
 * Before calling this function, ensure that the size does not overflow after 3 is added.
 *
 * @since 9
 * @version 1.0
 */
#define OH_HUKS_DEFAULT_ALIGN_MASK_SIZE 3

#define OH_HUKS_AE_TAG_LEN 16
#define OH_HUKS_BITS_PER_BYTE 8
#define OH_HUKS_MAX_KEY_SIZE 2048
#define OH_HUKS_AE_NONCE_LEN 12
#define OH_HUKS_MAX_KEY_ALIAS_LEN 64
#define OH_HUKS_MAX_PROCESS_NAME_LEN 50
#define OH_HUKS_MAX_RANDOM_LEN 1024
#define OH_HUKS_SIGNATURE_MIN_SIZE 64
#define OH_HUKS_MAX_OUT_BLOB_SIZE (5 * 1024 * 1024)
#define OH_HUKS_WRAPPED_FORMAT_MAX_SIZE (1024 * 1024)
#define OH_HUKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS 10
#define TOKEN_CHALLENGE_LEN 32
#define SHA256_SIGN_LEN 32
#define TOKEN_SIZE 32
#define MAX_AUTH_TIMEOUT_SECOND 60
#define SECURE_SIGN_VERSION 0x01000001

/**
 * @brief 表示密钥用途。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyPurpose {
    /** 表示密钥用于对明文进行加密操作。 */
    OH_HUKS_KEY_PURPOSE_ENCRYPT = 1,
    /** 表示密钥用于对密文进行解密操作。 */
    OH_HUKS_KEY_PURPOSE_DECRYPT = 2,
    /** 表示密钥用于对数据进行签名。 */
    OH_HUKS_KEY_PURPOSE_SIGN = 4,
    /** 表示密钥用于验证签名后的数据。 */
    OH_HUKS_KEY_PURPOSE_VERIFY = 8,
    /** 表示密钥用于派生密钥。 */
    OH_HUKS_KEY_PURPOSE_DERIVE = 16,
    /** 表示密钥用于加密导出。 */
    OH_HUKS_KEY_PURPOSE_WRAP = 32,
    /** 表示密钥加密导入。 */
    OH_HUKS_KEY_PURPOSE_UNWRAP = 64,
    /** 表示密钥用于生成mac消息验证码。 */
    OH_HUKS_KEY_PURPOSE_MAC = 128,
    /** 表示密钥用于进行密钥协商。 */
    OH_HUKS_KEY_PURPOSE_AGREE = 256,
};

/**
 * @brief 表示摘要算法类型。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyDigest {
    /** 无摘要算法。 */
    OH_HUKS_DIGEST_NONE = 0,
    /** MD5摘要算法。 */
    OH_HUKS_DIGEST_MD5 = 1,
    /** SM3摘要算法。 */
    OH_HUKS_DIGEST_SM3 = 2,
    /** SHA1摘要算法。 */
    OH_HUKS_DIGEST_SHA1 = 10,
    /** SHA224摘要算法。 */
    OH_HUKS_DIGEST_SHA224 = 11,
    /** SHA256摘要算法。 */
    OH_HUKS_DIGEST_SHA256 = 12,
    /** SHA384摘要算法。 */
    OH_HUKS_DIGEST_SHA384 = 13,
    /** SHA512摘要算法。 */
    OH_HUKS_DIGEST_SHA512 = 14,
};

/**
 * @brief 表示补齐算法。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyPadding {
    /** 不使用补齐算法。 */
    OH_HUKS_PADDING_NONE = 0,
    /** 使用OAEP补齐算法。 */
    OH_HUKS_PADDING_OAEP = 1,
    /** 使用PSS补齐算法。 */
    OH_HUKS_PADDING_PSS = 2,
    /** 使用PKCS1_V1_5补齐算法。 */
    OH_HUKS_PADDING_PKCS1_V1_5 = 3,
    /** 使用PKCS5补齐算法。 */
    OH_HUKS_PADDING_PKCS5 = 4,
    /** 使用PKCS7补齐算法。 */
    OH_HUKS_PADDING_PKCS7 = 5,
};

/**
 * @brief 表示加密工作模式。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_CipherMode {
    /** 使用ECB加密模式。 */
    OH_HUKS_MODE_ECB = 1,
    /** 使用CBC加密模式。 */
    OH_HUKS_MODE_CBC = 2,
    /** 使用CTR加密模式。 */
    OH_HUKS_MODE_CTR = 3,
    /** 使用OFB加密模式。 */
    OH_HUKS_MODE_OFB = 4,
    /** 使用CCM加密模式。 */
    OH_HUKS_MODE_CCM = 31,
    /** 使用GCM加密模式。 */
    OH_HUKS_MODE_GCM = 32,
};

/**
 * @brief 表示密钥长度。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeySize {
    /** 使用RSA算法的密钥长度为512bit。 */
    OH_HUKS_RSA_KEY_SIZE_512 = 512,
    /** 使用RSA算法的密钥长度为768bit。 */
    OH_HUKS_RSA_KEY_SIZE_768 = 768,
    /** 使用RSA算法的密钥长度为1024bit。 */
    OH_HUKS_RSA_KEY_SIZE_1024 = 1024,
    /** 使用RSA算法的密钥长度为2048bit。 */
    OH_HUKS_RSA_KEY_SIZE_2048 = 2048,
    /** 使用RSA算法的密钥长度为3072bit。 */
    OH_HUKS_RSA_KEY_SIZE_3072 = 3072,
    /** 使用RSA算法的密钥长度为4096bit。 */
    OH_HUKS_RSA_KEY_SIZE_4096 = 4096,
    
    /** 使用ECC算法的密钥长度为224bit。 */
    OH_HUKS_ECC_KEY_SIZE_224 = 224,
    /** 使用ECC算法的密钥长度为256bit。 */
    OH_HUKS_ECC_KEY_SIZE_256 = 256,
    /** 使用ECC算法的密钥长度为384bit。 */
    OH_HUKS_ECC_KEY_SIZE_384 = 384,
    /** 使用ECC算法的密钥长度为521bit。 */
    OH_HUKS_ECC_KEY_SIZE_521 = 521,

    /** 使用AES算法的密钥长度为128bit。 */
    OH_HUKS_AES_KEY_SIZE_128 = 128,
    /** 使用AES算法的密钥长度为192bit。 */
    OH_HUKS_AES_KEY_SIZE_192 = 192,
    /** 使用AES算法的密钥长度为256bit。 */
    OH_HUKS_AES_KEY_SIZE_256 = 256,
    /** 使用AES算法的密钥长度为512bit。 */
    OH_HUKS_AES_KEY_SIZE_512 = 512,

    /** 使用CURVE25519算法的密钥长度为256bit。 */
    OH_HUKS_CURVE25519_KEY_SIZE_256 = 256,

    /** 使用DH算法的密钥长度为2048bit。 */
    OH_HUKS_DH_KEY_SIZE_2048 = 2048,
    /** 使用DH算法的密钥长度为3072bit。 */
    OH_HUKS_DH_KEY_SIZE_3072 = 3072,
    /** 使用DH算法的密钥长度为4096bit。 */
    OH_HUKS_DH_KEY_SIZE_4096 = 4096,

    /** 使用SM2算法的密钥长度为256bit。 */
    OH_HUKS_SM2_KEY_SIZE_256 = 256,
    /** 使用SM4算法支持的密钥长度为128位。 */
    OH_HUKS_SM4_KEY_SIZE_128 = 128,
};

/**
 * @brief 表示密钥使用的算法。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyAlg {
    /** 使用RSA算法。 */
    OH_HUKS_ALG_RSA = 1,
    /** 使用ECC算法。 */
    OH_HUKS_ALG_ECC = 2,
    /** 使用DSA算法。 */
    OH_HUKS_ALG_DSA = 3,

    /** 使用AES算法。 */
    OH_HUKS_ALG_AES = 20,
    /** 使用HMAC算法。 */
    OH_HUKS_ALG_HMAC = 50,
    /** 使用HKDF算法。 */
    OH_HUKS_ALG_HKDF = 51,
    /** 使用PBKDF2算法。 */
    OH_HUKS_ALG_PBKDF2 = 52,

    /** 使用ECDH算法。 */
    OH_HUKS_ALG_ECDH = 100,
    /** 使用X25519算法。 */
    OH_HUKS_ALG_X25519 = 101,
    /** 使用ED25519算法。 */
    OH_HUKS_ALG_ED25519 = 102,
    /** 使用DH算法。 */
    OH_HUKS_ALG_DH = 103,

    /** 使用SM2算法。*/
    OH_HUKS_ALG_SM2 = 150,
    /** 使用SM3算法。*/
    OH_HUKS_ALG_SM3 = 151,
    /** 使用SM4算法。*/
    OH_HUKS_ALG_SM4 = 152,
};

/**
 * @brief 表示导入加密密钥的算法套件。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_AlgSuite {
    /** Algorithm suites of unwrapping wrapped-key by huks
     *  Unwrap suite of key agreement type
     */
    /** WrappedData format(Bytes Array):
     *  | x25519_plain_pubkey_length  (4 Byte) | x25519_plain_pubkey |  agreekey_aad_length (4 Byte) | agreekey_aad
     *  |   agreekey_nonce_length     (4 Byte) |   agreekey_nonce    | agreekey_aead_tag_len(4 Byte) | agreekey_aead_tag
     *  |    kek_enc_data_length      (4 Byte) |    kek_enc_data     |    kek_aad_length    (4 Byte) | kek_aad
     *  |      kek_nonce_length       (4 Byte) |      kek_nonce      |   kek_aead_tag_len   (4 Byte) | kek_aead_tag
     *  |   key_material_size_len     (4 Byte) |  key_material_size  |   key_mat_enc_length (4 Byte) | key_mat_enc_data
     */
    /** 导入加密密钥时，X25519密钥协商后使用AES-256 GCM加密。 */
    OH_HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING = 1,

    /* WrappedData format(Bytes Array):
     *  |  ECC_plain_pubkey_length    (4 Byte) |  ECC_plain_pubkey   |  agreekey_aad_length (4 Byte) | agreekey_aad
     *  |   agreekey_nonce_length     (4 Byte) |   agreekey_nonce    | agreekey_aead_tag_len(4 Byte) | agreekey_aead_tag
     *  |    kek_enc_data_length      (4 Byte) |    kek_enc_data     |    kek_aad_length    (4 Byte) | kek_aad
     *  |      kek_nonce_length       (4 Byte) |      kek_nonce      |   kek_aead_tag_len   (4 Byte) | kek_aead_tag
     *  |   key_material_size_len     (4 Byte) |  key_material_size  |   key_mat_enc_length (4 Byte) | key_mat_enc_data
     */
    /** 导入加密密钥时，ECDH密钥协商后使用AES-256 GCM加密。 */
    OH_HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING = 2,
};

/**
 * @brief 表示生成的密钥类型。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyGenerateType {
    /** 默认生成的密钥。 */
    OH_HUKS_KEY_GENERATE_TYPE_DEFAULT = 0,
    /** 派生生成的密钥。 */
    OH_HUKS_KEY_GENERATE_TYPE_DERIVE = 1,
    /** 协商生成的密钥。 */
    OH_HUKS_KEY_GENERATE_TYPE_AGREE = 2,
};

/**
 * @brief 表示密钥的产生方式。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyFlag {
    /** 通过导入公钥接口导入的密钥。*/
    OH_HUKS_KEY_FLAG_IMPORT_KEY = 1,
    /** 通过生成密钥接口生成的密钥。*/
    OH_HUKS_KEY_FLAG_GENERATE_KEY = 2,
    /** 通过生成密钥协商接口生成的密钥。*/
    OH_HUKS_KEY_FLAG_AGREE_KEY = 3,
    /** 通过生成密钥派生接口生成的密钥。*/
    OH_HUKS_KEY_FLAG_DERIVE_KEY = 4,
};

/**
 * @brief 表示密钥的存储方式。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_KeyStorageType {
    /** 通过本地直接管理密钥。*/
    OH_HUKS_STORAGE_TEMP = 0,
    /** 通过HUKS service管理密钥。*/
    OH_HUKS_STORAGE_PERSISTENT = 1,
};

/**
 * @brief 导入密钥的类型，默认为导入公钥，导入对称密钥时不需要该字段。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_ImportKeyType {
    /** 导入的密钥类型为公钥。 */
    OH_HUKS_KEY_TYPE_PUBLIC_KEY = 0,
    /** 导入的密钥类型为私钥。 */
    OH_HUKS_KEY_TYPE_PRIVATE_KEY = 1,
    /** 导入的密钥类型为公私钥对。 */
    OH_HUKS_KEY_TYPE_KEY_PAIR = 2,
};

/**
 * @brief 表示状态返回码。
 *
 * @since 9
 * @version 1.0
 */
enum  OH_Huks_ErrCode {
    /** 成功。 */
    OH_HUKS_SUCCESS = 0,
    /** 权限校验失败。 */
    OH_HUKS_ERR_CODE_PERMISSION_FAIL = 201,
    /** 非法参数（通用）。 */
    OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT = 401,
    /** 不支持该API。 */
    OH_HUKS_ERR_CODE_NOT_SUPPORTED_API = 801,

    /** 不支持该子功能（特性）。 */
    OH_HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED = 12000001,
    /** 缺少密钥算法参数。 */
    OH_HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT = 12000002,
    /** 无效的密钥算法参数。 */
    OH_HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT = 12000003,
    /** 文件错误。 */
    OH_HUKS_ERR_CODE_FILE_OPERATION_FAIL = 12000004,
    /** 进程通信错误。 */
    OH_HUKS_ERR_CODE_COMMUNICATION_FAIL = 12000005,
    /** 算法库操作失败。 */
    OH_HUKS_ERR_CODE_CRYPTO_FAIL = 12000006,
    /** 密钥访问失败 - 密钥已失效。 */
    OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED = 12000007,
    /** 密钥访问失败 - 密钥认证失败。 */
    OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED = 12000008,
    /** 密钥访问失败 - 密钥访问超时。 */
    OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT = 12000009,
    /** 密钥操作会话数已达上限。 */
    OH_HUKS_ERR_CODE_SESSION_LIMIT = 12000010,
    /** 该项实体不存在。 */
    OH_HUKS_ERR_CODE_ITEM_NOT_EXIST = 12000011,
    /** 内部错误。 */
    OH_HUKS_ERR_CODE_INTERNAL_ERROR = 12000012,
    /** 缺失所需凭据。 */
    OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST = 12000013,
};

/**
 * @brief 表示Tag的数据类型。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_TagType {
    /** 表示非法的Tag类型。 */
    OH_HUKS_TAG_TYPE_INVALID = 0 << 28,
    /** 表示该Tag的数据类型为int类型的number。 */
    OH_HUKS_TAG_TYPE_INT = 1 << 28,
    /** 表示该Tag的数据类型为uint类型的number。 */
    OH_HUKS_TAG_TYPE_UINT = 2 << 28,
    /** 表示该Tag的数据类型为bigint。 */
    OH_HUKS_TAG_TYPE_ULONG = 3 << 28,
    /** 表示该Tag的数据类型为boolean。 */
    OH_HUKS_TAG_TYPE_BOOL = 4 << 28,
    /** 表示该Tag的数据类型为Uint8Array。 */
    OH_HUKS_TAG_TYPE_BYTES = 5 << 28,
};

/**
 * @brief 表示发送Tag的方式
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_SendType {
    /** 表示异步发送TAG。 */
    OH_HUKS_SEND_TYPE_ASYNC = 0,
    /** 表示同步发送TAG。 */
    OH_HUKS_SEND_TYPE_SYNC,
};

/**
 * @brief 表示用户认证类型
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_UserAuthType {
    /** 用户认证类型为指纹。 */
    OH_HUKS_USER_AUTH_TYPE_FINGERPRINT = 1 << 0,
    /** 用户认证类型为人脸。 */
    OH_HUKS_USER_AUTH_TYPE_FACE = 1 << 1,
    /** 用户认证类型为PIN码。 */
    OH_HUKS_USER_AUTH_TYPE_PIN = 1 << 2,
};

/**
 * @brief 表示安全访问控制类型
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_AuthAccessType {
    /** 安全访问控制类型为清除密码后密钥无效。 */
    OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD = 1 << 0,
    /** 安全访问控制类型为新录入生物特征后密钥无效。 */
    OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL = 1 << 1,
};

/**
 * @brief 密钥使用时生成challenge的类型
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_ChallengeType {
    /** challenge为普通类型，默认32字节。 */
    OH_HUKS_CHALLENGE_TYPE_NORMAL = 0,
    /** challenge为用户自定义类型。支持使用多个密钥仅一次认证。 */
    OH_HUKS_CHALLENGE_TYPE_CUSTOM = 1,
    /** 免challenge类型。 */
    OH_HUKS_CHALLENGE_TYPE_NONE = 2,
};

/**
 * @brief challenge类型为用户自定义类型时，生成的challenge有效长度仅为8字节连续的数据，且仅支持4种位置。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_ChallengePosition {
    /** 0~7字节为当前密钥的有效challenge。 */
    OH_HUKS_CHALLENGE_POS_0 = 0,
    /** 8~15字节为当前密钥的有效challenge。 */
    OH_HUKS_CHALLENGE_POS_1,
    /** 16~23字节为当前密钥的有效challenge。 */
    OH_HUKS_CHALLENGE_POS_2,
    /** 24~31字节为当前密钥的有效challenge。 */
    OH_HUKS_CHALLENGE_POS_3,
};

/**
 * @brief 生成或导入密钥时，指定该密钥的签名类型。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_SecureSignType {
    /** 签名类型为携带认证信息。生成或导入密钥时指定该字段，则在使用密钥进行签名时，对待签名的数据添加认证信息后进行签名。 */
    OH_HUKS_SECURE_SIGN_WITH_AUTHINFO = 1,
};

/**
 * @brief 表示调用参数的Tag。
 *
 * @since 9
 * @version 1.0
 */
enum OH_Huks_Tag {
    /** 非法的Tag。 */
    OH_HUKS_TAG_INVALID = OH_HUKS_TAG_TYPE_INVALID | 0,

    /** 基础算法中用到的Tag从1到200。 */
    /** 算法类型。 */
    OH_HUKS_TAG_ALGORITHM = OH_HUKS_TAG_TYPE_UINT | 1,
    /** 密钥用途。 */
    OH_HUKS_TAG_PURPOSE = OH_HUKS_TAG_TYPE_UINT | 2,
    /** 密钥长度 。 */
    OH_HUKS_TAG_KEY_SIZE = OH_HUKS_TAG_TYPE_UINT | 3,
    /** 摘要算法。 */
    OH_HUKS_TAG_DIGEST = OH_HUKS_TAG_TYPE_UINT | 4,
    /** 补齐算法。 */
    OH_HUKS_TAG_PADDING = OH_HUKS_TAG_TYPE_UINT | 5,
    /** 加密模式。 */
    OH_HUKS_TAG_BLOCK_MODE = OH_HUKS_TAG_TYPE_UINT | 6,
    /** 密钥类型。 */
    OH_HUKS_TAG_KEY_TYPE = OH_HUKS_TAG_TYPE_UINT | 7,
    /** 附加身份验证数据。 */
    OH_HUKS_TAG_ASSOCIATED_DATA = OH_HUKS_TAG_TYPE_BYTES | 8,
    /** 密钥加解密的字段。 */
    OH_HUKS_TAG_NONCE = OH_HUKS_TAG_TYPE_BYTES | 9,
    /** 初始化的向量。 */
    OH_HUKS_TAG_IV = OH_HUKS_TAG_TYPE_BYTES | 10,

    /** 用于密钥派生的Tag。 */
    /** 密钥派生时的info。 */
    OH_HUKS_TAG_INFO = OH_HUKS_TAG_TYPE_BYTES | 11,
    /** 派生盐值。 */
    OH_HUKS_TAG_SALT = OH_HUKS_TAG_TYPE_BYTES | 12,
    /** 派生密码。 */
    OH_HUKS_TAG_PWD = OH_HUKS_TAG_TYPE_BYTES | 13,
    /** 派生迭代次数。 */
    OH_HUKS_TAG_ITERATION = OH_HUKS_TAG_TYPE_UINT | 14,

    /** 生成密钥的类型，类型可在枚举OH_Huks_KeyGenerateType中选择。 */
    OH_HUKS_TAG_KEY_GENERATE_TYPE = OH_HUKS_TAG_TYPE_UINT | 15,
    /** 密钥派生时的主密钥。 */
    OH_HUKS_TAG_DERIVE_MAIN_KEY = OH_HUKS_TAG_TYPE_BYTES | 16,
    /** 派生时的派生因子。 */
    OH_HUKS_TAG_DERIVE_FACTOR = OH_HUKS_TAG_TYPE_BYTES | 17,
    /** 派生时的算法类型。 */
    OH_HUKS_TAG_DERIVE_ALG = OH_HUKS_TAG_TYPE_UINT | 18,
    /** 密钥协商时的算法类型。 */
    OH_HUKS_TAG_AGREE_ALG = OH_HUKS_TAG_TYPE_UINT | 19,
    /** 密钥协商时的公钥别名。 */
    OH_HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS = OH_HUKS_TAG_TYPE_BOOL | 20,
    /** 密钥协商时的私钥别名。 */
    OH_HUKS_TAG_AGREE_PRIVATE_KEY_ALIAS = OH_HUKS_TAG_TYPE_BYTES | 21,
    /** 用于协商的公钥。 */
    OH_HUKS_TAG_AGREE_PUBLIC_KEY = OH_HUKS_TAG_TYPE_BYTES | 22,
    /** 密钥别名。 */
    OH_HUKS_TAG_KEY_ALIAS = OH_HUKS_TAG_TYPE_BYTES | 23,
    /** 派生密钥大小。 */
    OH_HUKS_TAG_DERIVE_KEY_SIZE = OH_HUKS_TAG_TYPE_UINT | 24,
    /** 导入密钥类型, 类型可在枚举OH_Huks_ImportKeyType中选择。 */
    OH_HUKS_TAG_IMPORT_KEY_TYPE = OH_HUKS_TAG_TYPE_UINT | 25,
    /** 导入加密密钥的套件。 */
    OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE = OH_HUKS_TAG_TYPE_UINT | 26,

    /** 密钥认证需要用到的标签值从201到300。 */
    /** 预留。 */
    OH_HUKS_TAG_ACTIVE_DATETIME = OH_HUKS_TAG_TYPE_ULONG | 201,

    /** Date when new "messages" should not be created. */
    /** 预留。 */
    OH_HUKS_TAG_ORIGINATION_EXPIRE_DATETIME = OH_HUKS_TAG_TYPE_ULONG | 202,

    /** Date when existing "messages" should not be used. */
    /** 预留。 */
    OH_HUKS_TAG_USAGE_EXPIRE_DATETIME = OH_HUKS_TAG_TYPE_ULONG | 203,

    /** 预留。 */
    OH_HUKS_TAG_CREATION_DATETIME = OH_HUKS_TAG_TYPE_ULONG | 204,

    /** Other authentication related TAG: 301 - 500 */
    /** 预留。 */
    OH_HUKS_TAG_ALL_USERS = OH_HUKS_TAG_TYPE_BOOL | 301,
    /** 预留。 */
    OH_HUKS_TAG_USER_ID = OH_HUKS_TAG_TYPE_UINT | 302,
    /** 预留。 */
    OH_HUKS_TAG_NO_AUTH_REQUIRED = OH_HUKS_TAG_TYPE_BOOL | 303,
    /** 用户认证类型。 */
    OH_HUKS_TAG_USER_AUTH_TYPE = OH_HUKS_TAG_TYPE_UINT | 304,
    /** 预留。 */
    OH_HUKS_TAG_AUTH_TIMEOUT = OH_HUKS_TAG_TYPE_UINT | 305,
    /** 预留。 */
    OH_HUKS_TAG_AUTH_TOKEN = OH_HUKS_TAG_TYPE_BYTES | 306,
    /** 表示安全访问控制类型。从OH_Huks_AuthAccessType中选择，需要和用户认证类型同时设置。 */
    OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE = OH_HUKS_TAG_TYPE_UINT | 307,
    /** 表示生成或导入密钥时，指定该密钥的签名类型。 */
    OH_HUKS_TAG_KEY_SECURE_SIGN_TYPE = OH_HUKS_TAG_TYPE_UINT | 308,
    /** 表示密钥使用时生成的challenge类型。从OH_Huks_ChallengeType中选择。 */
    OH_HUKS_TAG_CHALLENGE_TYPE = OH_HUKS_TAG_TYPE_UINT | 309,
    /** 表示challenge类型为用户自定义类型时，huks产生的challenge有效长度仅为8字节连续的数据。从OH_Huks_ChallengePosition中选择。 */
    OH_HUKS_TAG_CHALLENGE_POS = OH_HUKS_TAG_TYPE_UINT | 310,

    /** Attestation related TAG: 501 - 600 */
    /** attestation时的挑战值。 */
    OH_HUKS_TAG_ATTESTATION_CHALLENGE = OH_HUKS_TAG_TYPE_BYTES | 501,
    /** attestation时拥有该密钥的application的Id。 */
    OH_HUKS_TAG_ATTESTATION_APPLICATION_ID = OH_HUKS_TAG_TYPE_BYTES | 502,
    /** 设备的品牌。 */
    OH_HUKS_TAG_ATTESTATION_ID_BRAND = OH_HUKS_TAG_TYPE_BYTES | 503,
    /** 设备的设备ID。 */
    OH_HUKS_TAG_ATTESTATION_ID_DEVICE = OH_HUKS_TAG_TYPE_BYTES | 504,
    /** 设备的产品名。 */
    OH_HUKS_TAG_ATTESTATION_ID_PRODUCT = OH_HUKS_TAG_TYPE_BYTES | 505,
    /** 设备的SN号。 */
    OH_HUKS_TAG_ATTESTATION_ID_SERIAL = OH_HUKS_TAG_TYPE_BYTES | 506,
    /** 设备的IMEI号。 */
    OH_HUKS_TAG_ATTESTATION_ID_IMEI = OH_HUKS_TAG_TYPE_BYTES | 507,
    /** 设备的MEID号。 */
    OH_HUKS_TAG_ATTESTATION_ID_MEID = OH_HUKS_TAG_TYPE_BYTES | 508,
    /** 设备的制造商。 */
    OH_HUKS_TAG_ATTESTATION_ID_MANUFACTURER = OH_HUKS_TAG_TYPE_BYTES | 509,
    /** 设备的型号。 */
    OH_HUKS_TAG_ATTESTATION_ID_MODEL = OH_HUKS_TAG_TYPE_BYTES | 510,
    /** attestation时的密钥别名。 */
    OH_HUKS_TAG_ATTESTATION_ID_ALIAS = OH_HUKS_TAG_TYPE_BYTES | 511,
    /** 设备的SOCID。 */
    OH_HUKS_TAG_ATTESTATION_ID_SOCID = OH_HUKS_TAG_TYPE_BYTES | 512,
    /** 设备的UDID。 */
    OH_HUKS_TAG_ATTESTATION_ID_UDID = OH_HUKS_TAG_TYPE_BYTES | 513,
    /** attestation时的安全凭据。 */
    OH_HUKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO = OH_HUKS_TAG_TYPE_BYTES | 514,
    /** attestation时的版本号。 */
    OH_HUKS_TAG_ATTESTATION_ID_VERSION_INFO = OH_HUKS_TAG_TYPE_BYTES | 515,

    /**
     * Other reserved TAG: 601 - 1000
     *
     * Extention TAG: 1001 - 9999
     */
    /** 是否使用生成key时传入的别名的Tag。 */
    OH_HUKS_TAG_IS_KEY_ALIAS = OH_HUKS_TAG_TYPE_BOOL | 1001,
    /** 密钥存储方式的Tag, 类型可在枚举OH_Huks_KeyStorageType选择。 */
    OH_HUKS_TAG_KEY_STORAGE_FLAG = OH_HUKS_TAG_TYPE_UINT | 1002,
    /** 预留。 */
    OH_HUKS_TAG_IS_ALLOWED_WRAP = OH_HUKS_TAG_TYPE_BOOL | 1003,
    /** 预留。 */
    OH_HUKS_TAG_KEY_WRAP_TYPE = OH_HUKS_TAG_TYPE_UINT | 1004,
    /** 预留。 */
    OH_HUKS_TAG_KEY_AUTH_ID = OH_HUKS_TAG_TYPE_BYTES | 1005,
    /** 预留。 */
    OH_HUKS_TAG_KEY_ROLE = OH_HUKS_TAG_TYPE_UINT | 1006,
    /** 密钥标志的Tag, 类型可在枚举OH_Huks_KeyFlag选择。 */
    OH_HUKS_TAG_KEY_FLAG = OH_HUKS_TAG_TYPE_UINT | 1007,
    /** 预留。 */
    OH_HUKS_TAG_IS_ASYNCHRONIZED = OH_HUKS_TAG_TYPE_UINT | 1008,
    /** 预留。 */
    OH_HUKS_TAG_SECURE_KEY_ALIAS = OH_HUKS_TAG_TYPE_BOOL | 1009,
    /** 预留。 */
    OH_HUKS_TAG_SECURE_KEY_UUID = OH_HUKS_TAG_TYPE_BYTES | 1010,
    /** 预留。 */
    OH_HUKS_TAG_KEY_DOMAIN = OH_HUKS_TAG_TYPE_UINT | 1011,

    /**
     * Reversed TAGs for SOTER: 11000 - 12000
     *
     * Other TAGs: 20001 - N
     * TAGs used for paramSetOut
     */
    /** 预留。 */
    OH_HUKS_TAG_SYMMETRIC_KEY_DATA = OH_HUKS_TAG_TYPE_BYTES | 20001,
    /** 预留。 */
    OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA = OH_HUKS_TAG_TYPE_BYTES | 20002,
    /** 预留。 */
    OH_HUKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA = OH_HUKS_TAG_TYPE_BYTES | 20003,
};

/**
 * @brief 表示状态返回数据，包括返回码和消息。
 * 
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result {
    /** 状态返回码。 */
    int32_t errorCode;
    /** 对状态返回码的说明信息。 */
    const char *errorMsg;
    /** 其他返回数据。 */
    uint8_t *data;
};

/**
 * @brief 定义存放数据的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Blob {
    /** 数据大小 */
    uint32_t size;
    /** 指向数据内存的指针 */
    uint8_t *data;
};

/**
 * @brief 定义参数集中的参数结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Param {
    /** 标签值 */
    uint32_t tag;
/**
 * @brief 定义参数联合体。
 *
 * @since 9
 * @version 1.0
 */
    union {
        /** bool型参数。 */
        bool boolParam;
        /** int32_t型参数。 */
        int32_t int32Param;
        /** uint32_t型参数。 */
        uint32_t uint32Param;
        /** uint64_t型参数。 */
        uint64_t uint64Param;
        /** struct OH_Huks_Blob型参数。 */
        struct OH_Huks_Blob blob;
    };
};

/**
 * @brief 定义参数集的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_ParamSet {
    /** 参数集的内存大小。 */
    uint32_t paramSetSize;
    /** 参数的个数。*/
    uint32_t paramsCnt;
    /** 参数数组。*/
    struct OH_Huks_Param params[];
};

/**
 * @brief 定义证书链的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_CertChain {
    /** 指向证书数据的指针。 */
    struct OH_Huks_Blob *certs;
    /** 证书本数。 */
    uint32_t certsCount;
};

/**
 * @brief 定义密钥信息的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyInfo {
    /** 密钥的别名。 */
    struct OH_Huks_Blob alias;
    /** 指向密钥参数集的指针。 */
    struct OH_Huks_ParamSet *paramSet;
};

/**
 * @brief 定义公钥信息的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_PubKeyInfo {
    /** 公钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** 公钥的长度。 */
    uint32_t keySize;
    /** n或X值的长度。 */
    uint32_t nOrXSize;
    /** e或Y值的长度。 */
    uint32_t eOrYSize;
    /** 占位符大小。 */
    uint32_t placeHolder;
};

/**
 * @brief 定义Rsa密钥的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyMaterialRsa {
    /** 密钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** 密钥的长度。 */
    uint32_t keySize;
    /** n值的长度。 */
    uint32_t nSize;
    /** e值的长度。 */
    uint32_t eSize;
    /** d值的长度。 */
    uint32_t dSize;
};

/**
 * @brief 定义Ecc密钥的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyMaterialEcc {
    /** 密钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** 密钥的长度。 */
    uint32_t keySize;
    /** x值的长度。 */
    uint32_t xSize;
    /** y值的长度。 */
    uint32_t ySize;
    /** z值的长度。 */
    uint32_t zSize;
};

/**
 * @brief 定义Dsa密钥的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyMaterialDsa {
    /** 密钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** 密钥的长度。 */
    uint32_t keySize;
    /** x值的长度。 */
    uint32_t xSize;
    /** y值的长度。 */
    uint32_t ySize;
    /** p值的长度。 */
    uint32_t pSize;
    /** q值的长度。 */
    uint32_t qSize;
    /** g值的长度。 */
    uint32_t gSize;
};

/**
 * @brief 定义Dh密钥的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyMaterialDh {
    /** 密钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** Dh密钥的长度。 */
    uint32_t keySize;
    /** 公钥的长度。 */
    uint32_t pubKeySize;
    /** 私钥的长度。 */
    uint32_t priKeySize;
    /** 保留。 */
    uint32_t reserved;
};

/**
 * @brief 定义25519类型密钥的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_KeyMaterial25519 {
    /** 密钥的算法类型。 */
    enum OH_Huks_KeyAlg keyAlg;
    /** 25519类型密钥的长度。 */
    uint32_t keySize;
    /** 公钥的长度。 */
    uint32_t pubKeySize;
    /** 私钥的长度。 */
    uint32_t priKeySize;
    /** 保留。 */
    uint32_t reserved;
};

#define OH_HUKS_DERIVE_DEFAULT_SALT_LEN 16
#define OH_HUKS_HMAC_DIGEST_SHA512_LEN 64
#define OH_HUKS_DEFAULT_RANDOM_LEN 16
#define OH_HUKS_MAX_KEY_AUTH_ID_LEN 64
#define OH_HUKS_KEY_MATERIAL_NUM 3
#define OH_HUKS_MAX_KEY_LEN ((((4096) + OH_HUKS_BITS_PER_BYTE - 1) / OH_HUKS_BITS_PER_BYTE) * OH_HUKS_KEY_MATERIAL_NUM)
#define OH_HUKS_MAX_KEY_MATERIAL_LEN (sizeof(struct OH_Huks_PubKeyInfo) + OH_HUKS_MAX_KEY_LEN + OH_HUKS_AE_TAG_LEN)

/**
 * @brief 定义存储区头部信息的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_StoreHeaderInfo {
    /** 版本号。 */
    uint16_t version;
    /** 存储的密钥数量。 */
    uint16_t keyCount;
    /** 存储的密钥总的内存大小。 */
    uint32_t totalLen;
    /** 存储的密封算法。 */
    uint32_t sealingAlg;
    /** 存储的盐值。 */
    uint8_t salt[OH_HUKS_DERIVE_DEFAULT_SALT_LEN];
    /** 存储的hmac摘要值。 */
    uint8_t hmac[OH_HUKS_HMAC_DIGEST_SHA512_LEN];
};

/**
 * @brief 定义存储密钥的信息的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_StoreKeyInfo {
    /** 当前密钥信息的内存大小。 */
    uint16_t keyInfoLen;
    /** 加密后的密钥长度。 */
    uint16_t keySize;
    /** 密钥的随机值。 */
    uint8_t random[OH_HUKS_DEFAULT_RANDOM_LEN];
    /** 标记是导入的密钥还是业务生成的密钥。 */
    uint8_t flag;        /* import or generate key */
    /** 密钥算法类型。 */
    uint8_t keyAlg;
    /** 密钥工作模式。 */
    uint8_t keyMode;
    /** 摘要算法。 */
    uint8_t digest;
    /** 数据填充方式。 */
    uint8_t padding;
    /** 保留。 */
    uint8_t rsv;
    /** 密钥长度，该值来源于输入参数集。 */
    uint16_t keyLen;
    /** 用途。 */
    uint32_t purpose;
    /** 作用。*/
    uint32_t role;
    /** 领域值。 */
    uint16_t domain;
    /** 密钥别名数据的长度。 */
    uint8_t aliasSize;
    /** 认证id的数据长度。 */
    uint8_t authIdSize;
};

/**
 * @brief 定义25519类型算法协商密钥对的结构体类型。
 *
 * @since 9
 * @version 1.0
 */
struct OH_Huks_25519KeyPair {
    /** 公钥占用内存的大小 */
    uint32_t publicBufferSize;
    /** 私钥占用内存的大小 */
    uint32_t privateBufferSize;
};

#ifdef __cplusplus
}
#endif

#endif /* NATIVE_OH_HUKS_TYPE_H */
