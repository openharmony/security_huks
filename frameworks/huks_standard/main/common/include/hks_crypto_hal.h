/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_CRYPTO_HAL_H
#define HKS_CRYPTO_HAL_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HksKeyAlgMode {
    HKS_ALGORITHM_RSA_MODE_CRT = 1,
    HKS_ALGORITHM_RSA_MODE_NO_CRT = 2,
    HKS_ALGORITHM_EC_MODE_ECDH = 3,
    HKS_ALGORITHM_ED_MODE_SIG_VERIFY = 4,
    HKS_ALGORITHM_ED_MODE_VERIFY = 5,
    HKS_ALGORITHM_X25519_MODE = 6,
};

enum {
    OPENSSL_CTX_PADDING_NONE = 0, /* set chipher padding none */
    OPENSSL_CTX_PADDING_ENABLE = 1, /* set chipher padding enable */
};

struct HksKeySpec {
    uint32_t algType;
    uint32_t keyLen;
    void *algParam; /* for example : struct HksKeyDerivationParam */
};

struct HksKeyDerivationParam {
    struct HksBlob salt;
    struct HksBlob info;
    uint32_t iterations;
    uint32_t digestAlg;
};

struct HksAeadParam {
    struct HksBlob nonce;
    struct HksBlob aad;
    union {
        struct HksBlob tagDec;
        uint32_t tagLenEnc;
    };
    uint32_t payloadLen;
};

struct HksCipherParam {
    struct HksBlob iv;
};

struct HksUsageSpec {
    uint32_t algType;
    uint32_t mode;
    uint32_t padding;
    uint32_t mgfDigest;
    uint32_t digest;
    uint32_t purpose;
    uint32_t pssSaltLenType;
    /*
     * Different algorithms correspond to different structures,for example:
     * struct HksAeadParam for aead;
     * struct HksCipherParam for cipher;
     */
    void *algParam;
};

struct KeyMaterialRsa {
    enum HksKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t nSize;
    uint32_t eSize;
    uint32_t dSize;
};
#define RSA_KEY_MATERIAL_CNT 3U

struct KeyMaterialEcc {
    enum HksKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t xSize;
    uint32_t ySize;
    uint32_t zSize;
};
#define ECC_KEY_MATERIAL_CNT 3U

struct KeyMaterialDsa {
    enum HksKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t xSize;
    uint32_t ySize;
    uint32_t pSize;
    uint32_t qSize;
    uint32_t gSize;
};

struct KeyMaterialDh {
    enum HksKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t pubKeySize;
    uint32_t priKeySize;
    uint32_t reserved;
};

struct KeyMaterial25519 {
    enum HksKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t pubKeySize;
    uint32_t priKeySize;
    uint32_t reserved;
};

typedef int32_t (*GetMainKey)(const struct HksBlob *, struct HksBlob *);

typedef int32_t (*GenerateKey)(const struct HksKeySpec *, struct HksBlob *);

typedef int32_t (*PubKey)(const struct HksBlob *, struct HksBlob *);

typedef int32_t (*DeriveKey)(const struct HksBlob *, const struct HksKeySpec *, struct HksBlob *);

typedef int32_t (*FillRandom)(struct HksBlob *);

typedef int32_t (*AgreeKey)(const struct HksBlob *, const struct HksBlob *, const struct HksKeySpec *,
    struct HksBlob *);

typedef int32_t (*Sign)(const struct HksBlob *, const struct HksUsageSpec *, const struct HksBlob *,
    struct HksBlob *);

typedef int32_t (*Verify)(const struct HksBlob *, const struct HksUsageSpec *, const struct HksBlob *,
    const struct HksBlob *);

typedef int32_t (*Hmac)(const struct HksBlob *, uint32_t, const struct HksBlob *, struct HksBlob *);

typedef int32_t (*HmacInit)(void **, const struct HksBlob *, uint32_t);

typedef int32_t (*HmacUpdate)(void *, const struct HksBlob *);

typedef int32_t (*HmacFinal)(void **, const struct HksBlob *, struct HksBlob *);

typedef int32_t (*CmacInit)(void **, const struct HksBlob *, const struct HksUsageSpec *);

typedef int32_t (*CmacUpdate)(void *, const struct HksBlob *, const struct HksUsageSpec *);

typedef int32_t (*CmacFinal)(void **, const struct HksBlob *, struct HksBlob *, const struct HksUsageSpec *);

typedef int32_t (*Hash)(uint32_t, const struct HksBlob *, struct HksBlob *);

typedef int32_t (*HashInit)(void **, uint32_t);

typedef int32_t (*HashUpdate)(void *, const struct HksBlob *);

typedef int32_t (*HashFinal)(void **, const struct HksBlob *, struct HksBlob *);

typedef int32_t (*Encrypt)(const struct HksBlob *, const struct HksUsageSpec *,
    const struct HksBlob *, struct HksBlob *, struct HksBlob *);

typedef int32_t (*EncryptInit)(void **, const struct HksBlob *, const struct HksUsageSpec *, const bool);

typedef int32_t (*EncryptUpdate)(void *, const struct HksBlob *, struct HksBlob *, const bool);

typedef int32_t (*EncryptFinal)(void **, const struct HksBlob *, struct HksBlob *, struct HksBlob *, const bool);

typedef int32_t (*Decrypt)(const struct HksBlob *, const struct HksUsageSpec *,
    const struct HksBlob *, struct HksBlob *);

typedef int32_t (*DecryptInit)(void **, const struct HksBlob *, const struct HksUsageSpec *, const bool);

typedef int32_t (*DecryptUpdate)(void *, const struct HksBlob *, struct HksBlob *, const bool);

typedef int32_t (*DecryptFinal)(void **, const struct HksBlob *, struct HksBlob *, struct HksBlob *, const bool);

typedef int32_t (*DecryptFinalDes)(void **, const struct HksBlob *, struct HksBlob *, const bool);

typedef int32_t (*BnExpMod)(struct HksBlob *, const struct HksBlob *,
    const struct HksBlob *, const struct HksBlob *);

typedef void (*FreeCtx)(void **);

int32_t HksCryptoHalGetMainKey(const struct HksBlob *message, struct HksBlob *mainKey);

int32_t HksCryptoHalGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key);

int32_t HksCryptoHalGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut);

int32_t HksCryptoHalDeriveKey(const struct HksBlob *mainKey, const struct HksKeySpec *derivationSpec,
    struct HksBlob *derivedKey);

int32_t HksCryptoHalFillRandom(struct HksBlob *randomData);

int32_t HksCryptoHalFillPrivRandom(struct HksBlob *randomData);

int32_t HksCryptoHalAddEntropy(const struct HksBlob *entropy);

int32_t HksCryptoHalAgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey);

int32_t HksCryptoHalSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature);

int32_t HksCryptoHalVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature);

int32_t HksCryptoHalSignIsoIec97962(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature);

int32_t HksCryptoHalVerifyIsoIec97962(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature);

int32_t HksCryptoHalHmacInit(const struct HksBlob *key, uint32_t digestAlg, void **ctx);

int32_t HksCryptoHalHmacUpdate(const struct HksBlob *chunk, void *ctx);

int32_t HksCryptoHalHmacFinal(const struct HksBlob *msg, void **ctx, struct HksBlob *mac);

void HksCryptoHalHmacFreeCtx(void **ctx);

int32_t HksCryptoHalHmac(const struct HksBlob *key, uint32_t digestAlg, const struct HksBlob *msg,
    struct HksBlob *mac);

int32_t HksCryptoHalCmacInit(const struct HksBlob *key, void **ctx, const struct HksUsageSpec *usageSpec);

int32_t HksCryptoHalCmacUpdate(const struct HksBlob *chunk, void *ctx, const struct HksUsageSpec *usageSpec);

int32_t HksCryptoHalCmacFinal(
    const struct HksBlob *msg, void **ctx, struct HksBlob *mac, const struct HksUsageSpec *usageSpec);

void HksCryptoHalCmacFreeCtx(void **ctx);

int32_t HksCryptoHalHashInit(uint32_t alg, void **ctx);

int32_t HksCryptoHalHashUpdate(const struct HksBlob *msg, void *ctx);

int32_t HksCryptoHalHashFinal(const struct HksBlob *msg, void **ctx, struct HksBlob *hash);

void HksCryptoHalHashFreeCtx(void **ctx);

int32_t HksCryptoHalHash(uint32_t alg, const struct HksBlob *msg, struct HksBlob *hash);

int32_t HksCryptoHalEncryptInit(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, void **ctx);

int32_t HksCryptoHalEncryptUpdate(const struct HksBlob *message, void *ctx, struct HksBlob *out,
    const uint32_t algtype);

int32_t HksCryptoHalEncryptFinal(const struct HksBlob *message, void **ctx, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const uint32_t algtype);

void HksCryptoHalEncryptFreeCtx(void **ctx, const uint32_t algtype);

int32_t HksCryptoHalEncrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead);

int32_t HksCryptoHalDecryptInit(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, void **ctx);

int32_t HksCryptoHalDecryptUpdate(const struct HksBlob *message, void *ctx, struct HksBlob *out,
    const uint32_t algtype);

int32_t HksCryptoHalDecryptFinal(const struct HksBlob *message, void **ctx, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const uint32_t algtype);

void HksCryptoHalDecryptFreeCtx(void **ctx, const uint32_t algtype);

int32_t HksCryptoHalDecrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText);

int32_t HksCryptoHalBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n);

int32_t HksCryptoHalInit(void);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CRYPTO_HAL_H */
