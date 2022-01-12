/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_openssl_engine.h"

#include <openssl/err.h>

#include "hks_ability.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"

#include "hks_type_inner.h"

void HksLogOpensslError(void)
{
    char szErr[HKS_OPENSSL_ERROR_LEN] = {0};
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, HKS_OPENSSL_ERROR_LEN);

    HKS_LOG_E("Openssl engine fail, error code = %lu, error string = %s", errCode, szErr);
}

inline int32_t HksOpensslCheckBlob(const struct HksBlob *blob)
{
    if ((blob == NULL) || (blob->data == NULL) || (blob->size == 0)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t GenKeyCheckParam(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if ((spec == NULL) || (key == NULL)) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t SignVerifyCheckParam(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    if (HksOpensslCheckBlob(key) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param key!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(message) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param message!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(signature) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param signature!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (usageSpec == NULL) {
        HKS_LOG_E("Invalid param usageSpec!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t DeriveKeyCheckParam(
    const struct HksBlob *mainKey, const struct HksKeySpec *derivationSpec, struct HksBlob *derivedKey)
{
    if (HksOpensslCheckBlob(mainKey) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid mainKey params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((derivationSpec == NULL) || (derivationSpec->algParam == NULL)) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (derivedKey == NULL) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t AgreeKeyCheckParam(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    if (HksOpensslCheckBlob(nativeKey) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid nativeKey params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(pubKey) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid pubKey params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (spec == NULL) {
        HKS_LOG_E("Invalid spec params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (sharedKey == NULL) {
        HKS_LOG_E("Invalid sharedKey params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t EncryptCheckParam(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    if (HksOpensslCheckBlob(key) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param key!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(message) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param message!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(cipherText) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param cipherText!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (usageSpec == NULL) {
        HKS_LOG_E("Invalid param usageSpec!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t DecryptCheckParam(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    return EncryptCheckParam(key, usageSpec, message, cipherText);
}

const EVP_MD *GetOpensslAlg(uint32_t alg)
{
    switch (alg) {
        case HKS_DIGEST_MD5:
            return EVP_md5();
        case HKS_DIGEST_SHA1:
            return EVP_sha1();
        case HKS_DIGEST_SHA224:
            return EVP_sha224();
        case HKS_DIGEST_SHA256:
            return EVP_sha256();
        case HKS_DIGEST_SHA384:
            return EVP_sha384();
        case HKS_DIGEST_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

int32_t HksCryptoHalFillRandom(struct HksBlob *randomData)
{
    if (HksOpensslCheckBlob(randomData) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    FillRandom func = (FillRandom)GetAbility(HKS_CRYPTO_ABILITY_FILL_RANDOM);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(randomData);
}

int32_t HksCryptoHalGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    /* KeyMaterialRsa, KeyMaterialEcc, KeyMaterial25519's size are same */
    if (keyIn->size < sizeof(struct KeyMaterialRsa)) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    struct KeyMaterialRsa *key = (struct KeyMaterialRsa *)(keyIn->data);
    PubKey func = (PubKey)GetAbility(HKS_CRYPTO_ABILITY_GET_PUBLIC_KEY(key->keyAlg));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(keyIn, keyOut);
}

int32_t HksCryptoHalGetMainKey(const struct HksBlob *message, struct HksBlob *mainKey)
{
    (void)message;
    return 0;
}

int32_t HksCryptoHalHmac(const struct HksBlob *key, uint32_t digestAlg, const struct HksBlob *msg, struct HksBlob *mac)
{
    Hmac func = (Hmac)GetAbility(HKS_CRYPTO_ABILITY_HMAC);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, digestAlg, msg, mac);
}

int32_t HksCryptoHalHash(uint32_t alg, const struct HksBlob *msg, struct HksBlob *hash)
{
    Hash func = (Hash)GetAbility(HKS_CRYPTO_ABILITY_HASH);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(alg, msg, hash);
}

int32_t HksCryptoHalBnExpMod(
    struct HksBlob *x, const struct HksBlob *a, const struct HksBlob *e, const struct HksBlob *n)
{
    BnExpMod func = (BnExpMod)GetAbility(HKS_CRYPTO_ABILITY_BN_EXP_MOD);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(x, a, e, n);
}

int32_t HksCryptoHalGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    int32_t ret = GenKeyCheckParam(spec, key);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_LOG_I("generate key type %x", spec->algType);
    GenerateKey func = (GenerateKey)GetAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(spec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(spec, key);
}

int32_t HksCryptoHalAgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    int32_t ret = AgreeKeyCheckParam(nativeKey, pubKey, spec, sharedKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    AgreeKey func = (AgreeKey)GetAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(spec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(nativeKey, pubKey, spec, sharedKey);
}

int32_t HksCryptoHalSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const struct HksBlob *message,
    struct HksBlob *signature)
{
    int32_t ret = SignVerifyCheckParam(key, usageSpec, message, signature);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    Sign func = (Sign)GetAbility(HKS_CRYPTO_ABILITY_SIGN(usageSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, usageSpec, message, signature);
}

int32_t HksCryptoHalVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    int32_t ret = SignVerifyCheckParam(key, usageSpec, message, signature);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    Verify func = (Verify)GetAbility(HKS_CRYPTO_ABILITY_VERIFY(usageSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, usageSpec, message, signature);
}

int32_t HksCryptoHalDeriveKey(
    const struct HksBlob *masterKey, const struct HksKeySpec *derivationSpec, struct HksBlob *derivedKey)
{
    int32_t ret = DeriveKeyCheckParam(masterKey, derivationSpec, derivedKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    DeriveKey func = (DeriveKey)GetAbility(HKS_CRYPTO_ABILITY_DERIVE_KEY(derivationSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(masterKey, derivationSpec, derivedKey);
}

int32_t HksCryptoHalEncrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    int32_t ret = EncryptCheckParam(key, usageSpec, message, cipherText);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    Encrypt func = (Encrypt)GetAbility(HKS_CRYPTO_ABILITY_ENCRYPT(usageSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, usageSpec, message, cipherText, tagAead);
}

int32_t HksCryptoHalDecrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    int32_t ret = DecryptCheckParam(key, usageSpec, message, cipherText);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Invalid params!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    Decrypt func = (Decrypt)GetAbility(HKS_CRYPTO_ABILITY_DECRYPT(usageSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, usageSpec, message, cipherText);
}
