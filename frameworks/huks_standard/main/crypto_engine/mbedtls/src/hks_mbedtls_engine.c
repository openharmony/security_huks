/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#include "hks_mbedtls_engine.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_ability.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"

static int32_t EncryptCheckParam(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    if (CheckBlob(key) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param key!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (CheckBlob(message) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param message!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (CheckBlob(cipherText) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param cipherText!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (usageSpec == NULL) {
        HKS_LOG_E("Invalid param usageSpec!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCryptoHalHmac(const struct HksBlob *key, uint32_t digestAlg, const struct HksBlob *msg,
    struct HksBlob *mac)
{
    if (CheckBlob(key) != HKS_SUCCESS || CheckBlob(msg) != HKS_SUCCESS || CheckBlob(mac) != HKS_SUCCESS) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    Hmac func = (Hmac)GetAbility(HKS_CRYPTO_ABILITY_HMAC);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, digestAlg, msg, mac);
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCryptoHalHash(uint32_t alg, const struct HksBlob *msg, struct HksBlob *hash)
{
    Hash func = (Hash)GetAbility(HKS_CRYPTO_ABILITY_HASH);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(alg, msg, hash);
}
#endif /* _CUT_AUTHENTICATE_ */

int32_t HksCryptoHalBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n)
{
    BnExpMod func = (BnExpMod)GetAbility(HKS_CRYPTO_ABILITY_BN_EXP_MOD);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(x, a, e, n);
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCryptoHalGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if (spec == NULL || key == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    GenerateKey func = (GenerateKey)GetAbility(HKS_CRYPTO_ABILITY_GENERATE_KEY(spec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(spec, key);
}

int32_t HksCryptoHalGetMainKey(const struct HksBlob *message, struct HksBlob *mainKey)
{
    GetMainKey func = (GetMainKey)GetAbility(HKS_CRYPTO_ABILITY_GET_MAIN_KEY);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(message, mainKey);
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
#endif /* _CUT_AUTHENTICATE_ */

int32_t HksCryptoHalDeriveKey(const struct HksBlob *mainKey,
    const struct HksKeySpec *derivationSpec, struct HksBlob *derivedKey)
{
    DeriveKey func = (DeriveKey)GetAbility(HKS_CRYPTO_ABILITY_DERIVE_KEY(derivationSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(mainKey, derivationSpec, derivedKey);
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCryptoHalAgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    if (CheckBlob(nativeKey) != HKS_SUCCESS || CheckBlob(pubKey) != HKS_SUCCESS || spec == NULL ||
        CheckBlob(sharedKey) != HKS_SUCCESS) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    AgreeKey func = (AgreeKey)GetAbility(HKS_CRYPTO_ABILITY_AGREE_KEY(spec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(nativeKey, pubKey, spec, sharedKey);
}

int32_t HksCryptoHalSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    if (CheckBlob(key) != HKS_SUCCESS || usageSpec == NULL || CheckBlob(message) != HKS_SUCCESS ||
        CheckBlob(signature) != HKS_SUCCESS) {
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
    if (CheckBlob(key) != HKS_SUCCESS || usageSpec == NULL || CheckBlob(message) != HKS_SUCCESS ||
        CheckBlob(signature) != HKS_SUCCESS) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    Verify func = (Verify)GetAbility(HKS_CRYPTO_ABILITY_VERIFY(usageSpec->algType));
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(key, usageSpec, message, signature);
}
#endif /* _CUT_AUTHENTICATE_ */

int32_t HksCryptoHalFillRandom(struct HksBlob *randomData)
{
    FillRandom func = (FillRandom)GetAbility(HKS_CRYPTO_ABILITY_FILL_RANDOM);
    if (func == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return func(randomData);
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
    int32_t ret = EncryptCheckParam(key, usageSpec, message, cipherText);
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
