/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "openssl_rsa_helper.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <securec.h>

#include "hks_openssl_engine.h"
#include "hks_crypto_hal.h"
#include "hks_mem.h"
#include "hks_log.h"

int32_t SaveRsaKeyToHksBlob(EVP_PKEY *pkey, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / BIT_NUM_OF_UINT8;

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)key->data;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;
    keyMaterial->nSize = keyByteLen;
    keyMaterial->eSize = keyByteLen;
    keyMaterial->dSize = keyByteLen;

    uint8_t tmpBuff[keyByteLen];
    (void)memset_s(tmpBuff, keyByteLen, 0, keyByteLen);

    uint32_t offset = sizeof(*keyMaterial);
    if (BN_bn2binpad(RSA_get0_n(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        if (memcpy_s(key->data + offset, keyMaterial->nSize, tmpBuff, keyMaterial->nSize) != 0) {
            return RSA_FAILED;
        }
    }

    offset += keyMaterial->nSize;
    if (BN_bn2binpad(RSA_get0_e(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        if (memcpy_s(key->data + offset, keyMaterial->eSize, tmpBuff, keyMaterial->eSize) != 0) {
            return RSA_FAILED;
        }
    }

    offset += keyMaterial->eSize;
    if (BN_bn2binpad(RSA_get0_d(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        if (memcpy_s(key->data + offset, keyMaterial->dSize, tmpBuff, keyMaterial->dSize) != 0) {
            return RSA_FAILED;
        }
    }
    key->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;
    return RSA_SUCCESS;
}

EVP_PKEY *GenerateRsaKey(const uint32_t keySize)
{
    BIGNUM *bne = BN_new();
    if (bne == NULL) {
        return NULL;
    }
    BN_set_word(bne, RSA_F4);

    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        BN_free(bne);
        return NULL;
    }

    if (RSA_generate_key_ex(rsa, keySize, bne, NULL) != 1) {
        RSA_free(rsa);
        BN_free(bne);
        return NULL;
    }
    BN_free(bne);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }

    return pkey;
}

bool OpensslGetx509PubKey(EVP_PKEY *pkey, struct HksBlob *x509Key)
{
    uint8_t *tmp = NULL;
    int ret = i2d_PUBKEY(pkey, &tmp);
    uint32_t length = (uint32_t)(ret);
    if (ret <= 0 || x509Key->size < length) {
        OPENSSL_free(tmp);
        return false;
    }
    x509Key->size = length;
    if (tmp != NULL) {
        if (memcpy_s(x509Key->data, x509Key->size, tmp, length) != EOK) {
            OPENSSL_free(tmp);
            return false;
        }
        OPENSSL_free(tmp);
    } else {
        return false;
    }
    return true;
}

int32_t X509ToRsaPublicKey(struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    uint8_t *data = x509Key->data;

    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&data, x509Key->size);
    if (pkey == NULL) {
        return RSA_FAILED;
    }
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    int32_t nSizeTemp = BN_num_bytes(RSA_get0_n(rsa));
    int32_t eSizeTemp = BN_num_bytes(RSA_get0_e(rsa));
    if ((nSizeTemp <= 0) || (eSizeTemp <= 0)) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    uint32_t nSize = (uint32_t)nSizeTemp;
    uint32_t eSize = (uint32_t)eSizeTemp;

    struct HksPubKeyInfo *pubKeyInfo = (struct HksPubKeyInfo *)publicKey->data;
    pubKeyInfo->keyAlg = HKS_ALG_RSA;
    pubKeyInfo->keySize = (uint32_t)RSA_size(rsa) * BIT_NUM_OF_UINT8;
    pubKeyInfo->nOrXSize = nSize;
    pubKeyInfo->eOrYSize = eSize;
    if ((BN_bn2bin(RSA_get0_n(rsa), publicKey->data + sizeof(struct HksPubKeyInfo)) == 0) ||
        (BN_bn2bin(RSA_get0_e(rsa), publicKey->data + sizeof(struct HksPubKeyInfo) + nSize) == 0)) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    EVP_PKEY_free(pkey);
    return RSA_SUCCESS;
}

static RSA *InitRsa(struct HksBlob *key, const bool needPrivateExponent)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    uint8_t *buff = (uint8_t *)HksMalloc(HKS_KEY_BYTES(keyMaterial->keySize));
    if (buff == NULL) {
        return NULL;
    }

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    uint32_t offset = sizeof(*keyMaterial);
    if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->nSize) == 0) {
        n = BN_bin2bn(buff, keyMaterial->nSize, NULL);
    }
    offset += keyMaterial->nSize;

    if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->eSize) == 0) {
        e = BN_bin2bn(buff, keyMaterial->eSize, NULL);
    }
    offset += keyMaterial->eSize;

    if (needPrivateExponent) {
        if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->dSize) == 0) {
            d = BN_bin2bn(buff, keyMaterial->dSize, NULL);
        }
    }

    RSA *rsa = RSA_new();
    if (rsa != NULL) {
        if (RSA_set0_key(rsa, n, e, d) != 1) {
            RSA_free(rsa);
            rsa = NULL;
        }
    }

    if (rsa == NULL) {
        if (n != NULL) {
            BN_free(n);
        }
        if (e != NULL) {
            BN_free(e);
        }
        if (d != NULL) {
            BN_free(d);
        }
    }
    HKS_FREE(buff);

    return rsa;
}

static const EVP_MD *GetOpensslDigestType(enum HksKeyDigest digestType)
{
    switch (digestType) {
        case HKS_DIGEST_MD5:
            return EVP_md5();
        case HKS_DIGEST_SHA1:
            return EVP_sha1();
        case HKS_DIGEST_SHA224:
            return EVP_sha224();
        case HKS_DIGEST_SHA384:
            return EVP_sha384();
        case HKS_DIGEST_SHA256:
            return EVP_sha256();
        case HKS_DIGEST_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

int32_t EncryptRsa(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, false);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return RSA_FAILED;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return RSA_FAILED;
    }
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    if ((EVP_PKEY_encrypt_init(ectx) != 1) || (EVP_PKEY_CTX_set_rsa_padding(ectx, padding) != 1)) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        const EVP_MD *md = GetOpensslDigestType(digestType);
        if ((md == NULL) || (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, md) != 1) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, md) != 1)) {
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }
    size_t outLen = outData->size;
    if (EVP_PKEY_encrypt(ectx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    outData->size = outLen;
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);
    return RSA_SUCCESS;
}

int32_t DecryptRsa(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, true);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return RSA_FAILED;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return RSA_FAILED;
    }
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    if ((EVP_PKEY_decrypt_init(ectx) != 1) || (EVP_PKEY_CTX_set_rsa_padding(ectx, padding) != 1)) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        const EVP_MD *md = GetOpensslDigestType(digestType);
        if ((md == NULL) || (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, md) != 1) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, md) != 1)) {
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }
    size_t outLen = outData->size;
    if (EVP_PKEY_decrypt(ectx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    outData->size = outLen;

    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);

    return RSA_SUCCESS;
}

static EVP_PKEY_CTX *InitRsaCtx(struct HksBlob *key, int padding, bool signing, uint32_t len)
{
    const EVP_MD *opensslAlg = GetOpensslAlgFromLen(len);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        RSA *rsa = InitRsa(key, true);
        if (rsa == NULL) {
            break;
        }
        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            RSA_free(rsa);
            break;
        }
        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            RSA_free(rsa);
            break;
        }

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (ctx == NULL) {
            break;
        }

        if (signing) {
            ret = EVP_PKEY_sign_init(ctx);
        } else {
            ret = EVP_PKEY_verify_init(ctx);
        }
        if (ret != 1) {
            break;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) != 1) {
            break;
        }
        if (padding == RSA_PKCS1_PSS_PADDING && (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_MAX) != 1)) {
            break;
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, opensslAlg) != 1) {
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);
    EVP_PKEY_free(pkey);
    if (ret != HKS_SUCCESS) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ctx;
}

int32_t OpensslRsaSignWithNoneDegist(struct HksBlob *key, int padding, const struct HksBlob *message,
    struct HksBlob *signature)
{
    EVP_PKEY_CTX *ctx = InitRsaCtx(key, padding, true, message->size);
    if (ctx == NULL) {
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    size_t sigSize = (size_t)signature->size;
    if (EVP_PKEY_sign(ctx, signature->data, &sigSize, message->data, message->size) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = (uint32_t)sigSize;
    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t OpensslRsaVerifyWithNoneDegist(struct HksBlob *key, int padding, const struct HksBlob *message,
    struct HksBlob *signature)
{
    EVP_PKEY_CTX *ctx = InitRsaCtx(key, padding, false, message->size);
    if (ctx == NULL) {
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (EVP_PKEY_verify(ctx, signature->data, signature->size, message->data, message->size) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t OpensslSignRsa(const struct HksBlob *plainText, struct HksBlob *signData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, true);
    if (rsa == NULL) {
        return RSA_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return RSA_FAILED;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return RSA_FAILED;
    }

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    const EVP_MD *md = GetOpensslDigestType(digestType);
    if (EVP_DigestSignInit(mctx, NULL, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    if (padding == RSA_PKCS1_PSS_PADDING) {
        if ((EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mctx), padding) != 1) ||
            (EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(mctx), RSA_PSS_SALTLEN_MAX) != 1)) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }

    if (EVP_DigestSignUpdate(mctx, plainText->data, plainText->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    size_t signLen = signData->size;
    if (EVP_DigestSignFinal(mctx, signData->data, &signLen) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    signData->size = signLen;

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    return RSA_SUCCESS;
}

int32_t OpensslVerifyRsa(const struct HksBlob *plainText, struct HksBlob *signData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, false);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return RSA_FAILED;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return RSA_FAILED;
    }
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    const EVP_MD *md = GetOpensslDigestType(digestType);
    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    if (padding == RSA_PKCS1_PSS_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mctx), padding) != 1) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
            return RSA_FAILED;
        }
    }

    if (EVP_DigestVerifyUpdate(mctx, plainText->data, plainText->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }
    if (EVP_DigestVerifyFinal(mctx, signData->data, signData->size) != 1) {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    return RSA_SUCCESS;
}