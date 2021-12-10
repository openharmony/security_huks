/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "hks_crypto_hal.h"

void SaveRsaKeyToHksBlob(EVP_PKEY *pkey, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / BIT_NUM_OF_UINT8;

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)key->data;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;
    keyMaterial->nSize = keyByteLen;
    keyMaterial->eSize = keyByteLen;
    keyMaterial->dSize = keyByteLen;

    uint8_t tmpBuff[keyByteLen];
    memset_s(tmpBuff, keyByteLen, 0x00, keyByteLen);

    uint32_t offset = sizeof(*keyMaterial);
    if (BN_bn2binpad(RSA_get0_n(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        (void)memcpy_s(key->data + offset, keyMaterial->nSize, tmpBuff, keyMaterial->nSize);
    }

    offset += keyMaterial->nSize;
    if (BN_bn2binpad(RSA_get0_e(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        (void)memcpy_s(key->data + offset, keyMaterial->eSize, tmpBuff, keyMaterial->eSize);
    }

    offset += keyMaterial->eSize;
    if (BN_bn2binpad(RSA_get0_d(EVP_PKEY_get0_RSA(pkey)), tmpBuff, keyByteLen) > 0) {
        (void)memcpy_s(key->data + offset, keyMaterial->dSize, tmpBuff, keyMaterial->dSize);
    }
    key->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;
}

EVP_PKEY *GenerateRSAKey(const uint32_t keySize)
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
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }

    return pkey;
}

void OpensslGetx509PubKey(EVP_PKEY *pkey, struct HksBlob *x509Key)
{
    uint8_t *tmp = NULL;
    int32_t length = i2d_PUBKEY(pkey, &tmp);
    x509Key->size = length;
    if (tmp != NULL) {
        (void)memcpy_s(x509Key->data, x509Key->size, tmp, length);
        free(tmp);
    }
}

int32_t X509ToRsaPublicKey(struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    uint8_t *data = x509Key->data;

    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&data, x509Key->size);
    if (pkey == NULL) {
        return RSA_FAILED;
    }
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    int32_t nSize = BN_num_bytes(RSA_get0_n(rsa));
    int32_t eSize = BN_num_bytes(RSA_get0_e(rsa));
    if ((nSize <= 0) || (eSize <= 0)) {
        EVP_PKEY_free(pkey);
        return RSA_FAILED;
    }

    struct HksPubKeyInfo *pubKeyInfo = (struct HksPubKeyInfo *)publicKey->data;
    pubKeyInfo->keyAlg = HKS_ALG_RSA;
    pubKeyInfo->keySize = RSA_size(rsa) * BIT_NUM_OF_UINT8;
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
    uint8_t buff[HKS_KEY_BYTES(keyMaterial->keySize)];

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    uint32_t offset = sizeof(*keyMaterial);
    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->nSize) == 0) {
        n = BN_bin2bn(buff, keyMaterial->nSize, NULL);
    }
    offset += keyMaterial->nSize;

    if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->eSize) == 0) {
        e = BN_bin2bn(buff, keyMaterial->eSize, NULL);
    }
    offset += keyMaterial->eSize;

    if (needPrivateExponent) {
        if (memcpy_s(buff, sizeof(buff), key->data + offset, keyMaterial->dSize) == 0) {
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

int32_t EncryptRSA(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
    enum HksKeyDigest digestType)
{
    RSA *rsa = InitRsa(key, false);
    if (rsa == NULL) {
        return RSA_FAILED;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
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

int32_t DecryptRSA(const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding,
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
        if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mctx), padding) != 1) {
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