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

#include "hks_openssl_curve25519.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdbool.h>
#include <stddef.h>

#include "hks_crypto_adapter.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_ed25519tox25519.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

static int32_t SaveCurve25519KeyMaterial(uint32_t algType, const EVP_PKEY *pKey, struct HksBlob *keyOut)
{
    uint32_t totalSize = sizeof(struct KeyMaterial25519) + (CURVE25519_KEY_LEN << 1);
    uint8_t *buffer = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(buffer, HKS_ERROR_MALLOC_FAIL, "malloc size %" LOG_PUBLIC "u failed", totalSize)

    size_t tmpPubKeyLen = CURVE25519_KEY_LEN;
    size_t tmpPriKeyLen = CURVE25519_KEY_LEN;
    uint32_t offset = sizeof(struct KeyMaterial25519);

    if (EVP_PKEY_get_raw_public_key(pKey, buffer + offset, &tmpPubKeyLen) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        HKS_FREE(buffer);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    uint32_t pubKeyLen = (uint32_t)tmpPubKeyLen;

    offset += pubKeyLen;
    if (EVP_PKEY_get_raw_private_key(pKey, buffer + offset, &tmpPriKeyLen) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        HKS_FREE(buffer);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    uint32_t priKeyLen = (uint32_t)tmpPriKeyLen;

    struct KeyMaterial25519 *keyMaterial = (struct KeyMaterial25519 *)buffer;
    keyMaterial->keyAlg = algType;
    keyMaterial->keySize = CURVE25519_KEY_BITS;
    keyMaterial->pubKeySize = pubKeyLen;
    keyMaterial->priKeySize = priKeyLen;

    keyOut->data = buffer;
    keyOut->size = totalSize;
    return HKS_SUCCESS;
}

static int GetCurve25519Id(uint32_t algType)
{
    if (algType == HKS_ALG_X25519) {
        return EVP_PKEY_X25519;
    }
    return EVP_PKEY_ED25519;
}

int32_t HksOpensslCurve25519GenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    int32_t ret;
    do {
        if ((pctx = EVP_PKEY_CTX_new_id(GetCurve25519Id(spec->algType), NULL)) == NULL) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        if (EVP_PKEY_keygen_init(pctx) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        if (EVP_PKEY_keygen(pctx, &pkey) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        ret = SaveCurve25519KeyMaterial(spec->algType, pkey, key);
        HKS_IF_NOT_SUCC_LOGE(ret, "save curve25519 key material failed")
    } while (0);

    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

static int32_t ImportX25519EvpKey(EVP_PKEY **ours, EVP_PKEY **theirs, const struct HksBlob *nativeKey,
    const struct HksBlob *pubKey)
{
    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)nativeKey->data;
    uint32_t offset = sizeof(struct KeyMaterial25519) + km->pubKeySize;

    *ours = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, nativeKey->data + offset, km->priKeySize);
    if (*ours == NULL) {
        HKS_LOG_E("invalid private key");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct KeyMaterial25519 *kmPub = (struct KeyMaterial25519 *)pubKey->data;
    offset = sizeof(struct KeyMaterial25519);

    *theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubKey->data + offset, kmPub->pubKeySize);
    if (*theirs == NULL) {
        HKS_LOG_E("invalid public key");
        HksLogOpensslError();
        EVP_PKEY_free(*ours);
        *ours = NULL;
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return HKS_SUCCESS;
}

int32_t HksOpensslX25519AgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    (void)spec;
    EVP_PKEY *ours = NULL;
    EVP_PKEY *theirs = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t tmpSharedKeySize = (size_t)sharedKey->size;

    int32_t ret = ImportX25519EvpKey(&ours, &theirs, nativeKey, pubKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "import x25519 evp key failed")
    do {
        ctx = EVP_PKEY_CTX_new(ours, NULL);
        if (ctx == NULL) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        if (EVP_PKEY_derive_init(ctx) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        if (EVP_PKEY_derive_set_peer(ctx, theirs) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        if (EVP_PKEY_derive(ctx, sharedKey->data, &tmpSharedKeySize) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
        sharedKey->size = (uint32_t)tmpSharedKeySize;
    } while (0);
    EVP_PKEY_free(theirs);
    EVP_PKEY_free(ours);
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

int32_t HksOpensslEd25519AgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    struct HksBlob ed25519PubKey = { 0 };
    uint32_t materialKeySize = sizeof(struct KeyMaterial25519) + CURVE25519_KEY_LEN;
    struct HksBlob x25519PriKeyMaterial = { materialKeySize, (uint8_t *)HksMalloc(materialKeySize) };
    struct HksBlob x25519PubKeyMaterial = { materialKeySize, (uint8_t *)HksMalloc(materialKeySize) };

    int32_t ret;
    do {
        if (x25519PriKeyMaterial.data == NULL || x25519PubKeyMaterial.data == NULL) {
            HKS_LOG_E("malloc for x22519 key pair failed");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        // get x25519 private key material
        ret = ConvertPrivX25519FromED25519(nativeKey, &x25519PriKeyMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "convert ED25519 private key to x25519 failed")

        // get x25519 public key material
        ret = HksGetKeyFromMaterial(HKS_ALG_ED25519, true, pubKey, &ed25519PubKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get public key from keymaterial failed")
        ret = ConvertPubkeyX25519FromED25519(&ed25519PubKey, &x25519PubKeyMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "convert ED25519 public key to x25519 failed")

        // x25519 key agreement
        ret = HksOpensslX25519AgreeKey(&x25519PriKeyMaterial, &x25519PubKeyMaterial, spec, sharedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "x25519 agree key failed")
    } while (0);

    HKS_MEMSET_FREE_BLOB(ed25519PubKey);
    HKS_MEMSET_FREE_BLOB(x25519PriKeyMaterial);
    HKS_MEMSET_FREE_BLOB(x25519PubKeyMaterial);
    return ret;
}

int32_t HksOpensslEd25519Sign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    (void)usageSpec;
    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    uint32_t offset = sizeof(struct KeyMaterial25519) + km->pubKeySize;
    EVP_PKEY *edKeyPri = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
        key->data + offset, km->priKeySize);

    if (edKeyPri == NULL) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        HksLogOpensslError();
        EVP_PKEY_free(edKeyPri);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, edKeyPri) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            break;
        }

        size_t req = 0;
        if (EVP_DigestSign(mdctx, NULL, &req, NULL, 0) <= 0) {
            HksLogOpensslError();
            break;
        }

        if (EVP_DigestSign(mdctx, signature->data, &req, message->data, message->size) <= 0) {
            HksLogOpensslError();
            break;
        }

        signature->size = req;
        ret = HKS_SUCCESS;
    } while (0);

    EVP_PKEY_free(edKeyPri);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int32_t HksOpensslEd25519Verify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    (void)usageSpec;
    struct KeyMaterial25519 *km = (struct KeyMaterial25519 *)key->data;
    EVP_PKEY *edKeyPub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
        key->data + sizeof(struct KeyMaterial25519), km->pubKeySize);

    if (edKeyPub == NULL) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        HksLogOpensslError();
        EVP_PKEY_free(edKeyPub);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, edKeyPub) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            break;
        }

        if (EVP_DigestVerify(mdctx, signature->data, signature->size, message->data, message->size) !=
            HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            break;
        }

        ret = HKS_SUCCESS;
    } while (0);

    EVP_PKEY_free(edKeyPub);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int32_t HksOpensslGetEd25519PubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterial25519 *key = (struct KeyMaterial25519 *)input->data;
    uint32_t outLen = sizeof(struct KeyMaterial25519) + key->pubKeySize;
    if (memcpy_s(output->data, output->size, key, outLen) != EOK) {
        HKS_LOG_E("memcpy_s ed25519 pub key Fail!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    ((struct KeyMaterial25519 *)output->data)->priKeySize = 0;
    output->size = outLen;
    return HKS_SUCCESS;
}

