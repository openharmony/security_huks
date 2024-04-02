/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define OPENSSL_NO_DEPRECATED

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_SM2_C
#include "hks_openssl_sm2.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <stdbool.h>
#include <stddef.h>

#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_ecc.h"
#include "hks_openssl_engine.h"
#include "hks_openssl_hmac.h"
#include "hks_template.h"
#include "hks_type.h"

#include <string.h>

#include "securec.h"

#ifdef HKS_SUPPORT_SM2_GENERATE_KEY
static int32_t EvpPkeyToKeyMaterialEc(const struct HksKeySpec *spec, const EVP_PKEY *pkey, struct HksBlob *key)
{
    struct HksBlob pubXBlob = { 0, NULL };
    struct HksBlob pubYBlob = { 0, NULL };
    struct HksBlob privBlob = { 0, NULL };
    // pubXBlob pubYBlob privBlob length may not be HKS_KEY_BYTES(spec->keyLen)
    // pubXBlob pubYBlob privBlob length all are not greater than HKS_MAX_KEY_LEN
    // lengthes have been checked in GetBnBinpadFromPkey
    int pubXRet = GetBnBinpadFromPkey(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pubXBlob);
    int pubYRet = GetBnBinpadFromPkey(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &pubYBlob);
    int priRet = GetBnBinpadFromPkey(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &privBlob);
    int ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        if (pubXRet != HKS_SUCCESS || pubYRet != HKS_SUCCESS || priRet != HKS_SUCCESS) {
            HKS_LOG_E("GetBnBinpadFromPkey failed");
            break;
        }
        uint32_t rawMaterialLen = sizeof(struct KeyMaterialEcc) + pubXBlob.size + pubYBlob.size + privBlob.size;
        uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
        if (!rawMaterial) {
            HKS_LOG_E("HksMalloc rawMaterial NULL");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }
        /*
        * ECC key data internal struct:
        * struct KeyMaterialEcc + pubX_data + pubY_data + pri_data
        */
        struct KeyMaterialEcc *keyMaterial = (struct KeyMaterialEcc *)rawMaterial;
        keyMaterial->keyAlg = (enum HksKeyAlg)spec->algType;
        keyMaterial->keySize = spec->keyLen;
        keyMaterial->xSize = pubXBlob.size;
        keyMaterial->ySize = pubYBlob.size;
        keyMaterial->zSize = privBlob.size;
        uint32_t offset = sizeof(struct KeyMaterialEcc);
        pubXRet = memcpy_s(rawMaterial + offset, pubXBlob.size, pubXBlob.data, pubXBlob.size);
        offset += pubXBlob.size;
        pubYRet = memcpy_s(rawMaterial + offset, pubYBlob.size, pubYBlob.data, pubYBlob.size);
        offset += pubYBlob.size;
        priRet = memcpy_s(rawMaterial + offset, privBlob.size, privBlob.data, privBlob.size);
        if (pubXRet != EOK || pubYRet != EOK || priRet != EOK) {
            HKS_LOG_E("memcpy_s failed");
            HKS_FREE(rawMaterial);
            ret = HKS_ERROR_BAD_STATE;
            break;
        }
        key->data = rawMaterial;
        key->size = rawMaterialLen;
        ret = HKS_SUCCESS;
    } while (false);
    HKS_FREE(privBlob.data);
    HKS_FREE(pubXBlob.data);
    HKS_FREE(pubYBlob.data);
    return ret;
}

int32_t HksOpensslSm2GenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if (spec->algType != HKS_ALG_SM2) {
        HKS_LOG_E("not HKS_ALG_SM2 but %" LOG_PUBLIC "u", spec->algType);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (spec->keyLen != HKS_SM2_KEY_SIZE_256) {
        HKS_LOG_E("Sm2 Invalid keyLen %" LOG_PUBLIC "u", spec->keyLen);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!ctx) {
        HKS_LOG_E("ctx NULL %s", ERR_reason_error_string(ERR_get_error()));
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    int ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    EVP_PKEY *pkey = NULL;
    do {
        int osRet = EVP_PKEY_keygen_init(ctx);
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_keygen_init ret = %d %s", osRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        osRet = EVP_PKEY_keygen(ctx, &pkey);
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_keygen ret = %d %s", osRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        ret = EvpPkeyToKeyMaterialEc(spec, pkey, key);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("EvpPkeyToKeyMaterialEc ret = %" LOG_PUBLIC "d", ret);
            break;
        }
    } while (false);
    SELF_FREE_PTR(pkey, EVP_PKEY_free)
    SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
    return ret;
}
#endif

static int GetSm2Modules(const struct HksBlob *keyBlob, struct KeyMaterialEcc *out)
{
    struct KeyMaterialEcc *keyMaterial = (struct KeyMaterialEcc *)keyBlob->data;
    HKS_LOG_I("keySize = %" LOG_PUBLIC "u, xSize = %" LOG_PUBLIC "u, ySize = %" LOG_PUBLIC "u, zSize = %" LOG_PUBLIC
        "u", keyMaterial->keySize, keyMaterial->xSize, keyMaterial->ySize, keyMaterial->zSize);
    // if the big number starts with leading zero, then its length will be less than 32, e.g. 31, 30, but not 32,
    // so we ensure that its length is not greater than 32.
    if ((keyMaterial->keySize != HKS_SM2_KEY_SIZE_256) ||
        (keyMaterial->xSize > HKS_KEY_BYTES(keyMaterial->keySize)) ||
        (keyMaterial->ySize > HKS_KEY_BYTES(keyMaterial->keySize)) ||
        (keyMaterial->zSize > HKS_KEY_BYTES(keyMaterial->keySize)) ||
        (sizeof(struct KeyMaterialEcc) + keyMaterial->xSize + keyMaterial->ySize + keyMaterial->zSize !=
            keyBlob->size)) {
        HKS_LOG_E("invalid size");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    *out = *keyMaterial;
    return HKS_SUCCESS;
}

static int32_t PushPubKeyToParam(const uint8_t *keyPair, const struct KeyMaterialEcc *size,
    uint32_t fullSize, uint8_t *uncompressedPublicKey, OSSL_PARAM_BLD *paramBld)
{
    HKS_LOG_I("begin PushPubKeyToParam");
    // https://www.mail-archive.com/openssl-users@openssl.org/msg90185.html
    // Unfortunately supplying x and y separately is not supported for import.
    // You have to instead use OSSL_PKEY_PARAM_PUB_KEY.
    // You can supply the key as an uncompressed public key simply be concatenating the byte "04",
    // the x co-ord (padded to the appropriate size if necessary) and the y co-cord (also padded as appropriate).

    // NOTICE! x size and y size are smaller than or equal to HKS_KEY_BYTES(size->keySize)
    // e.g. assuming that HKS_KEY_BYTES(size->keySize) is 32, x size might be 32, 31, 30, etc.
    uncompressedPublicKey[0] = POINT_CONVERSION_UNCOMPRESSED;
    errno_t memRet = memcpy_s(uncompressedPublicKey + 1 + HKS_KEY_BYTES(size->keySize) - size->xSize, size->xSize,
        keyPair + sizeof(struct KeyMaterialEcc), size->xSize);
    if (memRet != EOK) {
        HKS_LOG_E("copy x fail");
        return HKS_ERROR_BAD_STATE;
    }
    memRet = memcpy_s(uncompressedPublicKey + fullSize - size->ySize, size->ySize,
        keyPair + sizeof(struct KeyMaterialEcc) + size->xSize, size->ySize);
    if (memRet != EOK) {
        HKS_LOG_E("copy y fail");
        return HKS_ERROR_BAD_STATE;
    }
    int osRet = OSSL_PARAM_BLD_push_octet_string(paramBld, OSSL_PKEY_PARAM_PUB_KEY,
        uncompressedPublicKey, fullSize);
    if (osRet != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("OSSL_PARAM_BLD_push_octet_string failed %" LOG_PUBLIC "d", osRet);
        HksLogOpensslError();
        return HKS_ERROR_BAD_STATE;
    }
    return HKS_SUCCESS;
}

// Notice: you must call OSSL_PARAM_free after using the return value.
static OSSL_PARAM *ConstructSm2ParamsFromRawKey(
    uint8_t *keyPair, const struct KeyMaterialEcc *size, enum HksKeyPurpose keyPurpose)
{
    // publicXSize publicYSize privateSize lengthes all are not greater than HKS_MAX_KEY_LEN
    // have been checked in GetSm2Modules
    OSSL_PARAM_BLD *paramBld = OSSL_PARAM_BLD_new();
    HKS_IF_NULL_LOGE_RETURN(paramBld, NULL, "OSSL_PARAM_BLD_new failed")
    OSSL_PARAM *params = NULL;
    uint8_t *uncompressedPublicKey = NULL;
    BIGNUM *priBn = NULL;
    do {
        int ret = OSSL_PARAM_BLD_push_utf8_string(paramBld, OSSL_PKEY_PARAM_GROUP_NAME, SN_sm2, 0);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("OSSL_PARAM_BLD_push_utf8_string failed %" LOG_PUBLIC "d", ret);
            HksLogOpensslError();
            break;
        }

        // push public key if it is present
        if (size->xSize != 0 && size->ySize != 0) {
            // sizes have been checked in GetSm2Modules
            uint32_t fullSize = 1 + HKS_KEY_BYTES(size->keySize) + HKS_KEY_BYTES(size->keySize);
            uncompressedPublicKey = HksMalloc(fullSize);
            HKS_IF_NULL_LOGE_BREAK(uncompressedPublicKey, "uncompressedPublicKey HksMalloc NULL")
            ret = PushPubKeyToParam(keyPair, size, fullSize, uncompressedPublicKey, paramBld);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PushPubKeyToParam failed %" LOG_PUBLIC "d", ret)
        }

        // push private key if required
        if ((keyPurpose == HKS_KEY_PURPOSE_DECRYPT) || (keyPurpose == HKS_KEY_PURPOSE_SIGN)) {
            if (size->zSize == 0) {
                HKS_LOG_E("decrypt or sign but private key empty");
                break;
            }
            priBn = BN_bin2bn(keyPair + sizeof(struct KeyMaterialEcc) + size->xSize + size->ySize,
                size->zSize, NULL);
            HKS_IF_NULL_LOGE_BREAK(priBn, "BN_bin2bn fail%" LOG_PUBLIC "s", ERR_reason_error_string(ERR_get_error()))
            ret = OSSL_PARAM_BLD_push_BN(paramBld, OSSL_PKEY_PARAM_PRIV_KEY, priBn);
            if (ret != HKS_OPENSSL_SUCCESS) {
                HKS_LOG_E("OSSL_PARAM_BLD_push_BN failed %" LOG_PUBLIC "d", ret);
                break;
            }
        }

        params = OSSL_PARAM_BLD_to_param(paramBld);
        HKS_IF_NULL_LOGE_BREAK(params, "OSSL_PARAM_BLD_to_param fail %" LOG_PUBLIC "s",
            ERR_reason_error_string(ERR_get_error()))
    } while (0);
    SELF_FREE_PTR(paramBld, OSSL_PARAM_BLD_free)
    HKS_FREE(uncompressedPublicKey);
    BN_free(priBn);
    return params;
}

static EVP_PKEY *Sm2InitKey(const struct HksBlob *keyBlob, enum HksKeyPurpose keyPurpose)
{
    /* get ecc pubX,pubY,pri */
    uint8_t *keyPair = keyBlob->data;
    struct KeyMaterialEcc keyMaterial = {0};

    HKS_IF_NOT_SUCC_LOGE_RETURN(GetSm2Modules(keyBlob, &keyMaterial),
        NULL, "get sm2 key modules is failed")

    EVP_PKEY *sm2EvpPkey = NULL;
    HKS_LOG_I("begin ConstructSm2ParamsFromRawKey");
    OSSL_PARAM *params = ConstructSm2ParamsFromRawKey(keyPair, &keyMaterial, keyPurpose);
    if (params == NULL) {
        HKS_LOG_E("ConstructSm2ParamsFromRawKey failed");
        return NULL;
    }
    do {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(NID_sm2, NULL);
        if (ctx == NULL) {
            HKS_LOG_E("EVP_PKEY_CTX_new_id failed");
            HksLogOpensslError();
            break;
        }
        int ret = EVP_PKEY_fromdata_init(ctx);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_fromdata_init failed %" LOG_PUBLIC "d", ret);
            HksLogOpensslError();
            SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
            break;
        }
        if (keyPurpose == HKS_KEY_PURPOSE_DECRYPT || keyPurpose == HKS_KEY_PURPOSE_SIGN) {
            HKS_LOG_I("selection is EVP_PKEY_KEYPAIR");
            ret = EVP_PKEY_fromdata(ctx, &sm2EvpPkey, EVP_PKEY_KEYPAIR, params);
        } else {
            HKS_LOG_I("selection is EVP_PKEY_PUBLIC_KEY");
            ret = EVP_PKEY_fromdata(ctx, &sm2EvpPkey, EVP_PKEY_PUBLIC_KEY, params);
        }
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_fromdata failed %" LOG_PUBLIC "d, %" LOG_PUBLIC "s",
                ret, ERR_reason_error_string(ERR_get_error()));
            SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
            SELF_FREE_PTR(sm2EvpPkey, EVP_PKEY_free)
            break;
        }
    } while (false);
    SELF_FREE_PTR(params, OSSL_PARAM_free)
    return sm2EvpPkey;
}

static int32_t SetDigestIfNeeded(enum HksKeyPurpose keyPurpose, uint32_t digest, const struct HksBlob *message,
    EVP_PKEY_CTX *ctx)
{
    if (!((keyPurpose == HKS_KEY_PURPOSE_SIGN) || (keyPurpose == HKS_KEY_PURPOSE_VERIFY))) {
        return HKS_SUCCESS;
    }
    const EVP_MD *opensslAlg = GetOpensslAlg(digest);
    if (opensslAlg != NULL) {
        HKS_LOG_I("selected EVP_MD name = %" LOG_PUBLIC "s", EVP_MD_get0_name(opensslAlg));
        int osRet = EVP_PKEY_CTX_set_signature_md(ctx, opensslAlg);
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("set digest type failed %" LOG_PUBLIC "d", osRet);
            HksLogOpensslError();
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        } else {
            return HKS_SUCCESS;
        }
    } else if (digest != HKS_DIGEST_NONE || message == NULL) {
        HKS_LOG_E("unknown digest %" LOG_PUBLIC "u", digest);
        return HKS_ERROR_INVALID_ARGUMENT;
    } else if (message->size != HKS_DIGEST_SM3_LEN) {
        HKS_LOG_E("digest is none but message size %" LOG_PUBLIC "u is not sm3 digest len!", message->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    } else {
        // the default digest for sm2 is sm3, so we don't need to set it.
        HKS_LOG_I("digest is none and message size is sm3 digest len");
        return HKS_SUCCESS;
    }
}

#ifdef HKS_SUPPORT_SM2_SIGN_VERIFY
static EVP_PKEY_CTX *InitSm2Ctx(const struct HksBlob *mainKey, uint32_t digest, enum HksKeyPurpose keyPurpose,
    const struct HksBlob *message)
{
    EVP_PKEY *key = Sm2InitKey(mainKey, keyPurpose);
    HKS_IF_NULL_LOGE_RETURN(key, NULL, "initialize sm2 key failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    EVP_PKEY_CTX *ctx = NULL;
    do {
        ctx = EVP_PKEY_CTX_new(key, NULL);
        HKS_IF_NULL_LOGE_BREAK(ctx, "new ctx failed")
        int osRet = 0; // set fail for default case
        switch (keyPurpose) {
            case HKS_KEY_PURPOSE_SIGN:
                osRet = EVP_PKEY_sign_init(ctx);
                break;
            case HKS_KEY_PURPOSE_VERIFY:
                osRet = EVP_PKEY_verify_init(ctx);
                break;
            case HKS_KEY_PURPOSE_ENCRYPT:
                osRet = EVP_PKEY_encrypt_init(ctx);
                break;
            case HKS_KEY_PURPOSE_DECRYPT:
                osRet = EVP_PKEY_decrypt_init(ctx);
                break;
            default:
                HKS_LOG_E("Not supported actionCode for SM2 keypair in huks!");
                break;
        }
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY sign/verify/encrypt/decrypt init failed %" LOG_PUBLIC "d", osRet);
            HksLogOpensslError();
            break;
        }
        HKS_LOG_I("init ok");
        ret = SetDigestIfNeeded(keyPurpose, digest, message, ctx);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("SetDigestIfNeeded failed %" LOG_PUBLIC "d", ret);
            break;
        }
    } while (0);
    SELF_FREE_PTR(key, EVP_PKEY_free)
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init ctx fail");
        HksLogOpensslError();
        SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
        return NULL;
    }
    return ctx;
}

int32_t HksOpensslSm2Verify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    if (CheckBlob(message) != HKS_SUCCESS || CheckBlob(signature) != HKS_SUCCESS) {
        HKS_LOG_E("sm sign invalid arg");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_LOG_I("sm2 verify");
    EVP_PKEY_CTX *ctx = InitSm2Ctx(key, usageSpec->digest, usageSpec->purpose, message);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize sm2 context failed")

    if (EVP_PKEY_verify(ctx, signature->data, signature->size, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_D("verify data failed");
        HksLogOpensslError();
        SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
    return HKS_SUCCESS;
}

int32_t HksOpensslSm2Sign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    if (CheckBlob(message) != HKS_SUCCESS || CheckBlob(signature) != HKS_SUCCESS) {
        HKS_LOG_E("sm sign invalid arg");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_LOG_I("sm2 sign");
    EVP_PKEY_CTX *ctx = InitSm2Ctx(key, usageSpec->digest, usageSpec->purpose, message);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize sm2 context failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        size_t sigSize = 0;
        int osRet = EVP_PKEY_sign(ctx, NULL, &sigSize, message->data, message->size);
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get sigSize failed osRet = %" LOG_PUBLIC "d %" LOG_PUBLIC "s",
                osRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }

        if (signature->size < sigSize) {
            HKS_LOG_E("out size too small %" LOG_PUBLIC "u < %" LOG_PUBLIC "zu", signature->size, sigSize);
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        osRet = EVP_PKEY_sign(ctx, signature->data, &sigSize, message->data, message->size);
        if (osRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("sign data failed osRet = %" LOG_PUBLIC "d %" LOG_PUBLIC "s",
                osRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        signature->size = (uint32_t)sigSize;
        ret = HKS_SUCCESS;
    } while (false);
    SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
    return ret;
}
#endif

#ifdef HKS_SUPPORT_SM2_ENCRYPT_DECRYPT
int HksOpensslSm2Encrypt(const struct HksBlob *keyPair, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *plainBlob, struct HksBlob *cipherBlob)
{
    HKS_LOG_I("sm2 encrypt");
    EVP_PKEY_CTX *ctx = InitSm2Ctx(keyPair, usageSpec->digest, HKS_KEY_PURPOSE_ENCRYPT, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize sm2 context when encrypt failed!")
    // cipherLength equals c1||c2||c3 which c1 and c3 is fixed length and c2 is equals to the plainText.
    size_t cipherSize = plainBlob->size + SM2_C1_SIZE + SM2_C3_SIZE;
    if (EVP_PKEY_encrypt(ctx, cipherBlob->data, &cipherSize, plainBlob->data,
        (size_t)plainBlob->size) != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("encrypt data failed");
        HksLogOpensslError();
        SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherBlob->size = (uint32_t)cipherSize;
    SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
    return HKS_SUCCESS;
}

int HksOpensslSm2Decrypt(const struct HksBlob *keyPair, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *cipherBlob, struct HksBlob *plainBlob)
{
    HKS_LOG_I("sm2 decrypt");
    if (usageSpec == NULL) {
        HKS_LOG_E("Invalid param");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(cipherBlob),
        HKS_ERROR_INVALID_ARGUMENT, "Invalid param cipherBlob!");
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(plainBlob), HKS_ERROR_INVALID_ARGUMENT, "Invalid param plainBlob!");
    EVP_PKEY_CTX *ctx = InitSm2Ctx(keyPair, usageSpec->digest, HKS_KEY_PURPOSE_DECRYPT, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize sm2 context when decrypt failed!")
    size_t decryptSize = plainBlob->size;
    if (EVP_PKEY_decrypt(ctx, plainBlob->data, &decryptSize, cipherBlob->data,
        cipherBlob->size) != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("decrypt data failed");
        HksLogOpensslError();
        SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainBlob->size  = (uint32_t)decryptSize;
    SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free)
    return HKS_SUCCESS;
}
#endif //HKS_SUPPORT_SM2_ENCRYPT_DECRYPT

#endif
