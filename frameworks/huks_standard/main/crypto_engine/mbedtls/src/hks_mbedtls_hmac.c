/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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

#ifdef HKS_SUPPORT_HMAC_C

#ifdef HUKS_LOG_MINI_EXT_ENABLED
#include "log.h"
#endif

#include "hks_mbedtls_hmac.h"

#include <mbedtls/md.h>
#include <securec.h>

#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_mbedtls_common.h"
#include "hks_mem.h"
#include "hks_template.h"

struct HksMbedtlsHmacCtx {
    uint32_t digestAlg;
    void    *append;
} HksMbedtlsHmacCtx;

#ifdef HKS_SUPPORT_HMAC_GENERATE_KEY
int32_t HksMbedtlsHmacGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if ((spec->keyLen == 0) || (spec->keyLen % HKS_BITS_PER_BYTE != 0)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    const uint32_t keyByteLen = spec->keyLen / HKS_BITS_PER_BYTE;

    uint8_t *outKey = (uint8_t *)HksMalloc(keyByteLen);
    HKS_IF_NULL_RETURN(outKey, HKS_ERROR_MALLOC_FAIL)

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    int32_t ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(outKey);
        return ret;
    }

    do {
        ret = mbedtls_ctr_drbg_random(&ctrDrbg, outKey, keyByteLen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls ctr drbg random failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
            HILOG_ERROR(HILOG_MODULE_SCY, "Mbedtls ctr drbg random failed! mbedtls ret = 0x%{public}X", ret);
#endif
            (void)memset_s(outKey, keyByteLen, 0, keyByteLen);
            HKS_FREE(outKey);
            break;
        }

        key->data = outKey;
        key->size = keyByteLen;
    } while (0);

    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
#endif /* HKS_SUPPORT_HMAC_GENERATE_KEY */

int32_t HksMbedtlsHmac(const struct HksBlob *key,
    uint32_t digestAlg, const struct HksBlob *msg, struct HksBlob *mac)
{
    /* input params have been checked */
    uint32_t mbedtlsAlg;
    int32_t ret = HksToMbedtlsDigestAlg(digestAlg, &mbedtlsAlg);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = mbedtls_md_hmac(mbedtls_md_info_from_type((mbedtls_md_type_t)mbedtlsAlg),
        key->data, key->size, msg->data, msg->size, mac->data);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls hmac failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
        HILOG_ERROR(HILOG_MODULE_SCY, "Mbedtls hmac failed! mbedtls ret = 0x%{public}X", ret);
#endif
        (void)memset_s(mac->data, mac->size, 0, mac->size);
        return ret;
    }

    ret = HksGetDigestLen(digestAlg, &(mac->size));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get digest len failed!");
        (void)memset_s(mac->data, mac->size, 0, mac->size);
    }

    return ret;
}

int32_t HksMbedtlsHmacInit(void **cryptoCtx, const struct HksBlob *key, uint32_t digestAlg)
{
    /* input params have been checked */
    uint32_t mbedtlsAlg;
    int32_t ret = HksToMbedtlsDigestAlg(digestAlg, &mbedtlsAlg);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (mbedtls_md_info_from_type((mbedtls_md_type_t)mbedtlsAlg) == NULL) {
        HKS_LOG_E("Mbedtls hmac engine info failed!");
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mbedtls_md_context_t *hmacCtx = (mbedtls_md_context_t *)HksMalloc(sizeof(mbedtls_md_context_t));
    HKS_IF_NULL_LOGE_RETURN(hmacCtx, HKS_ERROR_MALLOC_FAIL, "Mbedtls hmac init hmacCtx malloc fail!")

    mbedtls_md_init(hmacCtx);

    ret = mbedtls_md_setup(hmacCtx, mbedtls_md_info_from_type((mbedtls_md_type_t)mbedtlsAlg), 1);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls hmac setup failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_md_free(hmacCtx);
        HKS_FREE(hmacCtx);
        return ret;
    }

    ret = mbedtls_md_hmac_starts(hmacCtx, key->data, key->size);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls hmac start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_md_free(hmacCtx);
        HKS_FREE(hmacCtx);
        return ret;
    }

    struct HksMbedtlsHmacCtx *outCtx = (struct HksMbedtlsHmacCtx *)HksMalloc(sizeof(struct HksMbedtlsHmacCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("Mbedtls hmac start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_md_free(hmacCtx);
        HKS_FREE(hmacCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->digestAlg = digestAlg;
    outCtx->append = (void *)hmacCtx;
    *cryptoCtx = (void *)outCtx;
    return HKS_SUCCESS;
}

int32_t HksMbedtlsHmacUpdate(void *cryptoCtx, const struct HksBlob *msg)
{
    struct HksMbedtlsHmacCtx *hctx = (struct HksMbedtlsHmacCtx *)cryptoCtx;
    mbedtls_md_context_t *hmacCtx = (mbedtls_md_context_t *)hctx->append;
    HKS_IF_NULL_LOGE_RETURN(hmacCtx, HKS_ERROR_MALLOC_FAIL, "Mbedtls hmac update hmacCtx is null!")

    int32_t ret = mbedtls_md_hmac_update(hmacCtx, msg->data, msg->size);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls hmac start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t HksMbedtlsHmacFinal(void **cryptoCtx, struct HksBlob *msg, struct HksBlob *mac)
{
    struct HksMbedtlsHmacCtx *hctx = (struct HksMbedtlsHmacCtx *)*cryptoCtx;
    mbedtls_md_context_t *hmacCtx = (mbedtls_md_context_t *)hctx->append;
    if (hmacCtx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret;
    if (msg->size != 0) {
        ret = mbedtls_md_hmac_update(hmacCtx, msg->data, msg->size);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls hmac start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            HksMbedtlsHmacHalFreeCtx(cryptoCtx);
            return ret;
        }
    }

    ret = mbedtls_md_hmac_finish(hmacCtx, mac->data);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls hmac finish failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(mac->data, mac->size, 0, mac->size);
        HksMbedtlsHmacHalFreeCtx(cryptoCtx);
        return ret;
    }

    ret = HksGetDigestLen(hctx->digestAlg, &(mac->size));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get digest len failed!");
        HksMbedtlsHmacHalFreeCtx(cryptoCtx);
        return ret;
    }

    HksMbedtlsHmacHalFreeCtx(cryptoCtx);
    return HKS_SUCCESS;
}

void HksMbedtlsHmacHalFreeCtx(void **cryptoCtx)
{
    if (cryptoCtx == NULL || *cryptoCtx == NULL) {
        HKS_LOG_E("Mbedtls hmac free ctx is null");
        return;
    }

    struct HksMbedtlsHmacCtx *hctx = (struct HksMbedtlsHmacCtx *)*cryptoCtx;
    if (hctx->append != NULL) {
        mbedtls_md_free((mbedtls_md_context_t *)hctx->append);
        HKS_FREE(hctx->append);
    }
    HKS_FREE(*cryptoCtx);
}
#endif /* HKS_SUPPORT_HMAC_C */
