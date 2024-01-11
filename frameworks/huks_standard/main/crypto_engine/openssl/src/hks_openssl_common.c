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

#include "hks_openssl_common.h"

#include <openssl/rand.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

int32_t HksOpensslGenerateRandomKey(const uint32_t keySize, struct HksBlob *key)
{
    uint32_t keySizeByte = keySize / BIT_NUM_OF_UINT8;
    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;

    uint8_t *tmpKey = (uint8_t *)HksMalloc(keySizeByte);
    HKS_IF_NULL_LOGE_RETURN(tmpKey, HKS_ERROR_MALLOC_FAIL, "malloc buffer failed")

    do {
        if (RAND_bytes(tmpKey, keySizeByte) <= 0) {
            HKS_LOG_E("generate key is failed:0x%" LOG_PUBLIC "x", ret);
            break;
        }

        key->data = tmpKey;
        key->size = keySizeByte;
        ret = HKS_SUCCESS;
    } while (0);

    if (ret != HKS_SUCCESS) {
        (void)memset_s(tmpKey, keySizeByte, 0, keySizeByte);
        HKS_FREE(tmpKey);
    }
    return ret;
}

static int32_t HksOpensslFillRandomInner(struct HksBlob *randomData, bool isPriv)
{
    int ret = isPriv ?
        RAND_priv_bytes(randomData->data, randomData->size) :
        RAND_bytes(randomData->data, randomData->size);
    if (ret <= 0) {
        HKS_LOG_E("generate random failed, ret = 0x%" LOG_PUBLIC "x, isPriv = %" LOG_PUBLIC "d", ret, isPriv);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    if (randomData->size == 1) {
        return HKS_SUCCESS;
    }

    uint32_t j = 0;

    for (uint32_t i = 0; i < randomData->size; i++) {
        if (randomData->data[i] == 0) {
            j++;
        }
    }
    if (j == randomData->size) {
        HKS_LOG_E("fill random failed, size %" LOG_PUBLIC "x, isPriv = %" LOG_PUBLIC "d", randomData->size, isPriv);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    HKS_LOG_D("generate random success, isPriv =%" LOG_PUBLIC "d", isPriv);

    return HKS_SUCCESS;
}

int32_t HksOpensslFillRandom(struct HksBlob *randomData)
{
    return HksOpensslFillRandomInner(randomData, false);
}

int32_t HksOpensslFillPrivRandom(struct HksBlob *randomData)
{
    return HksOpensslFillRandomInner(randomData, true);
}
