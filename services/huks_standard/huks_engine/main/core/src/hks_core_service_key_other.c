/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_core_service_key_other.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_ability.h"
#include "dcm_attest.h"
#include "hks_log.h"
#include "hks_crypto_hal.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_keynode.h"

#include "securec.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

int32_t HksCoreModuleInit(void)
{
    int32_t ret = HksInitHuksMutex();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hks mutex init failed, ret = %" LOG_PUBLIC "d", ret)

    ret = HksCryptoAbilityInit();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hks init crypto ability failed, ret = %" LOG_PUBLIC "d", ret)

    ret = HksCoreInitAuthTokenKey();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hks init auth token key failed, ret = %" LOG_PUBLIC "d", ret)
#ifndef _HARDWARE_ROOT_KEY_
    ret = HksRkcInit();
    HKS_IF_NOT_SUCC_LOGE(ret, "Hks rkc init failed! ret = 0x%" LOG_PUBLIC "X", ret)
#endif

    return ret;
}

int32_t HksCoreModuleDestroy(void)
{
    HksDestroyHuksMutex();
    HksCoreDestroyAuthTokenKey();
#ifndef _HARDWARE_ROOT_KEY_
    HksCfgDestroy();
    HksMkDestroy();
#endif
    return HKS_SUCCESS;
}

int32_t HksCoreRefreshKeyInfo(void)
{
#ifndef _HARDWARE_ROOT_KEY_
    HksCfgDestroy();
    HksMkDestroy();
    int32_t ret = HksRkcInit();
    HKS_IF_NOT_SUCC_LOGE(ret, "Hks rkc refresh info failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return ret;
#else
    return HKS_SUCCESS;
#endif
}

#ifdef _STORAGE_LITE_
static int32_t GetMacKey(const struct HksBlob *salt, struct HksBlob *macKey)
{
    uint8_t keyBuf[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256)] = {0};
    struct HksBlob mk = { HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), keyBuf };

    int32_t ret = HksCryptoHalGetMainKey(NULL, &mk);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get kek failed, ret = %" LOG_PUBLIC "d", ret)

    struct HksKeyDerivationParam derParam = {
        .salt = *salt,
        .iterations = HKS_KEY_BLOB_DERIVE_CNT,
        .digestAlg = HKS_DIGEST_SHA256,
    };
    struct HksKeySpec derivationSpec = { HKS_ALG_PBKDF2, HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), &derParam };
    ret = HksCryptoHalDeriveKey(&mk, &derivationSpec, macKey);
    HKS_IF_NOT_SUCC_LOGE(ret, "get keyblob derive key failed!")

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    return ret;
}

int32_t HksCoreCalcMacHeader(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    /* 1. get mac key by derive from salt */
    uint8_t keyBuf[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256)] = {0};
    struct HksBlob macKey = { HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), keyBuf };
    int32_t ret = GetMacKey(salt, &macKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get mac key failed, ret = %" LOG_PUBLIC "d", ret)

    struct HksParam *digestParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("calc mac header get HKS_TAG_DIGEST param failed, ret = %" LOG_PUBLIC "d", ret);
        (void)memset_s(macKey.data, macKey.size, 0, macKey.size);
        return ret;
    }

    /* 2. do mac */
    ret = HksCryptoHalHmac(&macKey, digestParam->uint32Param, srcData, mac);
    (void)memset_s(macKey.data, macKey.size, 0, macKey.size);
    return ret;
}
#endif

int32_t HksCoreRefresh(void)
{
    return HksCoreRefreshKeyInfo();
}

int32_t HksCoreGetAbility(int32_t funcType)
{
    (void)(funcType);
    return 0;
}

int32_t HksCoreGetHardwareInfo(void)
{
    return 0;
}