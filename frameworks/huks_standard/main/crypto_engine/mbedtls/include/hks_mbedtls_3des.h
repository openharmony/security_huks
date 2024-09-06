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

#ifndef HKS_MBEDTLS_3DES_H
#define HKS_MBEDTLS_3DES_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_crypto_hal.h"
#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HKS_SUPPORT_3DES_C
#ifdef HKS_SUPPORT_3DES_GENERATE_KEY
int32_t HksMbedtls3DesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key);
#endif /* HKS_SUPPORT_3DES_GENERATE_KEY */

int32_t HksMbedtls3DesCryptoInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt);

int32_t HksMbedtls3DesCryptoUpdate(
    void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText, const bool encrypt);

int32_t HksMbedtls3DesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt);

void HksMbedtls3DesHalFreeCtx(void **cryptoCtx);

#endif /* HKS_SUPPORT_3DES_C */
#ifdef __cplusplus
}
#endif

#endif /* HKS_MBEDTLS_3DES_H */