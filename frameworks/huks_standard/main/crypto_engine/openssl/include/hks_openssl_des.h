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

#ifndef HKS_OPENSSL_DES_H
#define HKS_OPENSSL_DES_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_crypto_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HKS_DES_IV_SIZE 8
#define HKS_DES_BLOCK_SIZE 8

struct HksOpensslDesCtx {
    uint32_t mode;
    uint32_t padding;
    void *append;
};

#ifdef HKS_SUPPORT_DES_C
#ifdef HKS_SUPPORT_DES_GENERATE_KEY
int32_t HksOpensslDesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key);
#endif /* HKS_SUPPORT_DES_GENERATE_KEY */

int32_t HksOpensslDesCryptoInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt);

int32_t HksOpensslDesCryptoUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt);

int32_t HksOpensslDesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const bool encrypt);

void HksOpensslDesHalFreeCtx(void **cryptoCtx);
#endif /* HKS_SUPPORT_DES_C */

int32_t DesNoPaddingCryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt);

int32_t DesNoPaddingCryptUpdate(void *cryptoCtx, const struct HksBlob *message, const bool encrypt,
    struct HksBlob *cipherText);

int32_t DesNoPaddingCryptFinal(void **cryptoCtx, const struct HksBlob *message, const bool encrypt,
    struct HksBlob *cipherText);
#ifdef __cplusplus
}
#endif

#endif /* HKS_OPENSSL_DES_H */