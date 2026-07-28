/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef HKS_OPENSSL_ML_KEM_H
#define HKS_OPENSSL_ML_KEM_H

#include "hks_crypto_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HKS_SUPPORT_ML_KEM_C
#ifdef HKS_SUPPORT_ML_KEM_GENERATE_KEY
int32_t HksOpensslMlKemGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key);
#endif // HKS_SUPPORT_ML_KEM_GENERATE_KEY

#ifdef HKS_SUPPORT_ML_KEM_GET_PUBLIC_KEY
int32_t HksOpensslMlKemGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut);
#endif // HKS_SUPPORT_ML_KEM_GET_PUBLIC_KEY

#endif // HKS_SUPPORT_ML_KEM_C

#ifdef __cplusplus
}
#endif

#endif /* HKS_OPENSSL_ML_KEM_H */