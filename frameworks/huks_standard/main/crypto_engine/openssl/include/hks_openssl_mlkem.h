/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HKS_OPENSSL_MLKEM_H
#define HKS_OPENSSL_MLKEM_H

#include "hks_type.h"
#include "hks_crypto_hal.h"
#include "hks_openssl_engine.h"

int32_t HksOpensslMlKemEncapsulate(const struct HksBlob *rawKey, struct HksEncapsulationResult *encapResult);

int32_t HksOpensslMlKemDecapsulate(const struct HksBlob *rawKey, const struct HksBlob *ciphertext,
    struct HksBlob *sharedSecret);

#endif /* HKS_OPENSSL_MLKEM_H */