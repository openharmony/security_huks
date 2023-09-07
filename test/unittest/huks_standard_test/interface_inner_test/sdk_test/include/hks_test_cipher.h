/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_CIPHER_H
#define HKS_TEST_CIPHER_H

#include "hks_test_cipher_h.h"

struct CipherEncryptStructure {
    struct HksBlob *keyAlias;
    const struct HksTestCipherParamsParamSet *cipherParms;
    struct HksBlob *plainData;
    struct HksBlob *cipherData;
    struct HksBlob **ivData;
    struct HksBlob **nonceData;
    struct HksBlob **aadData;
    uint32_t performTimes;
};

#endif