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

#ifndef HKS_HMAC_DERIVE_TEST_COMMON_H
#define HKS_HMAC_DERIVE_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"
namespace Unittest::HmacDerive {
static const std::string g_deriveInfo = "Hks_HMAC_Derive_Test_0000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t COMMON_SIZE = 2048;
static const uint32_t DERIVE_KEY_SIZE_32 = 32;
static const uint32_t DERIVE_KEY_SIZE_48 = 48;
static const uint32_t DERIVE_KEY_SIZE_64 = 64;

int32_t HksHmacDeriveTestNormalCase1(const struct HksBlob keyAlias, const struct HksParamSet *genParamSet,
    struct HksParamSet *DeriveParamSet, struct HksParamSet *DeriveFinalParamsSet, int32_t cmpRet);
int32_t HksHmacDeriveTestNormalCase2(const struct HksBlob keyAlias, const struct HksParamSet *genParamSet,
    struct HksParamSet *DeriveParamSet, struct HksParamSet *DeriveFinalParamsSet, int32_t cmpRet);
int32_t HksHmacDeriveTestCmpCase(const struct HksBlob keyAlias, const struct HksParamSet *genParamSet,
    struct HksParamSet *DeriveParamSet, struct HksParamSet *DeriveFinalParamsSet);
}
#endif // HKS_HMAC_DERIVE_TEST_COMMON_H