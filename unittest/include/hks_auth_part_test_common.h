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

#ifndef HKS_AUTH_PART_TEST_COMMON_H
#define HKS_AUTH_PART_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"
namespace Unittest::AuthPartTest {
static const std::string g_inData = "Hks_Auth_Part_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t SIGN_COMMON_SIZE = 1024;

struct GenerateKeyCaseParam {
    uint32_t id;
    int32_t result;
    struct HksParam params[9];
};

int32_t HksAuthSignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);
int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, bool isSign);
}
#endif // HKS_AUTH_PART_TEST_COMMON_H

