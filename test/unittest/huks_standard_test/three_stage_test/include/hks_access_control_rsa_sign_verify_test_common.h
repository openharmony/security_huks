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

#ifndef HKS_ACCESS_CONTROL_RSA_SIGN_VERIFY_TEST_COMMON_H
#define HKS_ACCESS_CONTROL_RSA_SIGN_VERIFY_TEST_COMMON_H

#include <string>

#include "hks_access_control_test_common.h"
#include "hks_api.h"
#include "hks_in_data_array_after_hash_test_common.h"

namespace Unittest::AccessControlRsaSignVerify {
static const uint32_t RSA_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_RSA_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

struct TestAccessCaseRSAParams {
    std::vector<HksParam> genParams;
    std::vector<HksParam> signParams;
    std::vector<HksParam> verifyParams;
    HksErrorCode initResult = HksErrorCode::HKS_SUCCESS;
};

int32_t HksAcRsaSignVerifyTestNormalCase(const TestAccessCaseRSAParams &testCaseParams, const IDMParams &testIDMParams);
int32_t HksAcRsaSignVerifyTestAbnormalCase(const TestAccessCaseRSAParams &testCaseParams,
    const IDMParams &testIDMParams);
int32_t HksAcRsaSignTestCustomCase(const TestAccessCaseRSAParams &testCaseParams1,
    const TestAccessCaseRSAParams &testCaseParams2, const IDMParams &testIDMParams);
}
#endif