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

namespace Unittest::AccessControlRsaSignVerify {


static const std::string g_inData = "Hks_RSA_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t RSA_COMMON_SIZE = 1024;

struct TestAccessCaseRSAParams {
    std::vector<HksParam> genParams;
    std::vector<HksParam> signParams;
    std::vector<HksParam> verifyParams;
    HksErrorCode initResult = HksErrorCode::HKS_SUCCESS;
};

int32_t RSAAuthTokenSign(struct HksBlob *challenge, const IDMParams &testIDMParams,
                         struct HksParam *tmpParams);
int32_t AddAuthTokenParam(struct HksParamSet *paramSet, const struct HksParam *tmpParams);
int32_t HksAcRsaThreeStageNormalCase(struct HksBlob *keyAlias, struct HksParamSet *ParamSet,
                                     const IDMParams &testIDMParams, struct HksBlob *inDataSign, struct HksBlob *outDataSign);
int32_t AddAuthToeknParamCustomCase(struct HksBlob &challengeBlob1, struct HksBlob &challengeBlob2,
                                    struct HksParam *signParams, const IDMParams &testIDMParams);
int32_t AddPosParamCustomCase(struct HksParam *signParams, struct HksParamSet *ParamSet, struct HksParamSet *newParamSet, 
                              int32_t pos, const IDMParams &testIDMParams);
int32_t HksAcRsaThreeStageSignCustomCase(struct HksBlob *keyAlias1, struct HksParamSet *ParamSet1,
                                         struct HksBlob *keyAlias2, struct HksParamSet *ParamSet2,
                                         const IDMParams &testIDMParams);
int32_t HksAcRsaThreeStageVerifyCustomCase(struct HksBlob *keyAlias1, struct HksParamSet *ParamSet1,
                                           struct HksBlob *keyAlias2, struct HksParamSet *ParamSet2,
                                           const IDMParams &testIDMParams);
int32_t HksAcRsaSignVerifyTestNormalCase(const TestAccessCaseRSAParams &testCaseParams,
                                         const IDMParams &testIDMParams);
int32_t HksAcRsaSignVerifyTestAbnormalCase(const TestAccessCaseRSAParams &testCaseParams,
                                           const IDMParams &testIDMParams);
int32_t HksAcRsaSignTestCustomCase(const TestAccessCaseRSAParams &testCaseParams1,
                                         const TestAccessCaseRSAParams &testCaseParams2,
                                         const IDMParams &testIDMParams);
int32_t HksAcRsaVerifyTestCustomCase (const TestAccessCaseRSAParams &testCaseParams1,
                                      const TestAccessCaseRSAParams &testCaseParams2,
                                      struct HksBlob *publicKey1, struct HksBlob *publicKey2,
                                      const IDMParams &testIDMParams);
}
#endif