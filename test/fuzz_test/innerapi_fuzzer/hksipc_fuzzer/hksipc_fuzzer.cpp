/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hksipc_fuzzer.h"

#include <cstring>
#include <securec.h>
#include <vector>

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_service_ipc_serialization.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest001
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest001()
{
    HKS_LOG_I("enter HksIpcSerializationTest001");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    const char *alias = "alias";
    struct HksBlob aliasBlob = { .size = strlen(alias), .data = (uint8_t *)alias };
    struct HksParam aliasParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = aliasBlob };
    ret = HksAddParams(paramSet, &aliasParam, 1);
    ret = HksBuildParamSet(&paramSet);
    struct HksParamOut aliasOutParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = &aliasBlob };
    ret = HksParamSetToParams(paramSet, &aliasOutParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest002
 * @tc.desc: tdd HksParamSetToParams, expect HKS_ERROR_PARAM_NOT_EXIST
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest002()
{
    HKS_LOG_I("enter HksIpcSerializationTest002");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    const char *alias = "alias";
    struct HksBlob aliasBlob = { .size = strlen(alias), .data = (uint8_t *)alias };
    struct HksParamOut aliasOutParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = &aliasBlob };
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &aliasOutParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest003
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest003()
{
    HKS_LOG_I("enter HksIpcSerializationTest003");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    const char *alias = "alias";
    struct HksBlob aliasBlob = { .size = strlen(alias), .data = (uint8_t *)alias };
    struct HksParamOut aliasOutParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = &aliasBlob };
    struct HksParam aliasNullParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS + HKS_PARAM_BUFFER_NULL_INTERVAL,
        .blob = aliasBlob };
    ret = HksAddParams(paramSet, &aliasNullParam, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &aliasOutParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest004
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest004()
{
    HKS_LOG_I("enter HksIpcSerializationTest004");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    struct HksParam param = { .tag = HKS_TAG_KEY_AUTH_RESULT, .int32Param = 0 };
    int32_t outParamInt = 1;
    struct HksParamOut outParam = { .tag = HKS_TAG_KEY_AUTH_RESULT, .int32Param = &outParamInt };
    ret = HksAddParams(paramSet, &param, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &outParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest005
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest005()
{
    HKS_LOG_I("enter HksIpcSerializationTest005");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    struct HksParam param = { .tag = HKS_TAG_ACCESS_TIME, .uint32Param = 0 };
    uint32_t outParamUint = 1;
    struct HksParamOut outParam = { .tag = HKS_TAG_ACCESS_TIME, .uint32Param = &outParamUint };
    ret = HksAddParams(paramSet, &param, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &outParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest006
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest006()
{
    HKS_LOG_I("enter HksIpcSerializationTest006");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    struct HksParam param = { .tag = HKS_TAG_IF_NEED_APPEND_AUTH_INFO, .boolParam = true };
    bool outParamBool = false;
    struct HksParamOut outParam = { .tag = HKS_TAG_IF_NEED_APPEND_AUTH_INFO, .boolParam = &outParamBool };
    ret = HksAddParams(paramSet, &param, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &outParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest007
 * @tc.desc: tdd HksParamSetToParams, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest007()
{
    HKS_LOG_I("enter HksIpcSerializationTest007");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    struct HksParam param = { .tag = HKS_TAG_KEY_ACCESS_TIME, .uint64Param = 0 };
    uint64_t outParamUint = 1;
    struct HksParamOut outParam = { .tag = HKS_TAG_KEY_ACCESS_TIME, .uint64Param = &outParamUint };
    ret = HksAddParams(paramSet, &param, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &outParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest008
 * @tc.desc: tdd HksParamSetToParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest008()
{
    HKS_LOG_I("enter HksIpcSerializationTest008");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    struct HksParam param = { .tag = HKS_TAG_KEY_ACCESS_TIME ^ HKS_TAG_TYPE_ULONG, .uint64Param = 0 };
    uint64_t outParamUint = 1;
    struct HksParamOut outParam = { .tag = HKS_TAG_KEY_ACCESS_TIME ^ HKS_TAG_TYPE_ULONG, .uint64Param = &outParamUint };
    ret = HksAddParams(paramSet, &param, 1);
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &outParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest009
 * @tc.desc: tdd HksParamSetToParams, expect HKS_ERROR_PARAM_NOT_EXIST
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest009()
{
    HKS_LOG_I("enter HksIpcSerializationTest009");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    const char *alias = "alias";
    struct HksBlob aliasBlob = { .size = strlen(alias), .data = (uint8_t *)alias };
    struct HksParamOut aliasOutParam = { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = &aliasBlob };
    ret = HksBuildParamSet(&paramSet);
    ret = HksParamSetToParams(paramSet, &aliasOutParam, 1);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest010
 * @tc.desc: tdd GetBlobFromBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest010()
{
    HKS_LOG_I("enter HksIpcSerializationTest010");
    const uint32_t blobSize = 15;
    const uint32_t srcBlobSize = 15;
    uint32_t index = 16;
    uint8_t blobData[blobSize] = { 0 };
    uint8_t srcBlobData[srcBlobSize] = { 0 };
    struct HksBlob blob = { .size = blobSize, .data = blobData };
    struct HksBlob srcBlob = { .size = srcBlobSize, .data = srcBlobData };

    GetBlobFromBuffer(&blob, &srcBlob, &index);
}

/**
 * @tc.name: HksIpcSerializationTest.HksIpcSerializationTest011
 * @tc.desc: tdd GetBlobFromBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
static void HksIpcSerializationTest011()
{
    HKS_LOG_I("enter HksIpcSerializationTest011");
    const uint32_t blobSize = 15;
    const uint32_t srcBlobSize = 15;
    uint32_t index = 15;
    uint8_t blobData[blobSize] = { 0 };
    uint8_t srcBlobData[srcBlobSize] = { 0 };
    struct HksBlob blob = { .size = blobSize, .data = blobData };
    struct HksBlob srcBlob = { .size = srcBlobSize, .data = srcBlobData };

    GetBlobFromBuffer(&blob, &srcBlob, &index);
}
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    OHOS::Security::Hks::HksIpcSerializationTest001();
    OHOS::Security::Hks::HksIpcSerializationTest002();
    OHOS::Security::Hks::HksIpcSerializationTest003();
    OHOS::Security::Hks::HksIpcSerializationTest004();
    OHOS::Security::Hks::HksIpcSerializationTest005();
    OHOS::Security::Hks::HksIpcSerializationTest006();
    OHOS::Security::Hks::HksIpcSerializationTest007();
    OHOS::Security::Hks::HksIpcSerializationTest008();
    OHOS::Security::Hks::HksIpcSerializationTest009();
    OHOS::Security::Hks::HksIpcSerializationTest010();
    OHOS::Security::Hks::HksIpcSerializationTest011();
    return 0;
}
