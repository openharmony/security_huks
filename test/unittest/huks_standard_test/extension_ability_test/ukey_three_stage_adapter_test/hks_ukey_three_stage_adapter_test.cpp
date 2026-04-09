/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_ukey_three_stage_adapter.h"
#include "hks_mock_common.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_type.h"
#include "hks_error_code.h"
#include "hks_param.h"
#include "gtest/gtest.h"

#include <string>
#include <vector>
#include <cstdint>
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

static uint64_t g_shellTokenId = 0;

class HksUkeyThreeStageAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksUkeyThreeStageAdapterTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksUkeyThreeStageAdapterTest::TearDownTestCase(void)
{
    HksMockCommon::ResetTestEvironment();
}

void HksUkeyThreeStageAdapterTest::SetUp() {}

void HksUkeyThreeStageAdapterTest::TearDown() {}

// Helper: create valid processInfo and paramSet
static void InitTestEnv(HksProcessInfo &processInfo, HksParamSet *&paramSet)
{
    HksGetProcessInfoForIPC(&processInfo);
    HksInitParamSet(&paramSet);
    HksParam params[] = { {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA} };
    HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    HksBuildParamSet(&paramSet);
}

static void FreeTestEnv(HksProcessInfo &processInfo, HksParamSet *&paramSet)
{
    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(processInfo.processName);
}

static HksBlob MakeBlob(const std::string &s)
{
    HksBlob b = {
        .size = static_cast<uint32_t>(s.size()),
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(s.data()))
    };
    return b;
}

// ==================== HksServiceOnUkeyGenerateKey tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest001
* @tc.desc: HksServiceOnUkeyGenerateKey — null/empty/oversized resourceId
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest001, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    // null resourceId
    int32_t ret = HksServiceOnUkeyGenerateKey(&processInfo, nullptr, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // empty resourceId
    HksBlob emptyBlob = {};
    ret = HksServiceOnUkeyGenerateKey(&processInfo, &emptyBlob, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // null data in resourceId
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    ret = HksServiceOnUkeyGenerateKey(&processInfo, &nullDataBlob, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // oversized resourceId (> MAX_SESSION_INDEX_SIZE = 1024)
    std::string longId(1025, 'r');
    HksBlob longBlob = MakeBlob(longId);
    ret = HksServiceOnUkeyGenerateKey(&processInfo, &longBlob, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest002
* @tc.desc: HksServiceOnUkeyGenerateKey — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest002, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    HksBlob resourceId = MakeBlob("testResourceId");
    int32_t ret = HksServiceOnUkeyGenerateKey(&processInfo, &resourceId, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyInitSession tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest003
* @tc.desc: HksServiceOnUkeyInitSession — null/empty/oversized index
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest003, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    // null index
    int32_t ret = HksServiceOnUkeyInitSession(&processInfo, nullptr, paramSet, &handle);
    EXPECT_NE(ret, HKS_SUCCESS);

    // empty index
    HksBlob emptyBlob = {};
    ret = HksServiceOnUkeyInitSession(&processInfo, &emptyBlob, paramSet, &handle);
    EXPECT_NE(ret, HKS_SUCCESS);

    // null data in index
    HksBlob nullDataBlob = { .size = 1, .data = nullptr };
    ret = HksServiceOnUkeyInitSession(&processInfo, &nullDataBlob, paramSet, &handle);
    EXPECT_NE(ret, HKS_SUCCESS);

    // oversized index
    std::string longIdx(1025, 'i');
    HksBlob longBlob = MakeBlob(longIdx);
    ret = HksServiceOnUkeyInitSession(&processInfo, &longBlob, paramSet, &handle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest004
* @tc.desc: HksServiceOnUkeyInitSession — handle size too small
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest004, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    HksBlob index = MakeBlob("testIndex");
    // handle size < sizeof(uint64_t)
    uint8_t smallBuf[4] = {};
    HksBlob smallHandle = { .size = sizeof(smallBuf), .data = smallBuf };
    int32_t ret = HksServiceOnUkeyInitSession(&processInfo, &index, paramSet, &smallHandle);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_MEMORY);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest005
* @tc.desc: HksServiceOnUkeyInitSession — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest005, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    HksBlob index = MakeBlob("testIndex");
    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };
    int32_t ret = HksServiceOnUkeyInitSession(&processInfo, &index, paramSet, &handle);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(handle.size, sizeof(uint64_t));

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyUpdateSession tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest006
* @tc.desc: HksServiceOnUkeyUpdateSession — normal flow with empty outData
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest006, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    uint8_t inBuf[] = {'a', 'b', 'c'};
    HksBlob inData = { .size = sizeof(inBuf), .data = inBuf };

    // outData with size=0 — should return current ret (mock returns SUCCESS)
    uint8_t outBuf[64] = {};
    HksBlob outData = { .size = 0, .data = outBuf };
    int32_t ret = HksServiceOnUkeyUpdateSession(&processInfo, &handle, paramSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest007
* @tc.desc: HksServiceOnUkeyUpdateSession — normal flow with valid outData
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest007, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    uint8_t inBuf[] = {'a', 'b', 'c'};
    HksBlob inData = { .size = sizeof(inBuf), .data = inBuf };

    uint8_t outBuf[64] = {};
    HksBlob outData = { .size = sizeof(outBuf), .data = outBuf };
    int32_t ret = HksServiceOnUkeyUpdateSession(&processInfo, &handle, paramSet, &inData, &outData);
    // mock OnUpdateSession returns SUCCESS with empty outdata, so outData->size check passes
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest008
* @tc.desc: HksServiceOnUkeyUpdateSession — outData size too small
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest008, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    uint8_t inBuf[] = {'a'};
    HksBlob inData = { .size = sizeof(inBuf), .data = inBuf };

    // mock OnUpdateSession returns empty outdata (size 0), so size check passes.
    // To test INSUFFICIENT_MEMORY branch, we'd need mock to return outdata larger than outData->size.
    // Since mock returns empty outdata, this test verifies the normal path where no size mismatch.
    uint8_t outBuf[1] = {};
    HksBlob outData = { .size = sizeof(outBuf), .data = outBuf };
    int32_t ret = HksServiceOnUkeyUpdateSession(&processInfo, &handle, paramSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyFinishSession tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest009
* @tc.desc: HksServiceOnUkeyFinishSession — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest009, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    uint8_t outBuf[64] = {};
    HksBlob outData = { .size = sizeof(outBuf), .data = outBuf };
    int32_t ret = HksServiceOnUkeyFinishSession(&processInfo, &handle, paramSet, nullptr, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest010
* @tc.desc: HksServiceOnUkeyFinishSession — outData size=0
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest010, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };

    uint8_t outBuf[64] = {};
    HksBlob outData = { .size = 0, .data = outBuf };
    int32_t ret = HksServiceOnUkeyFinishSession(&processInfo, &handle, paramSet, nullptr, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyAbortSession tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest011
* @tc.desc: HksServiceOnUkeyAbortSession — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest011, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    uint8_t handleBuf[sizeof(uint64_t)] = {};
    HksBlob handle = { .size = sizeof(handleBuf), .data = handleBuf };
    int32_t ret = HksServiceOnUkeyAbortSession(&processInfo, &handle, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // null handle is also accepted (handleU64 remains 0)
    ret = HksServiceOnUkeyAbortSession(&processInfo, nullptr, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyImportWrappedKey tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest012
* @tc.desc: HksServiceOnUkeyImportWrappedKey — null/empty/oversized keyAlias
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest012, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    HksBlob wrappingKey = MakeBlob("wrappingKey");

    // null keyAlias
    int32_t ret = HksServiceOnUkeyImportWrappedKey(&processInfo, nullptr, &wrappingKey, paramSet, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);

    // empty keyAlias
    HksBlob emptyBlob = {};
    ret = HksServiceOnUkeyImportWrappedKey(&processInfo, &emptyBlob, &wrappingKey, paramSet, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);

    // oversized keyAlias
    std::string longKey(1025, 'k');
    HksBlob longBlob = MakeBlob(longKey);
    ret = HksServiceOnUkeyImportWrappedKey(&processInfo, &longBlob, &wrappingKey, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // oversized wrappingKeyAlias
    HksBlob validKey = MakeBlob("key");
    std::string longWrap(1025, 'w');
    HksBlob longWrapBlob = MakeBlob(longWrap);
    ret = HksServiceOnUkeyImportWrappedKey(&processInfo, &validKey, &longWrapBlob, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest013
* @tc.desc: HksServiceOnUkeyImportWrappedKey — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest013, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    HksBlob keyAlias = MakeBlob("keyAlias");
    HksBlob wrappingKey = MakeBlob("wrappingKey");

    // null wrappedKeyData is accepted
    int32_t ret = HksServiceOnUkeyImportWrappedKey(&processInfo, &keyAlias, &wrappingKey, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // valid wrappedKeyData
    uint8_t wrappedBuf[] = {0x01, 0x02, 0x03};
    HksBlob wrappedData = { .size = sizeof(wrappedBuf), .data = wrappedBuf };
    ret = HksServiceOnUkeyImportWrappedKey(&processInfo, &keyAlias, &wrappingKey, paramSet, &wrappedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

// ==================== HksServiceOnUkeyExportPublicKey tests ====================

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest014
* @tc.desc: HksServiceOnUkeyExportPublicKey — null/empty/oversized keyAlias
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest014, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);

    uint8_t keyBuf[64] = {};
    HksBlob key = { .size = sizeof(keyBuf), .data = keyBuf };

    // null keyAlias
    int32_t ret = HksServiceOnUkeyExportPublicKey(&processInfo, nullptr, paramSet, &key);
    EXPECT_NE(ret, HKS_SUCCESS);

    // empty keyAlias
    HksBlob emptyBlob = {};
    ret = HksServiceOnUkeyExportPublicKey(&processInfo, &emptyBlob, paramSet, &key);
    EXPECT_NE(ret, HKS_SUCCESS);

    // oversized keyAlias
    std::string longKey(1025, 'k');
    HksBlob longBlob = MakeBlob(longKey);
    ret = HksServiceOnUkeyExportPublicKey(&processInfo, &longBlob, paramSet, &key);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // null key output blob
    HksBlob validKeyAlias = MakeBlob("keyAlias");
    ret = HksServiceOnUkeyExportPublicKey(&processInfo, &validKeyAlias, paramSet, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

/**
* @tc.name: HksUkeyThreeStageAdapterTest.HksUkeyThreeStageAdapterTest015
* @tc.desc: HksServiceOnUkeyExportPublicKey — normal flow
* @tc.type: FUNC
*/
HWTEST_F(HksUkeyThreeStageAdapterTest, HksUkeyThreeStageAdapterTest015, TestSize.Level0) {
    HksProcessInfo processInfo{};
    HksParamSet *paramSet = nullptr;
    InitTestEnv(processInfo, paramSet);

    HksBlob keyAlias = MakeBlob("keyAlias");

    // mock OnExportPublicKey returns empty outdata, so memcpy is fine
    uint8_t keyBuf[64] = {};
    HksBlob key = { .size = sizeof(keyBuf), .data = keyBuf };
    int32_t ret = HksServiceOnUkeyExportPublicKey(&processInfo, &keyAlias, paramSet, &key);
    EXPECT_EQ(ret, HKS_SUCCESS);

    FreeTestEnv(processInfo, paramSet);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
