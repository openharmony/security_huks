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

#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_ukey_session_manager.h"
#include "hks_remote_handle_manager.h"
#include "hks_mock_common.h"
#include "hks_type.h"
#include "gtest/gtest.h"
#include <vector>
#include "hks_ukey_common.h"
#include "hks_log.h"
#include "token_setproc.h"
#include "hks_json_wrapper.h"
#include "hks_provider_life_cycle_manager.h"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

static const std::string TEST_BUNDLE_NAME = "com.huawei.extensionhap.test";
static const std::string TEST_ABILITY_NAME = "HiTaiCryptoAbility";
static const std::string TEST_PROVIDER_NAME = "SessionMgrFullTest";

static uint64_t g_shellTokenId = 0;
class HksSessionMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksSessionMgrTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksSessionMgrTest::TearDownTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::ResetTestEvironment();
}

void HksSessionMgrTest::SetUp()
{}

void HksSessionMgrTest::TearDown() {
}

static std::string BuildWrappedIndex(const std::string &providerName, const HksProcessInfo &processInfo)
{
    CommJsonObject root = CommJsonObject::CreateObject();
    (void)root.SetValue("providerName", providerName);
    (void)root.SetValue("abilityName", std::string(TEST_ABILITY_NAME));
    (void)root.SetValue("bundleName", std::string(TEST_BUNDLE_NAME));
    (void)root.SetValue("userid", processInfo.userIdInt);
    (void)root.SetValue("index", providerName);
    return root.Serialize(false);
}

static int32_t SetupFullTest(HksProcessInfo &processInfo, std::string &wrappedIndex,
    uint32_t &outHandle, std::shared_ptr<HksMockHapToken> &mockToken)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    mockToken = std::make_shared<HksMockHapToken>(TEST_BUNDLE_NAME, reqPerm, true);

    HksGetProcessInfoForIPC(&processInfo);

    std::vector<HksParam> regParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet regParamSet(regParams);

    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    int32_t ret = providerMgr->OnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet,
        [](HksProcessInfo) {});
    if (ret != HKS_SUCCESS) {
        HKS_FREE_BLOB(processInfo.userId);
        HKS_FREE_BLOB(processInfo.processName);
        return ret;
    }

    wrappedIndex = BuildWrappedIndex(TEST_PROVIDER_NAME, processInfo);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    ret = handleMgr->CreateRemoteHandle(processInfo, wrappedIndex, regParamSet);
    if (ret != HKS_SUCCESS) {
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet, false, deleteCount);
        HKS_FREE_BLOB(processInfo.userId);
        HKS_FREE_BLOB(processInfo.processName);
        return ret;
    }

    std::vector<HksParam> initParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet initPs(initParams);

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, initPs, outHandle);
    if (ret != HKS_SUCCESS) {
        handleMgr->CloseRemoteHandle(processInfo, wrappedIndex, regParamSet);
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet, false, deleteCount);
        HKS_FREE_BLOB(processInfo.userId);
        HKS_FREE_BLOB(processInfo.processName);
        return ret;
    }
    return HKS_SUCCESS;
}

static void CleanupFullTest(HksProcessInfo &processInfo, const std::string &wrappedIndex)
{
    std::vector<HksParam> regParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
    };
    CppParamSet regParamSet(regParams);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    (void)handleMgr->CloseRemoteHandle(processInfo, wrappedIndex, regParamSet);

    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    int32_t deleteCount = 0;
    (void)providerMgr->OnUnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet, false, deleteCount);

    HksSessionManager::ReleaseInstance();

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

// ========== Existing tests (001-003) ==========

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest001
* @tc.desc: GetInstanceWrapper / ReleaseInstance.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest001, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    sessionMgr->ReleaseInstance();
}

HWTEST_F(HksSessionMgrTest, HksSessionMgrTest002, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr)  << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
    };
    CppParamSet paramSet(params);
    std::string providerName = "HksSessionMgrTest002";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    uint32_t handle = 0;
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("HksSessionMgrTest002")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("HiTaiCryptoAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.huawei.extensionhap.test")));
    EXPECT_TRUE(root.SetValue("userid", processInfo.userIdInt));
    EXPECT_TRUE(root.SetValue("index", std::string("parse_original_index")));
    std::string wrappedIndex = root.Serialize(false);

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, paramSet, handle);
    EXPECT_NE(ret, HKS_SUCCESS) << "ExtensionInitSession failed";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

HWTEST_F(HksSessionMgrTest, HksSessionMgrTest003, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr)  << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        { .tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet paramSet(params);
    std::string providerName = "HksSessionMgrTest003";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    uint32_t handle = 0;
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("HksSessionMgrTest003")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("HiTaiCryptoAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.huawei.extensionhap.test")));
    EXPECT_TRUE(root.SetValue("userid", processInfo.userIdInt));
    EXPECT_TRUE(root.SetValue("index", std::string("HksSessionMgrTest003")));
    std::string wrappedIndex = root.Serialize(false);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(handleMgr, nullptr);
    ret = handleMgr->CreateRemoteHandle(processInfo, wrappedIndex, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "CreateRemoteHandle failed";

    int32_t authState{1};
    uint32_t retryCount{0};
    ret = handleMgr->RemoteVerifyPin(processInfo, wrappedIndex, paramSet, authState, retryCount);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "RemoteVerifyPin failed";

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, paramSet, handle);
    EXPECT_EQ(ret, HKS_ERROR_PIN_NO_AUTH) << "ExtensionInitSession failed";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

// ========== New tests ==========

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest004
* @tc.desc: ExtensionUpdateSession - handle not exist.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest004, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo processInfo{};
    processInfo.uidInt = 99999;
    CppParamSet paramSet;
    std::vector<uint8_t> inData, outData;
    uint32_t handle = 12345;

    int32_t ret = sessionMgr->ExtensionUpdateSession(processInfo, handle, paramSet, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest005
* @tc.desc: ExtensionFinishSession - handle not exist.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest005, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo processInfo{};
    processInfo.uidInt = 99999;
    CppParamSet paramSet;
    std::vector<uint8_t> inData, outData;
    uint32_t handle = 12345;

    int32_t ret = sessionMgr->ExtensionFinishSession(processInfo, handle, paramSet, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest006
* @tc.desc: ExtensionAbortSession - handle not exist.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest006, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo processInfo{};
    processInfo.uidInt = 99999;
    CppParamSet paramSet;
    uint32_t handle = 12345;

    int32_t ret = sessionMgr->ExtensionAbortSession(processInfo, handle, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest007
* @tc.desc: ExtensionInitSession success with ENCRYPT purpose (no auth check needed).
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest007, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    EXPECT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";
    EXPECT_NE(outHandle, 0u) << "session handle should not be zero";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest008
* @tc.desc: ExtensionUpdateSession success.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest008, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    std::vector<HksParam> updateParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet updatePs(updateParams);
    std::vector<uint8_t> inData = {0x01, 0x02, 0x03};
    std::vector<uint8_t> outData;

    ret = sessionMgr->ExtensionUpdateSession(processInfo, outHandle, updatePs, inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExtensionUpdateSession failed";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest009
* @tc.desc: ExtensionFinishSession success.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest009, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    std::vector<HksParam> finishParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet finishPs(finishParams);
    std::vector<uint8_t> inData, outData;

    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExtensionFinishSession failed";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest010
* @tc.desc: ExtensionAbortSession success.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest010, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    std::vector<HksParam> abortParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet abortPs(abortParams);

    ret = sessionMgr->ExtensionAbortSession(processInfo, outHandle, abortPs);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExtensionAbortSession failed";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest011
* @tc.desc: ExtensionUpdateSession - uid mismatch (handle exists but uid differs).
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest011, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo otherInfo{};
    otherInfo.uidInt = processInfo.uidInt + 10000;
    CppParamSet updatePs;
    std::vector<uint8_t> inData, outData;

    ret = sessionMgr->ExtensionUpdateSession(otherInfo, outHandle, updatePs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "uid mismatch should return NOT_EXIST";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest012
* @tc.desc: CheckAndAppendProcessInfo - no UID tag in paramSet.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest012, TestSize.Level0) {
    HksProcessInfo processInfo{};
    processInfo.uidInt = 12345;

    std::vector<HksParam> tmpParams = {
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
    };
    CppParamSet paramSet(tmpParams);

    bool result = CheckAndAppendProcessInfo(paramSet, processInfo);
    EXPECT_TRUE(result) << "should succeed when UID tag is absent";
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest013
* @tc.desc: CheckAndAppendProcessInfo - UID tag matches runtime uid.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest013, TestSize.Level0) {
    HksProcessInfo processInfo{};
    processInfo.uidInt = 12345;

    std::vector<HksParam> tmpParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 12345},
    };
    CppParamSet paramSet(tmpParams);

    bool result = CheckAndAppendProcessInfo(paramSet, processInfo);
    EXPECT_TRUE(result) << "should succeed when UID matches";
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest014
* @tc.desc: CheckAndAppendProcessInfo - UID tag mismatch.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest014, TestSize.Level0) {
    HksProcessInfo processInfo{};
    processInfo.uidInt = 12345;

    std::vector<HksParam> tmpParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 99999},
    };
    CppParamSet paramSet(tmpParams);

    bool result = CheckAndAppendProcessInfo(paramSet, processInfo);
    EXPECT_FALSE(result) << "should fail when UID does not match";
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest015
* @tc.desc: ClearSessionMapByHandle - CRYPTO_FAIL erases handle.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest015, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    sessionMgr->ClearSessionMapByHandle(HUKS_ERR_CODE_CRYPTO_FAIL, outHandle);

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been erased";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest016
* @tc.desc: ClearSessionMapByHandle - ITEM_NOT_EXIST erases handle.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest016, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    sessionMgr->ClearSessionMapByHandle(HUKS_ERR_CODE_ITEM_NOT_EXIST, outHandle);

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been erased";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest017
* @tc.desc: ClearSessionMapByHandle - other error code does NOT erase handle.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest017, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    sessionMgr->ClearSessionMapByHandle(HKS_SUCCESS, outHandle);

    std::vector<HksParam> abortParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet abortPs(abortParams);
    ret = sessionMgr->ExtensionAbortSession(processInfo, outHandle, abortPs);
    EXPECT_EQ(ret, HKS_SUCCESS) << "handle should still exist and abort should succeed";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest018
* @tc.desc: HksClearHandle(processInfo, paramSet) - clear all handles by uid.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest018, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    CppParamSet clearPs;
    bool result = sessionMgr->HksClearHandle(processInfo, clearPs);
    EXPECT_TRUE(result) << "HksClearHandle should return true";

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest019
* @tc.desc: HksClearHandle(processInfo, paramSet) - clear with abilityName.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest019, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    std::vector<HksParam> clearParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
    };
    CppParamSet clearPs(clearParams);
    bool result = sessionMgr->HksClearHandle(processInfo, clearPs);
    EXPECT_TRUE(result) << "HksClearHandle should return true";

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest020
* @tc.desc: HksClearHandle(processInfo, paramSet) - abilityName too long returns false.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest020, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo processInfo{};
    processInfo.uidInt = 12345;

    std::string longName(128, 'A');
    std::vector<HksParam> clearParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(longName)},
    };
    CppParamSet clearPs(clearParams);

    bool result = sessionMgr->HksClearHandle(processInfo, clearPs);
    EXPECT_FALSE(result) << "should return false when abilityName is too long";
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest021
* @tc.desc: HksClearHandle(providerInfo) - clear by provider info.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest021, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    ProviderInfo providerInfo{};
    providerInfo.m_providerName = TEST_PROVIDER_NAME;
    providerInfo.m_abilityName = TEST_ABILITY_NAME;
    providerInfo.m_bundleName = TEST_BUNDLE_NAME;
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);

    sessionMgr->HksClearHandle(providerInfo);

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared by providerInfo";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest022
* @tc.desc: HksClearHandle(processInfo, paramSet, index) - clear by index with abilityName.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest022, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    std::vector<HksParam> clearParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
    };
    CppParamSet clearPs(clearParams);
    bool result = sessionMgr->HksClearHandle(processInfo, clearPs, wrappedIndex);
    EXPECT_TRUE(result) << "HksClearHandle with index should return true";

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest023
* @tc.desc: HksClearHandle(processInfo, paramSet, index) - clear by index without abilityName.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest023, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    CppParamSet clearPs;
    bool result = sessionMgr->HksClearHandle(processInfo, clearPs, wrappedIndex);
    EXPECT_TRUE(result) << "HksClearHandle with index (no abilityName) should return true";

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest024
* @tc.desc: HksClearHandle(processInfo, paramSet, index) - abilityName too long returns false.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest024, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    HksProcessInfo processInfo{};
    processInfo.uidInt = 12345;

    std::string longName(128, 'B');
    std::vector<HksParam> clearParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(longName)},
    };
    CppParamSet clearPs(clearParams);
    bool result = sessionMgr->HksClearHandle(processInfo, clearPs, "some_index");
    EXPECT_FALSE(result) << "should return false when abilityName is too long";
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest025
* @tc.desc: ExtensionInitSession - missing purpose tag returns error.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest025, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    mockToken = std::make_shared<HksMockHapToken>(TEST_BUNDLE_NAME, reqPerm, true);

    HksGetProcessInfoForIPC(&processInfo);

    std::vector<HksParam> regParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet regParamSet(regParams);

    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    int32_t ret = providerMgr->OnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet,
        [](HksProcessInfo) {});
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    wrappedIndex = BuildWrappedIndex(TEST_PROVIDER_NAME, processInfo);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    ret = handleMgr->CreateRemoteHandle(processInfo, wrappedIndex, regParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS) << "CreateRemoteHandle failed";

    std::vector<HksParam> noPurposeParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet noPurposePs(noPurposeParams);

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, noPurposePs, outHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "missing purpose tag should fail";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest026
* @tc.desc: HksClearHandle(providerInfo) - non-matching provider info clears nothing.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest026, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    ProviderInfo providerInfo{};
    providerInfo.m_providerName = "NonExistentProvider";
    providerInfo.m_abilityName = "NonExistentAbility";
    providerInfo.m_bundleName = "non.existent.bundle";
    providerInfo.m_userid = 0;

    sessionMgr->HksClearHandle(providerInfo);

    std::vector<HksParam> abortParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet abortPs(abortParams);
    ret = sessionMgr->ExtensionAbortSession(processInfo, outHandle, abortPs);
    EXPECT_EQ(ret, HKS_SUCCESS) << "handle should still exist after non-matching clear";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest027
* @tc.desc: HksClearHandle(providerInfo) - empty abilityName matches all abilities.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest027, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    int32_t ret = SetupFullTest(processInfo, wrappedIndex, outHandle, mockToken);
    ASSERT_EQ(ret, HKS_SUCCESS) << "SetupFullTest failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    ProviderInfo providerInfo{};
    providerInfo.m_providerName = TEST_PROVIDER_NAME;
    providerInfo.m_abilityName = "";
    providerInfo.m_bundleName = TEST_BUNDLE_NAME;
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);

    sessionMgr->HksClearHandle(providerInfo);

    CppParamSet finishPs;
    std::vector<uint8_t> inData, outData;
    ret = sessionMgr->ExtensionFinishSession(processInfo, outHandle, finishPs, inData, outData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "handle should have been cleared with empty abilityName";

    CleanupFullTest(processInfo, wrappedIndex);
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest028
* @tc.desc: ExtensionInitSession with purpose=SIGN, auth state OK.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest028, TestSize.Level0) {
    HksProcessInfo processInfo{};
    std::string wrappedIndex;
    uint32_t outHandle = 0;
    std::shared_ptr<HksMockHapToken> mockToken;

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    mockToken = std::make_shared<HksMockHapToken>(TEST_BUNDLE_NAME, reqPerm, true);

    HksGetProcessInfoForIPC(&processInfo);

    std::vector<HksParam> regParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet regParamSet(regParams);

    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    int32_t ret = providerMgr->OnRegisterProvider(processInfo, TEST_PROVIDER_NAME, regParamSet,
        [](HksProcessInfo) {});
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    wrappedIndex = BuildWrappedIndex(TEST_PROVIDER_NAME, processInfo);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    ret = handleMgr->CreateRemoteHandle(processInfo, wrappedIndex, regParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS) << "CreateRemoteHandle failed";

    std::vector<HksParam> pinParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
        {.tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN, .blob = StringToBlob("123456")},
    };
    CppParamSet pinParamSet(pinParams);
    int32_t authState{0};
    uint32_t retryCount{0};
    ret = handleMgr->RemoteVerifyPin(processInfo, wrappedIndex, pinParamSet, authState, retryCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "RemoteVerifyPin should succeed";

    std::vector<HksParam> signParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(TEST_ABILITY_NAME)},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet signPs(signParams);

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    ASSERT_NE(sessionMgr, nullptr);

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, signPs, outHandle);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExtensionInitSession with SIGN and auth OK should succeed";
    EXPECT_NE(outHandle, 0u) << "session handle should not be zero";

    CleanupFullTest(processInfo, wrappedIndex);
}
}
}
}
