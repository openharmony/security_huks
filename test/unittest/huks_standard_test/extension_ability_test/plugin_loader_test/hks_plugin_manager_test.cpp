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

#include "hks_plugin_manager_test.h"
#include "hks_function_types.h"
#include <unordered_map>

using namespace testing::ext;

const std::string TEST_PROVIDER = "testProvider";

namespace OHOS {
namespace Security {
namespace Huks {
void ExtensionPluginMgrTest::SetUpTestCase(void) {
}

void ExtensionPluginMgrTest::TearDownTestCase(void) {
}

void ExtensionPluginMgrTest::SetUp() {
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

void ExtensionPluginMgrTest::TearDown() {
    HuksPluginLoader::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest001
 * @tc.desc: 第一次注册，动态库加载成功且注册函数执行成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest001, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string index = "";
    std::string handle = "";
    ret = mgr->OnCreateRemoteKeyHandle(processInfo, index, paramSet, handle);
    EXPECT_EQ(ret, 0) << "fail: OnCreateRemoteKeyHandle fail";

    ret = mgr->OnCloseRemoteKeyHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnCloseRemoteKeyHandle fail";

    int32_t authState = 0;
    uint32_t retryCnt = 0;
    ret = mgr->OnAuthUkeyPin(processInfo, index, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, 0) << "fail: OnAuthUkeyPin fail";

    int32_t state = 0;
    ret = mgr->OnGetVerifyPinStatus(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, 0) << "fail: OnGetVerifyPinStatus fail";

    ret = mgr->OnClearUkeyPinAuthStatus(processInfo, index);
    EXPECT_EQ(ret, 0) << "fail: OnClearUkeyPinAuthStatus fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, index, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: UnRegisterProvider is not fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest002
 * @tc.desc: 第二次调用注册函数，register函数执行成功;非最后一次调用解注册函数，且函数执行成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest002, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);
    
    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string TEST_PROVIDER2 = "testProvider2";
    ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER2, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER2, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest003
 * @tc.desc: 最后一次调用解注册函数，函数执行成功，且动态库关闭成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest003, TestSize.Level0)
{
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    std::vector<HksParam> g_genAesParams = {
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    CppParamSet paramSet(g_genAesParams);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    std::string propertyId = "";
    CppParamSet outParams(g_genAesParams);
    const std::string index = "";
    ret = mgr->OnGetRemoteProperty(processInfo, index, propertyId, paramSet, outParams);
    EXPECT_EQ(ret, 0) << "fail: OnGetRemoteProperty fail";

    std::string certsJson = "";
    ret = mgr->OnExportCertificate(processInfo, index, paramSet, certsJson);
    EXPECT_EQ(ret, 0) << "fail: OnExportCertificate fail";

    std::string certsJsonArr = "";
    ret = mgr->OnExportProviderAllCertificates(processInfo, TEST_PROVIDER, paramSet, certsJsonArr);
    EXPECT_EQ(ret, 0) << "fail: OnExportProviderAllCertificates fail";

    uint32_t uhandle = 0;
    ret = mgr->OnInitSession(processInfo, index, paramSet, uhandle);
    EXPECT_EQ(ret, 0) << "fail: OnInitSession fail";

    std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    ret = mgr->OnUpdateSession(processInfo, uhandle, paramSet, inData, outData);
    EXPECT_EQ(ret, 0) << "fail: OnUpdateSession fail";

    ret = mgr->OnFinishSession(processInfo, uhandle, paramSet, inData, outData);
    EXPECT_EQ(ret, 0) << "fail: OnUpdateSession fail";

    ret = mgr->OnAbortSession(processInfo, uhandle, paramSet);
    EXPECT_EQ(ret, 0) << "fail: OnAbortSession fail";

    bool isDeath = false;
    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet, isDeath);
    EXPECT_EQ(ret, HKS_ERROR_LIB_REPEAT_CLOSE) << "fail: unregist is not -298.";
}
}
}
}