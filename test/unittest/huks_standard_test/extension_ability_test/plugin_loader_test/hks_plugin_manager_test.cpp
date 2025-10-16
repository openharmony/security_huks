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
std::string PLUGIN_PATH_SUCCESS = "libfake_success.so";
std::string PLUGIN_PATH_FAIL = "libfake_fail.so";
std::string PLUGIN_PATH_NOT_EXIST = "not_exist.so";

namespace OHOS {
namespace Security {
namespace Huks {
void ExtensionPluginMgrTest::SetUpTestCase(void) {
}

void ExtensionPluginMgrTest::TearDownTestCase(void) {
}

void ExtensionPluginMgrTest::SetUp() {
    HuksPluginLoader::ReleaseInstance();
    HuksLibInterface::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

void ExtensionPluginMgrTest::TearDown() {
    HuksPluginLoader::ReleaseInstance();
    HuksLibInterface::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

/*
    模拟dlopen返回的函数指针
    1. 第一次调用注册函数，动态库加载成功，且register函数执行成功；
    2. 第一次调用注册函数，打开动态库失败；
    3. 第二次调用注册函数，register函数执行失败;非最后一次调用解注册函数，且函数执行失败；
    4. 最后一次调用解注册函数，函数执行成功，且动态库关闭成功；
*/

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest001
 * @tc.desc: 第一次注册，动态库加载成功且注册函数执行成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest001, TestSize.Level0) {
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    CppParamSet paramSet;
    auto plugionLoader = HuksPluginLoader::GetInstanceWrapper();
    plugionLoader->SetPluginPath(PLUGIN_PATH_SUCCESS);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest002
 * @tc.desc: 第一次注册，动态库打开失败
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest002, TestSize.Level0) {
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    CppParamSet paramSet;

    auto plugionLoader = HuksPluginLoader::GetInstanceWrapper();
    plugionLoader->SetPluginPath(PLUGIN_PATH_NOT_EXIST);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_OPEN_LIB_FAIL) << "fail: plugin path exist";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest003
 * @tc.desc: 第二次调用注册函数，register函数执行失败;非最后一次调用解注册函数，且函数执行失败
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest003, TestSize.Level0) {
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    CppParamSet paramSet;

    auto plugionLoader = HuksPluginLoader::GetInstanceWrapper();
    plugionLoader->SetPluginPath(PLUGIN_PATH_FAIL);

    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, -1) << "fail: regist success";

    std::string TEST_PROVIDER2 = "testProvider2";
    ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER2, paramSet);
    EXPECT_EQ(ret, -1) << "fail: regist success";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, -1) << "fail: unregist success";
}

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest003
 * @tc.desc: 最后一次调用解注册函数，函数执行成功，且动态库关闭成功
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest004, TestSize.Level0) {
    auto mgr = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HksProcessInfo processInfo {};
    CppParamSet paramSet;

    auto plugionLoader = HuksPluginLoader::GetInstanceWrapper();
    plugionLoader->SetPluginPath(PLUGIN_PATH_SUCCESS);
    int ret = mgr->RegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: regist fail";

    ret = mgr->UnRegisterProvider(processInfo, TEST_PROVIDER, paramSet);
    EXPECT_EQ(ret, 0) << "fail: unregist fail";
}
}
}
}