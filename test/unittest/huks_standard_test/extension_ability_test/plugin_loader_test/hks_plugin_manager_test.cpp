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
    // 清空 provider map to ensure reproducible tests
    std::unordered_map<PluginMethodEnum, void*> empty;
    lib->initProviderMap(empty);
}

void ExtensionPluginMgrTest::TearDown() {
    HuksPluginLoader::ReleaseInstance();
    HuksLibInterface::ReleaseInstance();
    HuksPluginLifeCycleMgr::ReleaseInstance();
}

/*
    模拟dlopen返回的函数指针
    调用注册函数，且第一次加载动态库，且动态库加载成功，且register函数执行成功；
    第二次调用注册函数，打开动态库失败，且找不到函数对应string；
    第二次调用注册函数，打开动态库成功，但register函数执行失败；
    调用解注册函数，且函数执行成功，且是最后一次调用，且动态库关闭成功；非最后一次调用解注册函数，且函数执行失败
*/

/**
 * @tc.name: ExtensionPluginMgrTest.ExtensionPluginMgrTest001
 * @tc.desc: connect success.
 * @tc.type: FUNC
 */
HWTEST_F(ExtensionPluginMgrTest, ExtensionPluginMgrTest001, TestSize.Level10) {

}

}
}
}