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

#ifndef HKS_PLUGIN_MANAGER_TEST_H
#define HKS_PLUGIN_MANAGER_TEST_H

#include "hks_lib_interface.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_funtion_"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace OHOS {
namespace Security {
namespace Huks {
    
class ExtensionPluginMgrTest : public testing::Test {
protected:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<HuksExtensionPluginManager> pluginManager_;
    HksProcessInfo info_;
    std::string providerName_;
    CppParamSet paramSet_;
};

class MockHuksPluginLoader {
public:
    MOCK_METHOD(int32_t, Start, (struct HksProcessInfo &, const std::string&, const CppParamSet&));
    MOCK_METHOD(int32_t, Stop, (struct HksProcessInfo &, const std::string&, const CppParamSet&));
    
};

extern "C" {
void* __real_dlopen(const char* filename, int flags);
void* __wrap_dlopen(const char* filename, int flags) {
    return reinterpret_cast<void*>(0x12345);
}

void* __wrap_dlsym(void* handle, const char* symbol) {
    static int32_t dummy_func() { return HKS_SUCCESS; }
    return reinterpret_cast<void*>(&dummy_func);
}
}



}
}
}

#endif