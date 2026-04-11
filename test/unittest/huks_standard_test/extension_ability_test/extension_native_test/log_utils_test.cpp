/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include "log_utils.h"

using namespace testing;
using namespace testing::ext;

class LogUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(LogUtilsTest, LogPrint_0000, testing::ext::TestSize.Level0)
{
    LogPrint(LOG_LEVEL_DEBUG, "TestFunc", "test debug message %d", 1);
    LogPrint(LOG_LEVEL_INFO, "TestFunc", "test info message %s", "hello");
    LogPrint(LOG_LEVEL_WARN, "TestFunc", "test warn message");
    LogPrint(LOG_LEVEL_ERROR, "TestFunc", "test error message %d %s", 42, "world");
}

HWTEST_F(LogUtilsTest, LogPrint_0001, testing::ext::TestSize.Level0)
{
    CryptogLevel invalidLevel = static_cast<CryptogLevel>(99);
    LogPrint(invalidLevel, "TestFunc", "invalid level message");
}

HWTEST_F(LogUtilsTest, LogPrint_0002, testing::ext::TestSize.Level0)
{
    LogPrint(LOG_LEVEL_DEBUG, "TestFunc", "%s", std::string(900, 'A').c_str());
}

HWTEST_F(LogUtilsTest, LOGD_Test, testing::ext::TestSize.Level0)
{
    LOGD("debug macro test %d", 100);
    LOGI("info macro test");
    LOGW("warn macro test %s", "param");
    LOGE("error macro test %d %d", 1, 2);
}
