/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_xcollie.h"
#include "hks_log.h"
#include "hks_mem.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Hks {
namespace HksXCollieTest {

class HksXCollieTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksXCollieTest::SetUpTestCase(void)
{
}

void HksXCollieTest::TearDownTestCase(void)
{
}

void HksXCollieTest::SetUp()
{
}

void HksXCollieTest::TearDown()
{
}

HWTEST_F(HksXCollieTest, HksXCollieTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest001 - basic construction");
    std::string tag = "test_tag_001";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest002 - manual cancel");
    std::string tag = "test_tag_002";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);
    hksXCollie.CancelHksXCollie();
    hksXCollie.CancelHksXCollie();

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest003 - with callback");
    std::string tag = "test_tag_003";
    uint32_t timeoutSeconds = 10;
    
    auto callback = [](void *arg) {
        HKS_LOG_I("timeout callback triggered");
    };
    
    HksXCollie hksXCollie(tag, timeoutSeconds, callback, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest004 - destructor auto cancel");
    std::string tag = "test_tag_004";
    uint32_t timeoutSeconds = 5;
    
    {
        HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);
        HKS_LOG_I("HksXCollie created, will be destroyed on scope exit");
    }
    HKS_LOG_I("HksXCollie destroyed");

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest005 - empty tag");
    std::string tag = "";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest006 - zero timeout");
    std::string tag = "test_tag_006";
    uint32_t timeoutSeconds = 0;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest007 - large timeout");
    std::string tag = "test_tag_007";
    uint32_t timeoutSeconds = 120;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest008 - callback with argument");
    std::string tag = "test_tag_008";
    uint32_t timeoutSeconds = 10;
    int testData = 12345;
    
    auto callback = [](void *arg) {
        if (arg != nullptr) {
            int *data = static_cast<int*>(arg);
            HKS_LOG_I("timeout callback triggered with data: %d", *data);
        }
    };
    
    HksXCollie hksXCollie(tag, timeoutSeconds, callback, &testData, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest009 - with flag");
    std::string tag = "test_tag_009";
    uint32_t timeoutSeconds = 5;
    uint32_t flag = HiviewDFX::XCOLLIE_FLAG_LOG;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, flag);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest010 - multiple instances");
    std::string tag1 = "test_tag_010_a";
    std::string tag2 = "test_tag_010_b";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie1(tag1, timeoutSeconds, nullptr, nullptr, 0);
    HksXCollie hksXCollie2(tag2, timeoutSeconds, nullptr, nullptr, 0);
    
    hksXCollie1.CancelHksXCollie();

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest011 - default parameters");
    std::string tag = "test_tag_011";
    
    HksXCollie hksXCollie(tag);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest012 - cancel before destroy");
    std::string tag = "test_tag_012";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie *hksXCollie = new HksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);
    hksXCollie->CancelHksXCollie();
    delete hksXCollie;

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest013 - long tag name");
    std::string tag = "test_tag_013_this_is_a_very_long_tag_name_to_test_string_handling";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest014 - special characters in tag");
    std::string tag = "test_tag_014:special/chars:test";
    uint32_t timeoutSeconds = 5;
    
    HksXCollie hksXCollie(tag, timeoutSeconds, nullptr, nullptr, 0);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksXCollieTest, HksXCollieTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksXCollieTest015 - rapid create destroy cycle");
    for (int i = 0; i < 10; i++) {
        std::string tag = "test_tag_015_" + std::to_string(i);
        HksXCollie hksXCollie(tag, 1, nullptr, nullptr, 0);
    }

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

}
}
}
}