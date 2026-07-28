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

#include "hks_osaccount_check.h"
#include "hks_log.h"
#include "hks_type.h"
#include "hks_mem.h"

using namespace testing::ext;

namespace Unittest::HksOsAccountCheckTest {

class HksOsAccountCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksOsAccountCheckTest::SetUpTestCase(void)
{
}

void HksOsAccountCheckTest::TearDownTestCase(void)
{
}

void HksOsAccountCheckTest::SetUp()
{
}

void HksOsAccountCheckTest::TearDown()
{
}

#ifdef L2_STANDARD
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest001 - basic call");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest002 - different storage level");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_DE;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest003 - ECE storage level");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_ECE;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest004 - different user ID");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    int32_t storeUserId = 0;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest005 - negative user ID");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    int32_t storeUserId = -1;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest006 - multiple calls");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);
    HksTransferFileIfNeed(storageLevel, storeUserId);
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest007 - mixed storage levels");
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(HKS_AUTH_STORAGE_LEVEL_CE, storeUserId);
    HksTransferFileIfNeed(HKS_AUTH_STORAGE_LEVEL_DE, storeUserId);
    HksTransferFileIfNeed(HKS_AUTH_STORAGE_LEVEL_ECE, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest008 - large user ID");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    int32_t storeUserId = 1000000;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest009 - boundary storage level");
    uint32_t storageLevel = 0;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest010 - boundary storage level 2");
    uint32_t storageLevel = UINT32_MAX;
    int32_t storeUserId = 100;
    
    HksTransferFileIfNeed(storageLevel, storeUserId);

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

HWTEST_F(HksOsAccountCheckTest, HksOsAccountCheckTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksOsAccountCheckTest011 - sequence of calls");
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_CE;
    
    for (int32_t userId = 0; userId < 5; userId++) {
        HksTransferFileIfNeed(storageLevel, userId);
    }

    void* ptr = HksMalloc(1);
    EXPECT_NE(ptr, nullptr);
    HksFreeImpl(ptr);
}

#endif // HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#endif // L2_STANDARD

}