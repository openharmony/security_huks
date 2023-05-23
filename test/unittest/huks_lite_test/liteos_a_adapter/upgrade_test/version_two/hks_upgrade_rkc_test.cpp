/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "hks_upgrade_rkc_test.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"
#include "hks_rkc.h"
#include "hks_rkc_rw.c"
#include "hks_rkc_v1.c"

#include "cstring"
#include "unistd.h"
#include "securec.h"

using namespace testing::ext;
namespace HksUpgradeRkcTest {
class HksUpgradeRkcTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUpgradeRkcTest::SetUpTestCase(void)
{
}

void HksUpgradeRkcTest::TearDownTestCase(void)
{
}

void HksUpgradeRkcTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksUpgradeRkcTest::TearDown()
{
}

static void TestGetMkFromOldKsfFile(const HksBlob *oldKsfBlob, const uint8_t mkPlaintext[HKS_RKC_MK_LEN])
{
    // step1. parse old ksf file
    struct HksRkcKsfDataV1 ksfDataV1 = { 0 };
    int32_t ret = RkcExtractKsfBufV1(&oldKsfBlob, &ksfDataV1);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step1. decrypt mk
    struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, GetMkWithMask() };
    struct HksBlob cipherTextBlob = { sizeof(ksfDataV1.ksfDataMk.mkCiphertext), ksfDataV1.ksfDataMk.mkCiphertext };
    ret = RkcMkCryptV1(&ksfDataV1, &tempMkBlob, &cipherTextBlob, false);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(0, HksMemCmp(mkPlaintext, GetMkWithMask(), HKS_RKC_MK_LEN));
}

static void TestStoreNewKsfFile(HksBlob *rkcBlob, HksBlob *mkBlob)
{
    // step3. create new rkc material
    struct HksKsfDataRkcWithVer *newRkc = CreateNewKsfDataRkcWithVer();
    ASSERT_NE(HKS_NULL_POINTER, newRkc);

    // step4. encrypt mk with new rkc
    struct HksKsfDataMkWithVer *newMk = CreateNewKsfDataMkWithVer();
    ASSERT_NE(HKS_NULL_POINTER, newMk);

    struct HksBlob cipherTextBlob = { sizeof(newMk->ksfDataMk.mkCiphertext), newMk->ksfDataMk.mkCiphertext };
    int32_t ret = RkcMkCrypt(&(newRkc->ksfDataRkc), &(newMk->ksfDataMk), &tempMkBlob, &cipherTextBlob, true);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step5. store new rkc and mk file
    ret = FillKsfBufRkc(newRkc, rkcBlob);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = FillKsfBufMk(newMk, mkBlob);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HKS_MEMSET_FREE_PTR(newRkc, sizeof(struct HksKsfDataRkcWithVer));
    HKS_MEMSET_FREE_PTR(newMk, sizeof(struct HksKsfDataMkWithVer));
}

static void TestGetMkFromNewKsfFile(const HksBlob *rkcBlob, const HksBlob *mkBlob,
    const uint8_t mkPlaintext[HKS_RKC_MK_LEN])
{
    // step6. read new rkc and mk file
    struct HksKsfDataRkcWithVer newRkc = { 0 };
    int32_t ret = ExtractKsfBufRkc(rkcBlob, &newRkc);
    ASSERT_EQ(HKS_SUCCESS, ret);

    struct HksKsfDataMkWithVer newMk = { 0 };
    ret = ExtractKsfBufMk(mkBlob, &newMk);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step7. decrypt mk
    struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, GetMkWithMask() };
    struct HksBlob cipherTextBlob = { sizeof(newMk.ksfDataMk.mkCiphertext), newMk.ksfDataMk.mkCiphertext };
    ret = RkcMkCrypt(&newRkc.ksfDataRkc, &newMk.ksfDataMk, &tempMkBlob, &cipherTextBlob, false);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(0, HksMemCmp(mkPlaintext, GetMkWithMask(), HKS_RKC_MK_LEN));
}

/**
 * @tc.name: HksUpgradeRkcTest.HksUpgradeRkcTest001
 * @tc.desc: rewrite rkc&mk file and check mkPlaintext's consistency
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeRkcTest, HksUpgradeRkcTest001, TestSize.Level0)
{
    uint8_t oldKsfFile[] = {
        0// todo: add old ksf file content here
    };

    uint8_t mkPlaintext[] = {
        0// todo: add old mk here
    };

    HksBlob oldKsfBlob = { sizeof(oldKsfFile), oldKsfFile };
    TestGetMkFromOldKsfFile(&oldKsfBlob, mkPlaintext);

    uint8_t rkcFile[HKS_KSF_BUF_LEN] = { 0 };
    struct HksBlob rkcBlob = { HKS_KSF_BUF_LEN, rkcFile };
    uint8_t mkFile[HKS_KSF_BUF_LEN] = { 0 };
    struct HksBlob mkBlob = { HKS_KSF_BUF_LEN, mkFile };
    TestStoreNewKsfFile(&rkcBlob, &mkBlob);

    TestGetMkFromNewKsfFile(&rkcBlob, &mkBlob, mkPlaintext);
}
}
