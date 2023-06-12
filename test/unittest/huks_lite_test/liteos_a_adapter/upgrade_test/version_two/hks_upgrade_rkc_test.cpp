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

#include "hks_ability.h"
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
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksUpgradeRkcTest::TearDown()
{
}

static void TestGetMkFromOldKsfFile(const HksBlob *oldKsfBlob, const uint8_t mkPlaintext[HKS_RKC_MK_LEN])
{
    // step1. parse old ksf file
    struct HksRkcKsfDataV1 ksfDataV1 = { 0 };
    int32_t ret = RkcExtractKsfBufV1(oldKsfBlob, &ksfDataV1);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step2. decrypt mk
    uint8_t mk[HKS_RKC_MK_LEN] = { 0 };
    struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, mk };
    struct HksBlob cipherTextBlob = { sizeof(ksfDataV1.ksfDataMk.mkCiphertext), ksfDataV1.ksfDataMk.mkCiphertext };
    ret = RkcMkCryptV1(&ksfDataV1, &tempMkBlob, &cipherTextBlob, false);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(0, HksMemCmp(mkPlaintext, tempMkBlob.data, HKS_RKC_MK_LEN));
}

static void TestStoreNewKsfFile(HksBlob *rkcBlob, HksBlob *mkBlob, const uint8_t mkPlaintext[HKS_RKC_MK_LEN])
{
    // step3. create new rkc material
    struct HksKsfDataRkcWithVer newRkc = { 0 };
    int32_t ret = FillKsfDataRkcWithVer(&newRkc);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step4. encrypt mk with new rkc
    struct HksKsfDataMkWithVer newMk = { 0 };
    FillKsfDataMkWithVer(&newMk);

    struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, (uint8_t *)mkPlaintext };
    struct HksBlob cipherTextBlob = { sizeof(newMk.ksfDataMk.mkCiphertext), newMk.ksfDataMk.mkCiphertext };
    ret = RkcMkCrypt(&(newRkc.ksfDataRkc), &(newMk.ksfDataMk), &tempMkBlob, &cipherTextBlob, true);
    ASSERT_EQ(HKS_SUCCESS, ret);

    // step5. store new rkc and mk file
    ret = FillKsfBufRkc(&newRkc, rkcBlob);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = FillKsfBufMk(&newMk, mkBlob);
    ASSERT_EQ(HKS_SUCCESS, ret);
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
    uint8_t mk[HKS_RKC_MK_LEN] = { 0 };
    struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, mk };
    struct HksBlob cipherTextBlob = { sizeof(newMk.ksfDataMk.mkCiphertext), newMk.ksfDataMk.mkCiphertext };
    ret = RkcMkCrypt(&newRkc.ksfDataRkc, &newMk.ksfDataMk, &tempMkBlob, &cipherTextBlob, false);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(0, HksMemCmp(mkPlaintext, tempMkBlob.data, HKS_RKC_MK_LEN));
}

/**
 * @tc.name: HksUpgradeRkcTest.HksUpgradeRkcTest001
 * @tc.desc: rewrite rkc&mk file and check mkPlaintext's consistency
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeRkcTest, HksUpgradeRkcTest001, TestSize.Level0)
{
    uint8_t oldKsfFile[] = {
        0x5f, 0x64, 0x97, 0x8d, 0x19, 0x4f, 0x89, 0xcf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x95, 0x28, 0x4a, 0xca, 0x82, 0xbf, 0xe7,
        0xb2, 0x9f, 0x6b, 0xa6, 0x4c, 0x92, 0x60, 0x43, 0xb7, 0x2d, 0xda, 0x28, 0xae, 0x91, 0x59, 0xa8,
        0x7c, 0x02, 0x5a, 0x89, 0x92, 0x9e, 0x2f, 0x38, 0xeb, 0x7b, 0x0f, 0x71, 0xe3, 0xd8, 0x8a, 0x54,
        0x1f, 0x92, 0x6a, 0x96, 0xf0, 0x79, 0xf5, 0xde, 0x35, 0x2f, 0x04, 0x02, 0x69, 0x0f, 0x51, 0x38,
        0x95, 0xff, 0xdd, 0x98, 0x40, 0xd7, 0x32, 0x08, 0x01, 0x00, 0x00, 0x00, 0xf8, 0x93, 0xa4, 0x81,
        0x47, 0x5a, 0xaf, 0x91, 0x50, 0x5a, 0x48, 0x1b, 0xea, 0xab, 0x50, 0x76, 0x65, 0xc1, 0x6d, 0x9e,
        0xa6, 0xe4, 0x28, 0x80, 0xe0, 0xcc, 0x28, 0x9a, 0x89, 0xa2, 0x46, 0x1b, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x95, 0x62, 0x5a, 0x85, 0x0e, 0xc8,
        0xb9, 0xc3, 0x3b, 0x4f, 0xb9, 0xe7, 0xbf, 0x6a, 0x4e, 0x88, 0xfb, 0x9e, 0xc5, 0x3e, 0x5a, 0x05,
        0x2a, 0x4d, 0xb3, 0x1f, 0xac, 0xf1, 0xe7, 0x7f, 0x6e, 0x86, 0x69, 0xb5, 0xd9, 0x6f, 0x27, 0xc4,
        0xab, 0x9f, 0xbe, 0x0d, 0x86, 0xbd, 0x9c, 0x3f, 0x24, 0xce, 0x39, 0x4d, 0xab, 0xd5, 0x5c, 0x23,
        0xbc, 0x3e, 0x8c, 0xf3, 0xe7, 0xe5, 0x41, 0x3d, 0xb7, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x65, 0xfe, 0xe7, 0x25, 0xf8, 0x08, 0x3e, 0x33, 0xa5, 0x1e, 0x25, 0x31, 0x4c, 0xf0,
        0xe2, 0x59, 0xc9, 0x56, 0xa9, 0xf1, 0xb9, 0xa3, 0xce, 0xe8, 0xbd, 0x50, 0xad, 0xa6, 0x46, 0x5e,
        0x42, 0xea,
    };

    uint8_t mkPlaintext[] = {
        0x33, 0x45, 0x73, 0xfb, 0x7f, 0x1a, 0x45, 0xb5, 0x47, 0xcf, 0x86, 0xe6, 0x3b, 0x55, 0xf2, 0x2f,
        0x9e, 0x8d, 0x22, 0x3f, 0x46, 0x8c, 0x3b, 0x7e, 0x3d, 0xb7, 0xb3, 0x4d, 0x97, 0x2b, 0xd7, 0x0c,
    };

    HksBlob oldKsfBlob = { sizeof(oldKsfFile), oldKsfFile };
    TestGetMkFromOldKsfFile(&oldKsfBlob, mkPlaintext);

    uint8_t rkcFile[HKS_KSF_BUF_LEN] = { 0 };
    struct HksBlob rkcBlob = { HKS_KSF_BUF_LEN, rkcFile };
    uint8_t mkFile[HKS_KSF_BUF_LEN] = { 0 };
    struct HksBlob mkBlob = { HKS_KSF_BUF_LEN, mkFile };
    TestStoreNewKsfFile(&rkcBlob, &mkBlob, mkPlaintext);

    TestGetMkFromNewKsfFile(&rkcBlob, &mkBlob, mkPlaintext);
}
}
