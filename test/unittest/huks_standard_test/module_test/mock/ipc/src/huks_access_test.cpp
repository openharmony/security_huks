/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "huks_access_test.h"

#include <gtest/gtest.h>

#include "file_ex.h"
#include "huks_access.h"
#include "huks_core_hal_mock.h"

#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::HuksAccessTest {
class HuksAccessTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HuksAccessTest::SetUpTestCase(void)
{
}

void HuksAccessTest::TearDownTestCase(void)
{
}

void HuksAccessTest::SetUp()
{
}

void HuksAccessTest::TearDown()
{
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest001
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest001, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessModuleInit();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest002
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest002, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessModuleInit();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest003
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest003, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessRefresh();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest004
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest004, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessRefresh();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest005
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest005, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGenerateKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest006
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest006, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGenerateKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest007
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest007, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessImportKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest008
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest008, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessImportKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest009
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest009, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessImportWrappedKey(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest010
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest010, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessImportWrappedKey(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest011
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest011, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessExportPublicKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest012
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest012, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessExportPublicKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest013
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest013, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessInit(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest014
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest014, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessInit(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest015
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest015, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessUpdate(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest016
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest016, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessUpdate(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
* @tc.name: HuksAccessTest.HuksAccessTest017
* @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
* @tc.type: FUNC
*/
HWTEST_F(HuksAccessTest, HuksAccessTest017, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessFinish(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
* @tc.name: HuksAccessTest.HuksAccessTest018
* @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
* @tc.type: FUNC
*/
HWTEST_F(HuksAccessTest, HuksAccessTest018, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessFinish(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest019
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest019, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAbort(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest020
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest020, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAbort(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
* @tc.name: HuksAccessTest.HuksAccessTest021
* @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
* @tc.type: FUNC
*/
HWTEST_F(HuksAccessTest, HuksAccessTest021, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetKeyProperties(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
* @tc.name: HuksAccessTest.HuksAccessTest022
* @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
* @tc.type: FUNC
*/
HWTEST_F(HuksAccessTest, HuksAccessTest022, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetKeyProperties(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest023
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest023, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetAbility(0);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest024
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest024, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetAbility(0);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest025
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest025, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetHardwareInfo();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest026
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest026, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGetHardwareInfo();
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest027
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest027, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessSign(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest028
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest028, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessSign(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest029
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest029, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessVerify(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest030
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest030, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessVerify(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest031
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest031, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessEncrypt(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest032
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest032, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessEncrypt(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest033
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest033, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessDecrypt(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest034
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest034, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessDecrypt(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest035
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest035, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAgreeKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest036
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest036, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAgreeKey(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest037
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest037, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessDeriveKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest038
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest038, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessDeriveKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest039
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest039, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessMac(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest040
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest040, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessMac(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

#ifdef _STORAGE_LITE_

/**
 * @tc.name: HuksAccessTest.HuksAccessTest041
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest041, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessCalcHeaderMac(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest042
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest042, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessCalcHeaderMac(nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

#endif

/**
 * @tc.name: HuksAccessTest.HuksAccessTest045
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest045, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAttestKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest046
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest046, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessAttestKey(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest047
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest047, TestSize.Level0)
{
    HksEnableCreateOrDestroy(false);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGenerateRandom(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HuksAccessTest.HuksAccessTest048
 * @tc.desc: tdd HksCreateHuksHdiDevice, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HuksAccessTest, HuksAccessTest048, TestSize.Level0)
{
    HksEnableCreateOrDestroy(true);
    HksEnableSetHid(false);
    int32_t ret = HuksAccessGenerateRandom(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}
}
