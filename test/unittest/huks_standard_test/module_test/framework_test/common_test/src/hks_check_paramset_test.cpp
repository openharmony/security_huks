/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_check_paramset_test.h"

#include <gtest/gtest.h>

#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_check_paramset.c"

#include "hks_log.h"
#include "hks_mem.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksCheckParamsetTest {
class HksCheckParamsetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckParamsetTest::SetUpTestCase(void)
{
}

void HksCheckParamsetTest::TearDownTestCase(void)
{
}

void HksCheckParamsetTest::SetUp()
{
}

void HksCheckParamsetTest::TearDown()
{
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest001
 * @tc.desc: test CheckMutableParams with rsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest001");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_RSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest002
 * @tc.desc: test CheckMutableParams with ecc
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest002");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ECC, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest003
 * @tc.desc: test CheckMutableParams with sm2
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest003");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM2, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest004
 * @tc.desc: test CheckMutableParams with dsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest004");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest005
 * @tc.desc: test CheckMutableParams with ed255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest005");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ED25519, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest007
 * @tc.desc: test CheckMutableParams with x255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest007");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_X25519, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest008
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest008");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DH, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest009
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest009");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM4, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
}
}
