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

#include "hks_asn1_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/device_cert_manager/src/dcm_asn1.c"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksAsn1Test {
class HksAsn1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAsn1Test::SetUpTestCase(void)
{
}

void HksAsn1Test::TearDownTestCase(void)
{
}

void HksAsn1Test::SetUp()
{
}

void HksAsn1Test::TearDown()
{
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test001
 * @tc.desc: tdd DcmAsn1InsertValue, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test001, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test001");
    const uint32_t bufSize = 16;
    uint8_t bufData[bufSize] = { 0 };
    struct HksBlob buf = { .size = sizeof(bufData), .data = bufData };
    uint8_t tlvData[ASN_1_MAX_SIZE + 1] = { 0 };
    struct HksAsn1Blob tlv = { .type = 0, .size = sizeof(tlvData), .data = tlvData };
    int32_t ret = DcmAsn1InsertValue(&buf, nullptr, &tlv);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test002
 * @tc.desc: tdd DcmAsn1InsertValue, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test002, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test002");
    const uint32_t bufSize = 16;
    uint8_t bufData[bufSize] = { 0 };
    struct HksBlob buf = { .size = sizeof(bufData), .data = bufData };
    int32_t ret = DcmAsn1InsertValue(&buf, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test003
 * @tc.desc: tdd DcmAsn1InsertValue, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test003, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test003");
    int32_t ret = DcmAsn1InsertValue(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test004
 * @tc.desc: tdd DcmAsn1ExtractTag, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test004, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test004");
    const uint32_t nextSize = 16;
    uint8_t nextData[nextSize] = { 0 };
    struct HksBlob next = { .size = sizeof(nextData), .data = nextData };
    struct HksAsn1Obj obj;
    const uint32_t dataSize = 1;
    uint8_t dataData[dataSize] = { 0 };
    struct HksBlob data = { .size = sizeof(dataData), .data = dataData };
    int32_t ret = DcmAsn1ExtractTag(&next, &obj, &data, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test005
 * @tc.desc: tdd DcmAsn1ExtractTag, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test005, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test005");
    const uint32_t nextSize = 16;
    uint8_t nextData[nextSize] = { 0 };
    struct HksBlob next = { .size = sizeof(nextData), .data = nextData };
    struct HksAsn1Obj obj;
    int32_t ret = DcmAsn1ExtractTag(&next, &obj, nullptr, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test006
 * @tc.desc: tdd DcmAsn1ExtractTag, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test006, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test006");
    const uint32_t nextSize = 16;
    uint8_t nextData[nextSize] = { 0 };
    struct HksBlob next = { .size = sizeof(nextData), .data = nextData };
    int32_t ret = DcmAsn1ExtractTag(&next, nullptr, nullptr, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAsn1Test.HksAsn1Test007
 * @tc.desc: tdd DcmAsn1ExtractTag, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAsn1Test, HksAsn1Test007, TestSize.Level0)
{
    HKS_LOG_I("enter HksAsn1Test007");
    int32_t ret = DcmAsn1ExtractTag(nullptr, nullptr, nullptr, 0);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}
}
