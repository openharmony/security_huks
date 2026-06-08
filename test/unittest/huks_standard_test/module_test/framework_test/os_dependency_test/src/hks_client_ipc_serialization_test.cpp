/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_client_ipc_serialization.h"
#include "hks_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

using namespace testing::ext;
namespace Unittest::HksClientIpcSerializationTest {
class HksClientIpcSerializationTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksClientIpcSerializationTest::SetUpTestCase(void)
{
}

void HksClientIpcSerializationTest::TearDownTestCase(void)
{
}

void HksClientIpcSerializationTest::SetUp()
{
}

void HksClientIpcSerializationTest::TearDown()
{
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest001
 * @tc.desc: tdd CopyUint32ToBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest001");

    uint32_t index = 15;
    const uint32_t destBlobSize = 10;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { .size = destBlobSize, .data = destBlobData };

    int32_t ret = CopyUint32ToBuffer(0, &destBlob, &index);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest002
 * @tc.desc: tdd HksOnceParamPack CopyBlobToBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest002");

    uint32_t index = 15;
    const uint32_t destBlobSize = 10;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { .size = destBlobSize, .data = destBlobData };

    int32_t ret = HksOnceParamPack(&destBlob, nullptr, nullptr, &index);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest003
 * @tc.desc: tdd HksAgreeKeyPack CopyParamSetToBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest003");

    const uint32_t destBlobSize = 10;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { .size = destBlobSize, .data = destBlobData };
    const struct HksParamSet paramSet = { .paramSetSize = 12 };

    int32_t ret = HksAgreeKeyPack(&destBlob, &paramSet, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest004
 * @tc.desc: tdd HksGetKeyInfoListUnpackFromService GetUint32FromBuffer, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest004");

    const uint32_t destBlobSize = 2;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { .size = destBlobSize, .data = destBlobData };

    int32_t ret = HksGetKeyInfoListUnpackFromService(&destBlob, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest005
 * @tc.desc: tdd HksCertificateChainUnpackFromService GetBlobFromBuffer, expect HKS_ERROR_IPC_MSG_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest005");

    const uint32_t srcBlobSize = 7;
    uint8_t srcBlobData[srcBlobSize] = { 4 };
    struct HksBlob srcBlob = { .size = srcBlobSize, .data = srcBlobData };
    struct HksCertChain certChain = { .certsCount = 4 };

    int32_t ret = HksCertificateChainUnpackFromService(&srcBlob, false, &certChain);
    EXPECT_EQ(ret, HKS_ERROR_IPC_MSG_FAIL);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest006
 * @tc.desc: tdd EncodeCertChain CheckAndCalculateSize
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest006");

    struct HksBlob inBlob = { .size = UINT32_MAX };
    int32_t ret = EncodeCertChain(&inBlob, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    inBlob.size = UINT32_MAX - 2;
    ret = EncodeCertChain(&inBlob, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    inBlob.size = 3221225431;
    ret = EncodeCertChain(&inBlob, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest007
 * @tc.desc: tdd EncodeCertChain CheckAndCalculateSize Base64Encode
 * @tc.type: FUNC
 */
uint8_t inBlobData[] = {
    0x30, 0x82, 0x03, 0x13, 0x30, 0x82, 0x02, 0xb9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0e, 0x63,
    0xcb, 0x7d, 0xcd, 0xb3, 0x86, 0x85, 0x27, 0xc6, 0xbc, 0xe0, 0x4d, 0x33, 0x99, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x5d, 0x31, 0x39, 0x30, 0x37, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x30, 0x48, 0x75, 0x61, 0x77, 0x65, 0x69, 0x20, 0x43, 0x42, 0x47,
    0x20, 0x45, 0x43, 0x43, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x41, 0x6e, 0x6f, 0x6e,
    0x79, 0x6d, 0x6f, 0x75, 0x73, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x43, 0x41, 0x20, 0x31, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x0a, 0x48, 0x75, 0x61, 0x77, 0x65, 0x69, 0x20, 0x43, 0x42, 0x47, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4e, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x38,
    0x30, 0x38, 0x30, 0x32, 0x30, 0x35, 0x35, 0x37, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x38, 0x31,
    0x35, 0x30, 0x32, 0x30, 0x35, 0x35, 0x37, 0x5a, 0x30, 0x2c, 0x31, 0x2a, 0x30, 0x28, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x21, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74,
    0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x6d, 0x65,
    0x6e, 0x74, 0x20, 0x4b, 0x65, 0x79, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0xea, 0xba, 0xbf, 0x64, 0x55, 0x32, 0x59, 0x2b, 0xd6, 0xe2, 0x95, 0xea, 0x06, 0x4f, 0x35,
    0xe9, 0x58, 0x48, 0x68, 0x68, 0x9e, 0x55, 0x1e, 0xf4, 0xad, 0x3e, 0x62, 0x39, 0xad, 0xd4, 0xba,
    0x7b, 0x99, 0xbc, 0x0c, 0x9e, 0x8f, 0xc3, 0x77, 0x8f, 0x57, 0x01, 0xd8, 0x8a, 0xa6, 0x5d, 0x5b,
    0xe3, 0xfd, 0x0e, 0x23, 0xff, 0x1a, 0xe5, 0xbe, 0x6e, 0xd4, 0x73, 0x1d, 0xc4, 0x00, 0xe3, 0x9a,
    0x08, 0xa3, 0x82, 0x01, 0x8c, 0x30, 0x82, 0x01, 0x88, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0x55, 0xdc, 0x0d, 0xb0, 0x00, 0xa6, 0x36, 0x92, 0xa0, 0x9c, 0x93, 0xb5,
    0x8f, 0xd8, 0x68, 0x17, 0x44, 0x71, 0x1b, 0x16, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
    0x16, 0x80, 0x14, 0xe3, 0x2c, 0xcb, 0xff, 0x76, 0x87, 0x3b, 0x12, 0xfb, 0x43, 0x22, 0x3f, 0x3f,
    0xfb, 0x02, 0x06, 0x81, 0xdf, 0x27, 0xa7, 0x30, 0x82, 0x01, 0x36, 0x06, 0x0c, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x01, 0x03, 0x04, 0x82, 0x01, 0x24, 0x30, 0x82, 0x01,
    0x20, 0x02, 0x01, 0x00, 0x30, 0x81, 0xcf, 0x02, 0x01, 0x02, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x03, 0x30, 0x81, 0xba, 0x06, 0x0e, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x03, 0x01, 0x04, 0x81, 0xa7, 0x7b,
    0x22, 0x61, 0x70, 0x70, 0x49, 0x64, 0x22, 0x3a, 0x22, 0x63, 0x6f, 0x6d, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6d, 0x79, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x5f, 0x42, 0x4e, 0x73, 0x72, 0x6a, 0x4d, 0x73, 0x67, 0x4a, 0x54, 0x30, 0x4f, 0x61,
    0x59, 0x50, 0x49, 0x36, 0x70, 0x75, 0x57, 0x70, 0x7a, 0x74, 0x2b, 0x67, 0x43, 0x36, 0x71, 0x44,
    0x55, 0x73, 0x51, 0x78, 0x33, 0x78, 0x77, 0x49, 0x51, 0x67, 0x68, 0x4a, 0x4a, 0x6a, 0x7a, 0x6d,
    0x66, 0x4d, 0x49, 0x58, 0x59, 0x38, 0x6f, 0x32, 0x2b, 0x49, 0x57, 0x56, 0x79, 0x48, 0x37, 0x43,
    0x2f, 0x61, 0x63, 0x53, 0x2f, 0x44, 0x4a, 0x6f, 0x43, 0x57, 0x78, 0x41, 0x74, 0x44, 0x51, 0x4c,
    0x2b, 0x51, 0x35, 0x78, 0x36, 0x2b, 0x34, 0x78, 0x2f, 0x41, 0x3d, 0x22, 0x2c, 0x22, 0x62, 0x75,
    0x6e, 0x64, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x22, 0x63, 0x6f, 0x6d, 0x2e, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6d, 0x79, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x22, 0x7d, 0x30, 0x22, 0x02, 0x01, 0x00, 0x06, 0x0d, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x04, 0x04, 0x0e, 0x63, 0x68, 0x61, 0x6c,
    0x6c, 0x65, 0x6e, 0x67, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x30, 0x25, 0x02, 0x01, 0x03, 0x06,
    0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x02, 0x02, 0x06, 0x04,
    0x10, 0x28, 0xc4, 0xfb, 0x49, 0x44, 0xaf, 0xec, 0x11, 0xb9, 0x09, 0x02, 0x42, 0xac, 0x12, 0x00,
    0x02, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00,
    0x30, 0x45, 0x02, 0x21, 0x00, 0x92, 0x41, 0xa8, 0xf7, 0xb9, 0x57, 0x79, 0x78, 0x0d, 0xd8, 0xf1,
    0x76, 0xaf, 0x10, 0x4e, 0xef, 0xce, 0xc5, 0xff, 0xbe, 0x8b, 0x04, 0x86, 0xb4, 0xd4, 0xa5, 0x11,
    0x13, 0x16, 0xc5, 0xf8, 0xa1, 0x02, 0x20, 0x3b, 0xb2, 0x22, 0x50, 0xf5, 0x10, 0x76, 0x05, 0x98,
    0xf7, 0x5a, 0xeb, 0xe3, 0x92, 0xfe, 0x29, 0x31, 0x0f, 0xc8, 0x3a, 0x04, 0xf1, 0x97, 0xbf, 0x39,
    0x3a, 0x5d, 0xf5, 0xe3, 0xb7, 0x35, 0xa1
};
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest007");

    uint32_t inBlobSize = sizeof(inBlobData) / sizeof(inBlobData[0]);
    struct HksBlob inBlob = { .size = inBlobSize, .data = inBlobData };
    uint32_t outBlobSize = 4096;
    uint8_t outBlobData[outBlobSize];
    for (uint32_t i = 0; i < inBlobSize; ++i) {
    outBlobData[i] = inBlobData[i];
    }
    struct HksBlob outBlob = { .size = outBlobSize, .data = outBlobData };

    int32_t ret = EncodeCertChain(&inBlob, &outBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest008
 * @tc.desc: tdd HksCertificateChainUnpackFromService
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest008");

    const uint32_t srcBlobSize1 = 2;
    uint8_t srcBlobData1[srcBlobSize1] = { 5 };
    struct HksBlob srcBlob = { .size = srcBlobSize1, .data = srcBlobData1 };
    struct HksCertChain certChain = { .certsCount = 4 };

    int32_t ret = HksCertificateChainUnpackFromService(&srcBlob, true, &certChain);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);

    const uint32_t srcBlobSize2 = 4;
    uint8_t srcBlobData2[srcBlobSize2] = { 5 };
    srcBlob.size = srcBlobSize2;
    srcBlob.data = srcBlobData2;
    ret = HksCertificateChainUnpackFromService(&srcBlob, true, &certChain);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_DATA);
}

/**
 * @tc.name: HksClientIpcSerializationTest.HksClientIpcSerializationTest009
 * @tc.desc: tdd HksListAliasesUnpackFromService
 * @tc.type: FUNC
 */
HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest009");

    struct HksBlob srcBlob = { .size = 0, .data = nullptr };
    int32_t ret = HksListAliasesUnpackFromService(&srcBlob, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

static int32_t BuildTestParamSet(struct HksParamSet **outParamSet)
{
    int32_t ret = HksInitParamSet(outParamSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 256 },
    };
    ret = HksAddParams(*outParamSet, params, sizeof(params) / sizeof(params[0]));
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(outParamSet);
        return ret;
    }
    ret = HksBuildParamSet(outParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(outParamSet);
    }
    return ret;
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest010");

    uint32_t offset = 0;
    const uint32_t destBlobSize = 128;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    int32_t ret = CopyUint32ToBuffer(42, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(offset, sizeof(uint32_t));
    EXPECT_EQ(*(uint32_t *)destBlobData, 42);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest011");

    uint32_t offset = 0;
    const uint32_t destBlobSize = 128;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    int32_t ret = CopyInt32ToBuffer(-7, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(offset, sizeof(int32_t));
    EXPECT_EQ(*(int32_t *)destBlobData, -7);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest012");

    const uint32_t destBlobSize = 2;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    uint32_t offset = 0;
    int32_t ret = CopyInt32ToBuffer(42, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);

    const uint32_t bigSize = 128;
    uint8_t bigData[bigSize] = { 0 };
    struct HksBlob bigBlob = { bigSize, bigData };
    offset = 126;
    ret = CopyInt32ToBuffer(42, &bigBlob, &offset);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest013");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint32_t offset = 0;
    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = CopyParamSetToBuffer(paramSet, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(offset, ALIGN_SIZE(paramSet->paramSetSize));

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest014");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint32_t offset = 0;
    const uint32_t destBlobSize = 4;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = CopyParamSetToBuffer(paramSet, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest015");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t keyOutSize = 256;
    struct HksBlob keyOut = { keyOutSize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksGenerateKeyPack(&destBlob, &keyAlias, paramSet, &keyOut);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest016");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xBB };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t keySize = 8;
    uint8_t keyData[keySize] = { 0xCC };
    struct HksBlob key = { keySize, keyData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksImportKeyPack(&destBlob, &keyAlias, paramSet, &key);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest017");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t wrappingKeyAliasSize = 4;
    uint8_t wrappingKeyAliasData[wrappingKeyAliasSize] = { 0xBB };
    struct HksBlob wrappingKeyAlias = { wrappingKeyAliasSize, wrappingKeyAliasData };
    const uint32_t wrappedKeyDataSize = 8;
    uint8_t wrappedKeyDataBuf[wrappedKeyDataSize] = { 0xCC };
    struct HksBlob wrappedKeyData = { wrappedKeyDataSize, wrappedKeyDataBuf };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksImportWrappedKeyPack(&destBlob, &keyAlias, &wrappingKeyAlias, paramSet, &wrappedKeyData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest018");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksDeleteKeyPack(&keyAlias, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest019");

    const uint32_t indexSize = 4;
    uint8_t indexData[indexSize] = { 0xAA };
    struct HksBlob index = { indexSize, indexData };

    const uint32_t destBlobSize = 64;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    int32_t ret = HksClearPinAuthStatePack(&index, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest020");

    const uint32_t indexSize = 4;
    uint8_t indexData[indexSize] = { 0xAA };
    struct HksBlob index = { indexSize, indexData };

    const uint32_t destBlobSize = 2;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    int32_t ret = HksClearPinAuthStatePack(&index, &destBlob);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest021");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t keySize = 64;
    struct HksBlob key = { keySize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksExportPublicKeyPack(&keyAlias, paramSet, &key, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest022");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t keyOutSize = 256;
    struct HksBlob keyOut = { keyOutSize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksGetKeyParamSetPack(&keyAlias, paramSet, &keyOut, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest023");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksKeyExistPack(&keyAlias, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest024");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keySize = 4;
    uint8_t keyData[keySize] = { 0xAA };
    struct HksBlob key = { keySize, keyData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    uint32_t offset = 0;
    ret = HksOnceParamPack(&destBlob, &key, paramSet, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_NE(offset, 0);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest025");

    const uint32_t inputDataSize = 4;
    uint8_t inputDataBuf[inputDataSize] = { 0xAA };
    struct HksBlob inputData = { inputDataSize, inputDataBuf };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    uint32_t offset = 0;
    int32_t ret = HksOnceDataPack(&destBlob, &inputData, nullptr, nullptr, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest026");

    const uint32_t inputDataSize = 4;
    uint8_t inputDataBuf[inputDataSize] = { 0xAA };
    struct HksBlob inputData = { inputDataSize, inputDataBuf };
    const uint32_t rsvDataSize = 4;
    uint8_t rsvDataBuf[rsvDataSize] = { 0xBB };
    struct HksBlob rsvData = { rsvDataSize, rsvDataBuf };
    const uint32_t outputDataSize = 32;
    struct HksBlob outputData = { outputDataSize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    uint32_t offset = 0;
    int32_t ret = HksOnceDataPack(&destBlob, &inputData, &rsvData, &outputData, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest027");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t kdfKeySize = 4;
    uint8_t kdfKeyData[kdfKeySize] = { 0xAA };
    struct HksBlob kdfKey = { kdfKeySize, kdfKeyData };
    const uint32_t derivedKeySize = 32;
    struct HksBlob derivedKey = { derivedKeySize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksDeriveKeyPack(&destBlob, paramSet, &kdfKey, &derivedKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest028, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest028");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t certChainBlobSize = 64;
    struct HksBlob certChainBlob = { certChainBlobSize, nullptr };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksCertificateChainPack(&destBlob, &keyAlias, paramSet, &certChainBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest029, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest029");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksListAliasesPack(paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest030, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest030");

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 256 },
    };
    struct HksParamSet *outParamSet = nullptr;

    int32_t ret = HksParamsToParamSet(params, sizeof(params) / sizeof(params[0]), &outParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_NE(outParamSet, nullptr);

    HksFreeParamSet(&outParamSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest031, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest031");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t oldAliasSize = 4;
    uint8_t oldAliasData[oldAliasSize] = { 0xAA };
    struct HksBlob oldKeyAlias = { oldAliasSize, oldAliasData };
    const uint32_t newAliasSize = 4;
    uint8_t newAliasData[newAliasSize] = { 0xBB };
    struct HksBlob newKeyAlias = { newAliasSize, newAliasData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksRenameKeyAliasPack(&oldKeyAlias, &newKeyAlias, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest032, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest032");

    struct HksParamSet *srcParamSet = nullptr;
    struct HksParamSet *destParamSet = nullptr;
    int32_t ret = BuildTestParamSet(&srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = BuildTestParamSet(&destParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };

    const uint32_t destBlobSize = 2048;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksChangeStorageLevelPack(&destBlob, &keyAlias, srcParamSet, destParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&destParamSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest033, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest033");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    struct HksBlob wrappedKey = { 32, nullptr };

    const uint32_t inBlobSize = 1024;
    uint8_t inBlobData[inBlobSize] = { 0 };
    struct HksBlob inBlob = { inBlobSize, inBlobData };

    ret = HksWrapKeyPack(&inBlob, &keyAlias, paramSet, &wrappedKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest034, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest034");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t wrappedKeySize = 8;
    uint8_t wrappedKeyData[wrappedKeySize] = { 0xBB };
    struct HksBlob wrappedKey = { wrappedKeySize, wrappedKeyData };

    const uint32_t inBlobSize = 1024;
    uint8_t inBlobData[inBlobSize] = { 0 };
    struct HksBlob inBlob = { inBlobSize, inBlobData };

    ret = HksUnwrapKeyPack(&inBlob, &keyAlias, paramSet, &wrappedKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest035, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest035");

    struct HksParamSet *paramSet = nullptr;
    struct HksParamSet *sharedKeyParamSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = BuildTestParamSet(&sharedKeyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t sharedKeyAliasSize = 4;
    uint8_t sharedKeyAliasData[sharedKeyAliasSize] = { 0xBB };
    struct HksBlob sharedKeyAlias = { sharedKeyAliasSize, sharedKeyAliasData };

    const uint32_t destBlobSize = 2048;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksEncapsulatePack(&destBlob, &keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest036, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest036");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t keyAliasSize = 4;
    uint8_t keyAliasData[keyAliasSize] = { 0xAA };
    struct HksBlob keyAlias = { keyAliasSize, keyAliasData };
    const uint32_t sharedKeyAliasSize = 4;
    uint8_t sharedKeyAliasData[sharedKeyAliasSize] = { 0xBB };
    struct HksBlob sharedKeyAlias = { sharedKeyAliasSize, sharedKeyAliasData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };
    uint32_t offset = 0;

    ret = HksDecapsulatePack(&destBlob, &keyAlias, paramSet, &sharedKeyAlias, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest037, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest037");

    /* construct valid packed data: encapsulatedData blob + sharedSecret blob */
    uint8_t encapData[] = { 0x01, 0x02, 0x03, 0x04 };
    struct HksBlob encapBlob = { sizeof(encapData), encapData };
    uint8_t secretData[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    struct HksBlob secretBlob = { sizeof(secretData), secretData };

    const uint32_t bufSize = 256;
    uint8_t bufData[bufSize] = { 0 };
    struct HksBlob srcBlob = { bufSize, bufData };
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(&encapBlob, &srcBlob, &offset);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = CopyBlobToBuffer(&secretBlob, &srcBlob, &offset);
    ASSERT_EQ(ret, HKS_SUCCESS);
    srcBlob.size = offset;

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksEncapsulateUnpackFromService(&srcBlob, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(encapResult.encapsulatedData.size, sizeof(encapData));
    EXPECT_EQ(memcmp(encapResult.encapsulatedData.data, encapData, sizeof(encapData)), 0);
    EXPECT_EQ(encapResult.sharedSecret.size, sizeof(secretData));
    EXPECT_EQ(memcmp(encapResult.sharedSecret.data, secretData, sizeof(secretData)), 0);
    HKS_FREE(encapResult.encapsulatedData.data);
    HKS_FREE(encapResult.sharedSecret.data);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest038, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest038");

    /* null pointer checks */
    struct HksBlob sharedSecret = { 0, nullptr };
    int32_t ret = HksDecapsulateUnpackFromService(nullptr, &sharedSecret);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    struct HksBlob srcBlob = { 4, nullptr };
    ret = HksDecapsulateUnpackFromService(&srcBlob, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    /* valid packed sharedSecret with data > 0 */
    uint8_t secretData[] = { 0x11, 0x22, 0x33, 0x44 };
    struct HksBlob secretBlob = { sizeof(secretData), secretData };
    const uint32_t bufSize = 64;
    uint8_t bufData[bufSize] = { 0 };
    struct HksBlob packedBlob = { bufSize, bufData };
    uint32_t offset = 0;
    ret = CopyBlobToBuffer(&secretBlob, &packedBlob, &offset);
    ASSERT_EQ(ret, HKS_SUCCESS);
    packedBlob.size = offset;

    uint8_t outBuf[32] = { 0 };
    struct HksBlob outSecret = { sizeof(outBuf), outBuf };
    ret = HksDecapsulateUnpackFromService(&packedBlob, &outSecret);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(outSecret.size, sizeof(secretData));
    EXPECT_EQ(memcmp(outSecret.data, secretData, sizeof(secretData)), 0);

    /* packed sharedSecret with size == 0 -> early return HKS_SUCCESS */
    struct HksBlob emptyBlob = { 0, nullptr };
    uint8_t emptyBuf[32] = { 0 };
    struct HksBlob emptyPacked = { sizeof(emptyBuf), emptyBuf };
    offset = 0;
    ret = CopyBlobToBuffer(&emptyBlob, &emptyPacked, &offset);
    ASSERT_EQ(ret, HKS_SUCCESS);
    emptyPacked.size = offset;

    uint8_t outBuf2[32] = { 0 };
    struct HksBlob outSecret2 = { sizeof(outBuf2), outBuf2 };
    ret = HksDecapsulateUnpackFromService(&emptyPacked, &outSecret2);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

#ifdef HKS_UKEY_EXTENSION_CRYPTO

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest039, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest039");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t blobSize = 4;
    uint8_t blobData[blobSize] = { 0xAA };
    struct HksBlob blob = { blobSize, blobData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksUKeyGeneralPack(&blob, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest040, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest040");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t blob1Size = 4;
    uint8_t blob1Data[blob1Size] = { 0xAA };
    struct HksBlob blob1 = { blob1Size, blob1Data };
    const uint32_t blob2Size = 4;
    uint8_t blob2Data[blob2Size] = { 0xBB };
    struct HksBlob blob2 = { blob2Size, blob2Data };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksUkeyBlob2ParamSetPack(&blob1, &blob2, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest041, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest041");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t resourceIdSize = 4;
    uint8_t resourceIdData[resourceIdSize] = { 0xAA };
    struct HksBlob resourceId = { resourceIdSize, resourceIdData };
    const uint32_t propertyIdSize = 4;
    uint8_t propertyIdData[propertyIdSize] = { 0xBB };
    struct HksBlob propertyId = { propertyIdSize, propertyIdData };

    const uint32_t destBlobSize = 1024;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksSetOrGetRemotePropertyPack(HKS_EXT_PROPERTY_OPERATION_GET,
        &resourceId, &propertyId, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest042, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest042");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t blobSize = 4;
    uint8_t blobData[blobSize] = { 0xAA };
    struct HksBlob blob = { blobSize, blobData };

    struct HksExtCertInfo certInfo;
    certInfo.purpose = 1;
    const uint32_t indexSize = 4;
    uint8_t indexData[indexSize] = { 0xCC };
    certInfo.index = { indexSize, indexData };
    const uint32_t certSize = 8;
    uint8_t certData[certSize] = { 0xDD };
    certInfo.cert = { certSize, certData };

    const uint32_t destBlobSize = 2048;
    uint8_t destBlobData[destBlobSize] = { 0 };
    struct HksBlob destBlob = { destBlobSize, destBlobData };

    ret = HksUKeyGeneralPackWithCertInfo(&blob, &certInfo, paramSet, &destBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest043, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest043");

    int32_t ret = HksCertificatesUnpackFromService(nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest044, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest044");

    struct HksExtCertInfoSet destData = { 0, nullptr };
    struct HksBlob srcBlob = { 0, nullptr };

    int32_t ret = HksCertificatesUnpackFromService(&srcBlob, &destData);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(destData.count, 0);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest045, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest045");

    uint32_t cnt = 1;
    uint32_t offset = 0;
    const uint32_t srcSize = 1024;
    uint8_t srcData[srcSize] = { 0 };
    struct HksBlob srcBlob = { srcSize, srcData };

    int32_t ret = CopyUint32ToBuffer(cnt, &srcBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t purpose = 1;
    ret = CopyInt32ToBuffer(purpose, &srcBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t indexBlobSize = 4;
    uint8_t indexBlobData[indexBlobSize] = { 0xCC };
    struct HksBlob indexBlob = { indexBlobSize, indexBlobData };
    ret = CopyBlobToBuffer(&indexBlob, &srcBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t certBlobSize = 8;
    uint8_t certBlobData[certBlobSize] = { 0xDD };
    struct HksBlob certBlob = { certBlobSize, certBlobData };
    ret = CopyBlobToBuffer(&certBlob, &srcBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    srcBlob.size = offset;
    struct HksExtCertInfoSet destData = { 0, nullptr };
    ret = HksCertificatesUnpackFromService(&srcBlob, &destData);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(destData.count, 1);
    EXPECT_EQ(destData.certs[0].purpose, 1);

    HksFreeExtCertSet(&destData);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest046, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest046");

    struct HksParamSet *propertySetOut = nullptr;
    const uint32_t srcSize = 128;
    uint8_t srcData[srcSize] = { 0 };
    uint32_t offset = 0;

    struct HksBlob destBlob = { srcSize, srcData };
    int32_t ret = CopyInt32ToBuffer(HKS_SUCCESS, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob srcBlob = { offset, srcData };
    ret = HksRemotePropertyUnpackFromService(&srcBlob, &propertySetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(propertySetOut, nullptr);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest047, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest047");

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildTestParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const uint32_t srcSize = 512;
    uint8_t srcData[srcSize] = { 0 };
    uint32_t offset = 0;

    struct HksBlob destBlob = { srcSize, srcData };
    ret = CopyInt32ToBuffer(HKS_SUCCESS, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = CopyParamSetToBuffer(paramSet, &destBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob srcBlob = { offset, srcData };
    struct HksParamSet *propertySetOut = nullptr;
    ret = HksRemotePropertyUnpackFromService(&srcBlob, &propertySetOut);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_NE(propertySetOut, nullptr);

    HksFreeParamSet(&propertySetOut);
    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest048, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest048");

    const uint32_t srcSize = 2;
    uint8_t srcData[srcSize] = { 0 };

    struct HksBlob srcBlob = { srcSize, srcData };
    struct HksParamSet *propertySetOut = nullptr;
    int32_t ret = HksRemotePropertyUnpackFromService(&srcBlob, &propertySetOut);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest049, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest049");

    uint32_t offset = 0;
    const uint32_t srcSize = 128;
    uint8_t srcData[srcSize] = { 0 };
    struct HksBlob srcBlob = { srcSize, srcData };

    const uint32_t blobSize = 4;
    uint8_t blobData[blobSize] = { 0xAA };
    struct HksBlob packedBlob = { blobSize, blobData };

    int32_t ret = CopyBlobToBuffer(&packedBlob, &srcBlob, &offset);
    EXPECT_EQ(ret, HKS_SUCCESS);

    uint32_t unpackOffset = 0;
    struct HksBlob outBlob = { 0, nullptr };
    ret = UnpackBlobFromBuffer(&srcBlob, &unpackOffset, &outBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(outBlob.size, blobSize);
    EXPECT_NE(outBlob.data, nullptr);

    HKS_FREE(outBlob.data);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest050, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest050");

    const uint32_t tinySize = 2;
    uint8_t tinyData[tinySize] = { 0 };
    struct HksBlob srcBlob = { tinySize, tinyData };
    uint32_t offset = 0;
    struct HksBlob outBlob = { 0, nullptr };

    int32_t ret = UnpackBlobFromBuffer(&srcBlob, &offset, &outBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HksClientIpcSerializationTest, HksClientIpcSerializationTest051, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientIpcSerializationTest051");

    const uint32_t resourceIdSize = 4;
    uint8_t resourceIdData[resourceIdSize] = { 0xAA };
    struct HksBlob resourceId = { resourceIdSize, resourceIdData };
    const uint32_t bundleNameSize = 8;
    uint8_t bundleNameData[bundleNameSize] = { 't', 'e', 's', 't' };
    struct HksBlob bundleName = { bundleNameSize, bundleNameData };
    const uint32_t abilityNameSize = 8;
    uint8_t abilityNameData[abilityNameSize] = { 'a', 'b', 'c' };
    struct HksBlob abilityName = { abilityNameSize, abilityNameData };

    struct HksAbilityInfo abilityInfo = { bundleName, abilityName };
    struct HksBlob outResourceId = { resourceIdSize, (uint8_t *)HksMalloc(resourceIdSize) };
    struct HksAbilityInfo outAbilityInfo;
    outAbilityInfo.bundleName = { bundleNameSize, (uint8_t *)HksMalloc(bundleNameSize) };
    outAbilityInfo.abilityName = { abilityNameSize, (uint8_t *)HksMalloc(abilityNameSize) };

    int32_t ret = HksQueryAbilityCopyResult(&resourceId, &abilityInfo, &outResourceId, &outAbilityInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(outResourceId.size, resourceIdSize);
    EXPECT_EQ(outAbilityInfo.bundleName.size, bundleNameSize);
    EXPECT_EQ(outAbilityInfo.abilityName.size, abilityNameSize);

    HKS_FREE(outResourceId.data);
    HKS_FREE(outAbilityInfo.bundleName.data);
    HKS_FREE(outAbilityInfo.abilityName.data);
}

#endif
}
