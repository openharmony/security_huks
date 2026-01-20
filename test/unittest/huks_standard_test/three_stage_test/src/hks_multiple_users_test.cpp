/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_api.h"
#include "hks_three_stage_test_common.h"
#include "hks_mock_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksMultipleUsersTest {
class HksMultipleUsersTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};
static uint64_t g_shellTokenId = 0;
void HksMultipleUsersTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksMultipleUsersTest::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksMultipleUsersTest::SetUp()
{
}

void HksMultipleUsersTest::TearDown()
{
}

static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 };
static const uint32_t AES_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_AES_Cipher_Test_000000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

static const struct HksParam g_genParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_encryptParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_decryptParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};

static const struct HksParam g_genParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 101 },
};

static int32_t HksTestUpdateLoopFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = { MAX_OUTDATA_SIZE, NULL };
    uint8_t *cur = outData->data;
    uint32_t curSize = outData->size;
    outData->size = 0;

    inDataSeg.size = MAX_UPDATE_SIZE;

    bool isFinished = false;

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            break;
        }
        if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
        if (HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg) != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            HKS_FREE(outDataSeg.data);
            return HKS_FAILURE;
        }
        (void)memcpy_s(cur, outDataSeg.size, outDataSeg.data, outDataSeg.size);
        cur += outDataSeg.size;
        outData->size += outDataSeg.size;
        HKS_FREE(outDataSeg.data);
        if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
            return HKS_FAILURE;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }

    struct HksBlob outDataFinish = { inDataSeg.size * TIMES, NULL };
    if (MallocAndCheckBlobData(&outDataFinish, outDataFinish.size) != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    if (HksFinish(handle, paramSet, &inDataSeg, &outDataFinish) != HKS_SUCCESS) {
        HKS_FREE(outDataFinish.data);
        return HKS_FAILURE;
    }

    if (memcpy_s(cur, curSize, outDataFinish.data, outDataFinish.size) != EOK) {
        HKS_FREE(outDataFinish.data);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    outData->size += outDataFinish.size;
    HKS_FREE(outDataFinish.data);

    return HKS_SUCCESS;
}

int32_t HksAesCipherTestEncrypt(const struct HksBlob *keyAlias, const struct HksParamSet *encryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksTestUpdateLoopFinish(&handleEncrypt, encryptParamSet, inData, cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksTestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    return HKS_SUCCESS;
}

int32_t HksAesCipherTestDecrypt(const struct HksBlob *keyAlias, const struct HksParamSet *decryptParamSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText, const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksTestUpdateLoopFinish(&handleDecrypt, decryptParamSet, cipherText, plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksTestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";

    return HKS_SUCCESS;
}

/**
 * @tc.name: HksMultipleUsersTest.HksMultipleUsersTest001
 * @tc.desc: uid not in whilelist, front user id equals specific user id
 * @tc.type: FUNC
 */
HWTEST_F(HksMultipleUsersTest, HksMultipleUsersTest001, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksMultipleUsersTest001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksMultipleUsersTest.HksMultipleUsersTest002
 * @tc.desc: uid not in whilelist, front user id not equal specific user id
 * @tc.type: FUNC
 */
HWTEST_F(HksMultipleUsersTest, HksMultipleUsersTest002, TestSize.Level0)
{
    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksMultipleUsersTest002";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_ACCESS_OTHER_USER_KEY) << "HksGenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}
}
