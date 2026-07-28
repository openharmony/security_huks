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

#include "hks_api.h"
#include "hks_change_storage_level_test_common.h"
#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_three_stage_test_common.h"
#include "hks_mock_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksChangeStorageLevelTest {
class HksChangeStorageLevelPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};
static uint64_t g_shellTokenId = 0;
void HksChangeStorageLevelPart1Test::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksChangeStorageLevelPart1Test::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksChangeStorageLevelPart1Test::SetUp()
{
}

void HksChangeStorageLevelPart1Test::TearDown()
{
}

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

static int32_t HksAesCipherTestEncrypt(const struct HksBlob *keyAlias, const struct HksParamSet *encryptParamSet,
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

static int32_t HksAesCipherTestDecrypt(const struct HksBlob *keyAlias, const struct HksParamSet *decryptParamSet,
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
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test001
 * @tc.desc: upgrade DE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test001");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob plainText = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &plainText, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksChangeStorageLevel failed.";

    ret = HksKeyExist(&keyAlias, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[AES_COMMON_SIZE] = { 0 };
    struct HksBlob plainTextNew = { AES_COMMON_SIZE, plain };
    ret = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &plainTextNew, &plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test002
 * @tc.desc: upgrade DE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test002");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test002";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test003
 * @tc.desc: upgrade CE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test003");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test003";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test004
 * @tc.desc: upgrade tmpDE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test004");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test004";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params004, sizeof(g_params004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_PARAM_NOT_EXIST) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test005
 * @tc.desc: upgrade CE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test005");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test005";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test006
 * @tc.desc: upgrade ECE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test006");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test006";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test007
 * @tc.desc: upgrade ECE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test007");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test007";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test008
 * @tc.desc: upgrade DE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test008");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test008";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test009
 * @tc.desc: upgrade CE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test009");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test009";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test010
 * @tc.desc: upgrade ECE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test010");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test010";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test011
 * @tc.desc: upgrade DE to tmpDE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test011");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test011";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params004, sizeof(g_params004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_PARAM_NOT_EXIST) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test012
 * @tc.desc: upgrade DE to CE, srcParamSet is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test012");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test012";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, nullptr, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test013
 * @tc.desc: upgrade DE to CE, desParamSet is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test013, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test013");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test013";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test014
 * @tc.desc: upgrade DE to CE, srcParamSet HKS_TAG_AUTH_STORAGE_LEVEL is 10
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test014, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test014");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test014";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    srcParamSet->params[3].uint32Param = 10;
    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    srcParamSet->params[3].uint32Param = HKS_AUTH_STORAGE_LEVEL_DE;
    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test015
 * @tc.desc: upgrade DE to CE, desParamSet HKS_TAG_AUTH_STORAGE_LEVEL is 10
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test015, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test015");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test015";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    desParamSet->params[3].uint32Param = 10;
    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test016
 * @tc.desc: upgrade DE to CE, keyAlias is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test016, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test016");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test016";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(nullptr, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test017
 * @tc.desc: upgrade DE to CE, src key not exist, des key not exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test017, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test017");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test017";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "HksChangeStorageLevel failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test018
 * @tc.desc: upgrade DE to CE, src key not exist, des key maindata not exist, des key backup exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test018, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test018");

    HksMockNativeToken mock("asset_service");

    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    
    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test018";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, desParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    ret = HksFileRemove(STORE_PATH, tmpKeyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksFileRemove failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test019
 * @tc.desc: upgrade DE to CE, src key exist, des key maindata exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test019, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test019");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test019";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";
    
    char desTmpKeyAlias[] = "HksChangeStorageLevelPart1Test019";
    const struct HksBlob desKeyAlias = { strlen(desTmpKeyAlias), (uint8_t *)desTmpKeyAlias };
    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&desKeyAlias, desParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_KEY_CONFLICT) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    ret = HksDeleteKey(&desKeyAlias, desParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test020
 * @tc.desc: upgrade DE to CE, pressure test
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test020, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test020");

    HksMockNativeToken mock("asset_service");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test020_00";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    for (uint32_t i = 0; i < 50; i++) {
        keyAlias.data[29] = '0' + i / 10;
        keyAlias.data[30] = '0' + i % 10;
        ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

        ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksChangeStorageLevel failed.";

        ret = HksDeleteKey(&keyAlias, desParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";
    }

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test021
 * @tc.desc: upgrade DE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test021, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test021");

    HksMockNativeToken mock("asset_service");
    char tmpKeyAlias[] = "HksChangeStorageLevelPart1Test021";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    keyAlias.size = 130;
    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksChangeStorageLevel failed.";

    keyAlias.size = strlen(tmpKeyAlias);
    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}

/**
 * @tc.name: HksChangeStorageLevelPart1Test.HksChangeStorageLevelPart1Test022
 * @tc.desc: upgrade DE to CE, no permission
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart1Test, HksChangeStorageLevelPart1Test022, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart1Test022");

    char tmpKeyAlias[] = "HksChangeStorageLevelPart2Test001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksChangeStorageLevel failed.";

    ret = HksDeleteKey(&keyAlias, srcParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}
}
