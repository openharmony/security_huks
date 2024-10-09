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
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_three_stage_test_common.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
 
#include <gtest/gtest.h>
 
using namespace testing::ext;
namespace Unittest::HksChangeStorageLevelTest {
class HksChangeStorageLevelTest : public testing::Test {
public:
    static void SetUpTestCase(void);
 
    static void TearDownTestCase(void);
 
    void SetUp();
 
    void TearDown();
};
 
void HksChangeStorageLevelTest::SetUpTestCase(void)
{
}
 
void HksChangeStorageLevelTest::TearDownTestCase(void)
{
}
 
void HksChangeStorageLevelTest::SetUp()
{
}
 
void HksChangeStorageLevelTest::TearDown()
{
}
 
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 };
static const uint32_t AES_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_AES_Cipher_Test_000000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
 
static struct HksParam g_encryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};
 
static struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
 
static const struct HksParam g_params001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};
 
static const struct HksParam g_params002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
 
static const struct HksParam g_params003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
 
static const struct HksParam g_params004[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
};
 
#ifdef HKS_INTERACT_ABILITY
static int32_t SetIdsToken()
{
    uint64_t tokenId;
    const char *acls[] = {
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    const char *perms[] = {
        "ohos.permission.PLACE_CALL", // system_basic
        "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };
    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "test_upgrade";
    tokenId = GetAccessTokenId(&infoInstance);
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("SetSelfTokenID fail, ret is %" LOG_PUBLIC "x!", ret);
    }
    return ret;
}
#endif
 
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest001
 * @tc.desc: upgrade DE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest001");
 
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif
 
    char tmpKeyAlias[] = "HksChangeStorageLevelTest001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest002
 * @tc.desc: upgrade DE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest002");
 
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif
 
    char tmpKeyAlias[] = "HksChangeStorageLevelTest002";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest003
 * @tc.desc: upgrade CE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest003");
 
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif
 
    char tmpKeyAlias[] = "HksChangeStorageLevelTest003";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest004
 * @tc.desc: upgrade tmpDE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest004");
 
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif
 
    char tmpKeyAlias[] = "HksChangeStorageLevelTest004";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params004, sizeof(g_params004) / sizeof(HksParam));
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
}
