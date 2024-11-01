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
#include "hks_file_operator.h"
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
static const char *STORE_PATH = "/data/service/el1/public/huks_service/maindata/0/0/key/";

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

/**
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest005
 * @tc.desc: upgrade CE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest005");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest005";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest006
 * @tc.desc: upgrade ECE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest006");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest006";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest007
 * @tc.desc: upgrade ECE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest007");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest007";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest008
 * @tc.desc: upgrade DE to DE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest008");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest008";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest009
 * @tc.desc: upgrade CE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest009");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest009";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest010
 * @tc.desc: upgrade ECE to ECE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest010");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest010";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params003, sizeof(g_params003) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest011
 * @tc.desc: upgrade DE to tmpDE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest011");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest011";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest012
 * @tc.desc: upgrade DE to CE, srcParamSet is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest012");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest012";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest013
 * @tc.desc: upgrade DE to CE, desParamSet is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest013, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest013");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest013";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest014
 * @tc.desc: upgrade DE to CE, srcParamSet HKS_TAG_AUTH_STORAGE_LEVEL is 10
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest014, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest014");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest014";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest015
 * @tc.desc: upgrade DE to CE, desParamSet HKS_TAG_AUTH_STORAGE_LEVEL is 10
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest015, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest015");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest015";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest016
 * @tc.desc: upgrade DE to CE, keyAlias is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest016, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest016");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest016";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest017
 * @tc.desc: upgrade DE to CE, src key not exist, des key not exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest017, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest017");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest017";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest018
 * @tc.desc: upgrade DE to CE, src key not exist, des key maindata not exist, des key backup exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest018, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest018");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    
    char tmpKeyAlias[] = "HksChangeStorageLevelTest018";
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest019
 * @tc.desc: upgrade DE to CE, src key exist, des key maindata exist
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest019, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest019");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest019";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";
    
    char desTmpKeyAlias[] = "HksChangeStorageLevelTest019";
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest020
 * @tc.desc: upgrade DE to CE, pressure test
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest020, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest020");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest020_00";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest021
 * @tc.desc: upgrade DE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest021, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest021");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest021";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
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
 * @tc.name: HksChangeStorageLevelTest.HksChangeStorageLevelTest022
 * @tc.desc: upgrade DE to CE, src key exist, des key not exist, delete src key fail
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelTest, HksChangeStorageLevelTest022, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelTest022");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksChangeStorageLevelTest022";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_KEY_CLEAR_FAILED) << "HksChangeStorageLevel failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}
}
