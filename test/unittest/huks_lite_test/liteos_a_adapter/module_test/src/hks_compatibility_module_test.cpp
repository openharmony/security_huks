/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "hks_compatibility_module_test.h"

#include "hks_api.h"
#include "hks_client_service.h"
#include "hks_param.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_test_modify_old_key.h"
#include "hks_type_inner.h"

#include "cstring"
#include "unistd.h"
#include "securec.h"

using namespace testing::ext;
namespace HksCompatibilityModuleTest{
class HksCompatibilityModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCompatibilityModuleTest::SetUpTestCase(void)
{
}

void HksCompatibilityModuleTest::TearDownTestCase(void)
{
}

void HksCompatibilityModuleTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
    EXPECT_EQ(HksTestInitialize(), 0);
}

void HksCompatibilityModuleTest::TearDown()
{
}

static const char *g_keyAlias = "test_compatibility_module_key";

static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = {0};

static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

static struct HksParam g_encryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static struct HksParam g_decryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static int32_t TestGenerateOldkey(const struct HksBlob *keyAlias, const struct HksParam *genParams,
    uint32_t genParamsCnt)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(genParamSet, genParams, genParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksTestGenerateOldKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t TestDoServiceEncrypt(const struct HksBlob *keyAlias, const struct HksParam *encParams,
    uint32_t encParamsCnt, struct HksBlob *plainBlob, struct HksBlob *cipherBlob)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(encryptParamSet, encParams, encParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const char *userId = "0";
    uint32_t uid = 999;
    uint8_t *processName = (uint8_t *)HksMalloc(sizeof(uid));
    EXPECT_TRUE(processName != nullptr);
    (void)memcpy_s(processName, sizeof(uid), &uid, sizeof(uid));
    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { sizeof(uid), (uint8_t *)processName },
        0,
        0
    };

    ret = HksServiceEncrypt(&processInfo, keyAlias, encryptParamSet, plainBlob, cipherBlob);

    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t TestDoServiceDecrypt(const struct HksBlob *keyAlias, const struct HksParam *decParams,
    uint32_t decParamsCnt, struct HksBlob *cipherBlob, struct HksBlob *decryptedBlob)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(decryptParamSet, decParams, decParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    const char *userId = "0";
    uint32_t uid = 999;
    uint8_t *processName = (uint8_t *)HksMalloc(sizeof(uid));
    EXPECT_TRUE(processName != nullptr);
    (void)memcpy_s(processName, sizeof(uid), &uid, sizeof(uid));
    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { sizeof(uid), (uint8_t *)processName },
        0,
        0
    };

    ret = HksServiceDecrypt(&processInfo, keyAlias, decryptParamSet, cipherBlob, decryptedBlob);
    HksFreeParamSet(&decryptParamSet);
    return ret;
}

/**
 * @tc.name: HksCompatibilityModuleTest.HksCompatibilityModuleTest001
 * @tc.desc: and have key in old path, test to check key existance without whiteList, expect fail
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityModuleTest, HksCompatibilityModuleTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityModuleTest001");
    struct HksBlob keyAlias = { .size = strlen(g_keyAlias), .data = (uint8_t *)g_keyAlias};
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias);

    int32_t ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = TestGenerateOldkey(&keyAlias, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksChangeOldKeyOwner("/data/service/el1/public/huks_service/maindata", 12);

    const char *userId = "0";
    const char *processName1 = "123456";
    struct HksProcessInfo processInfo1 = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName1), (uint8_t *)processName1 },
        0,
        0
    };

    ret = HksServiceKeyExist(&processInfo1, &keyAlias);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    uint32_t uid = 999;
    uint8_t *processName2 = (uint8_t *)HksMalloc(sizeof(uid));
    ASSERT_TRUE(processName2 != nullptr);
    (void)memcpy_s(processName2, sizeof(uid), &uid, sizeof(uid));
    struct HksProcessInfo processInfo2 = {
        { strlen(userId), (uint8_t *)userId },
        { sizeof(uid), (uint8_t *)processName2 },
        0,
        0
    };

    ret = HksServiceKeyExist(&processInfo2, &keyAlias);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    (void)HksTestDeleteOldKey(&keyAlias);
}

/**
 * @tc.name: HksCompatibilityModuleTest.HksCompatibilityModuleTest002
 * @tc.desc: test failed to get key to encrypt, and have key in old path without whiteList, then fail to enc or dec
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityModuleTest, HksCompatibilityModuleTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityModuleTest002");
    struct HksBlob keyAlias = { .size = strlen(g_keyAlias), .data = (uint8_t *)g_keyAlias};
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias);

    int32_t ret = TestGenerateOldkey(&keyAlias, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksChangeOldKeyOwner("/data/service/el1/public/huks_service/maindata", 12);

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

    ret = TestDoServiceEncrypt(&keyAlias, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam), &plainBlob,
        &cipherBlob);

    ASSERT_TRUE(ret == HKS_ERROR_NOT_EXIST);

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

    ret = TestDoServiceDecrypt(&keyAlias, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam),
        &cipherBlob, &decryptedBlob);

    ASSERT_TRUE(ret == HKS_ERROR_NOT_EXIST);

    (void)HksTestDeleteOldKey(&keyAlias);
}

/**
 * @tc.name: HksCompatibilityModuleTest.HksCompatibilityModuleTest003
 * @tc.desc: test failed to get key to delete, and have key in old path without whiteList, then fail to delete
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityModuleTest, HksCompatibilityModuleTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityModuleTest003");
    struct HksBlob keyAlias = { .size = strlen(g_keyAlias), .data = (uint8_t *)g_keyAlias};
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias);

    int32_t ret = TestGenerateOldkey(&keyAlias, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksChangeOldKeyOwner("/data/service/el1/public/huks_service/maindata", 12);

    const char *userId = "0";
    const char *processName = "123456";
    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0
    };

    ret = HksServiceDeleteKey(&processInfo, &keyAlias);

    ASSERT_TRUE(ret == HKS_ERROR_NOT_EXIST);

    (void)HksTestDeleteOldKey(&keyAlias);
}

static void FreeKeyInfoList(struct HksKeyInfo **keyList, uint32_t listCount)
{
    for (uint32_t i = 0; i < listCount; ++i) {
        if ((*keyList)[i].alias.data == nullptr) {
            break;
        }
        HKS_FREE_PTR((*keyList)[i].alias.data);
        if ((*keyList)[i].paramSet == nullptr) {
            break;
        }
        HksFreeParamSet(&((*keyList)[i].paramSet));
    }
    HKS_FREE_PTR(*keyList);
}

static int32_t BuildKeyInfoList(struct HksKeyInfo **outKeyInfoList, uint32_t listCount)
{
    struct HksKeyInfo *keyList = (struct HksKeyInfo *)HksMalloc(sizeof(struct HksKeyInfo) * listCount);
    if (keyList == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(keyList, sizeof(struct HksKeyInfo) * listCount, 0, sizeof(struct HksKeyInfo) * listCount);
    int32_t ret = HKS_SUCCESS;
    for (uint32_t i = 0; i < listCount; ++i) {
        keyList[i].alias.data = (uint8_t *)HksMalloc(HKS_MAX_KEY_ALIAS_LEN);
        if (keyList[i].alias.data == nullptr) {
            FreeKeyInfoList(&keyList, listCount);
            return HKS_ERROR_MALLOC_FAIL;
        }
        keyList[i].alias.size = HKS_MAX_KEY_ALIAS_LEN;
        ret = HksInitParamSet(&(keyList[i].paramSet));
        if (ret != HKS_SUCCESS) {
            FreeKeyInfoList(&keyList, listCount);
            return ret;
        }
        keyList[i].paramSet->paramSetSize = HKS_DEFAULT_PARAM_SET_SIZE;
    }
    *outKeyInfoList = keyList;
    return ret;
}

/**
 * @tc.name: HksCompatibilityModuleTest.HksCompatibilityModuleTest004
 * @tc.desc: test have key in old path without whiteList, then fail to get key info list
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityModuleTest, HksCompatibilityModuleTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityModuleTest004");
    struct HksBlob keyAlias = { .size = strlen(g_keyAlias), .data = (uint8_t *)g_keyAlias};

    int32_t ret = TestGenerateOldkey(&keyAlias, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksChangeOldKeyOwner("/data/service/el1/public/huks_service/maindata", 12);

    const char *userId = "0";
    uint32_t uid = 999;
    uint8_t *processName = (uint8_t *)HksMalloc(sizeof(uid));
    ASSERT_TRUE(processName != nullptr);
    (void)memcpy_s(processName, sizeof(uid), &uid, sizeof(uid));
    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { sizeof(uid), (uint8_t *)processName },
        0,
        0
    };

    uint32_t keyInfoListSize = 3;
    struct HksKeyInfo *keyInfoList = nullptr;
    ret = BuildKeyInfoList(&keyInfoList, keyInfoListSize);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksServiceGetKeyInfoList(&processInfo, keyInfoList, &keyInfoListSize);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(keyInfoListSize, 0) << "keyInfoListSize is " << keyInfoListSize;

    (void)HksTestDeleteOldKey(&keyAlias);
    FreeKeyInfoList(&keyInfoList, keyInfoListSize);
}
}
