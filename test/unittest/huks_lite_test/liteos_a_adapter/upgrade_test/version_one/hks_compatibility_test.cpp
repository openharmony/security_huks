/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_compatibility_test.h"

#include "hks_api.h"
#include "hks_client_service.h"
#include "hks_param.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_test_modify_old_key.h"
#include "hks_type_inner.h"
#include "hks_compatibility_test_c.h"
#include "cstring"
#include "unistd.h"
#include "securec.h"

using namespace testing::ext;
namespace HksCompatibilityTest {
class HksCompatibilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCompatibilityTest::SetUpTestCase(void)
{
}

void HksCompatibilityTest::TearDownTestCase(void)
{
}

void HksCompatibilityTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
    EXPECT_EQ(HksTestInitialize(), 0);
}

void HksCompatibilityTest::TearDown()
{
}

static const uint32_t HUKS_UID = 12;
static const char KEY_ALIAS[] = "test_compatibility_key";

static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = {0};

static const struct HksParam GEN_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    },
    HKS_AES_128
};

static const struct HksParam ENCYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    },
    HKS_AES_128,
    HKS_NONE_DIGEST_IV
};

static const struct HksParam DECRYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    },
    HKS_AES_128,
    HKS_NONE_DIGEST_IV
};

#define USER_ID "0"
#define OLD_PROCESS_NAME "hks_client"
static const struct HksProcessInfo OLD_PROCESS_INFO = {
    { strlen(USER_ID), (uint8_t *)USER_ID },
    { strlen(OLD_PROCESS_NAME), (uint8_t *)OLD_PROCESS_NAME },
    0,
    0
};

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest001
 * @tc.desc: test failed to get key to encrypt, and no key in old path
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest001");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ret = HksAddParams(paramSet, ENCYPT_AES_PARAMS, sizeof(ENCYPT_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};
    ret = HksEncrypt(&keyAlias, paramSet, &plainBlob, &cipherBlob);
    ASSERT_TRUE(ret == HKS_ERROR_NOT_EXIST);
    HksFreeParamSet(&paramSet);
}

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

    ret = HksTestGenerateOldKey(keyAlias, genParamSet, &OLD_PROCESS_INFO);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t TestGenerateNewkey(const struct HksBlob *keyAlias, const struct HksParam *genParams,
    uint32_t genParamsCnt)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(genParamSet, genParams, genParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "build new key paramset failed!";

    ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t TestDoEncrypt(const struct HksBlob *keyAlias, const struct HksParam *encParams, uint32_t encParamsCnt,
    struct HksBlob *plainBlob, struct HksBlob *cipherBlob)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(encryptParamSet, encParams, encParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksEncrypt(keyAlias, encryptParamSet, plainBlob, cipherBlob);

    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t TestDoDecrypt(const struct HksBlob *keyAlias, const struct HksParam *decParams, uint32_t decParamsCnt,
    struct HksBlob *cipherBlob, struct HksBlob *decryptedBlob)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(decryptParamSet, decParams, decParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksDecrypt(keyAlias, decryptParamSet, cipherBlob, decryptedBlob);

    HksFreeParamSet(&decryptParamSet);
    return ret;
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest002
 * @tc.desc: test success to get key to encrypt, and have key in old path, then success enc and dec
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest002");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);

    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);

    int32_t ret = TestGenerateOldkey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

    ret = TestDoEncrypt(&keyAlias, ENCYPT_AES_PARAMS, sizeof(ENCYPT_AES_PARAMS) / sizeof(HksParam), &plainBlob,
        &cipherBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

    ret = TestDoDecrypt(&keyAlias, DECRYPT_AES_PARAMS, sizeof(DECRYPT_AES_PARAMS) / sizeof(HksParam), &cipherBlob,
        &decryptedBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    (void)HksDeleteKey(&keyAlias, nullptr);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest003
 * @tc.desc: test and have key in old path, delete expect success
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest003");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);

    int32_t ret = TestGenerateOldkey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    ret = HksDeleteKey(&keyAlias, nullptr);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest004
 * @tc.desc: have key in old path, test to check key existance, delete and then check again, expect success
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest004");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);

    int32_t ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = TestGenerateOldkey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksDeleteKey(&keyAlias, nullptr);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);
}

static int32_t TestGenerateNewKeyInOldPath(const struct HksBlob *keyAlias, const struct HksParam *genParams,
    uint32_t genParamsCnt)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(genParamSet, genParams, genParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksServiceGenerateKey(&OLD_PROCESS_INFO, keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t HksTestDeleteNewKeyInOldPath(const struct HksBlob *keyAlias)
{
    return HksServiceDeleteKey(&OLD_PROCESS_INFO, keyAlias, nullptr);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest005
 * @tc.desc: have key in old path with new version, test to check key existance, expect fail
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest005");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);
    (void)HksTestDeleteNewKeyInOldPath(&keyAlias);

    int32_t ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = TestGenerateNewKeyInOldPath(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = HksTestDeleteNewKeyInOldPath(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest006
 * @tc.desc: have key in old path with new version, test to use key to encrypt, expect fail
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest006");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);

    int32_t ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = TestGenerateNewKeyInOldPath(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

    ret = TestDoEncrypt(&keyAlias, ENCYPT_AES_PARAMS, sizeof(ENCYPT_AES_PARAMS) / sizeof(HksParam), &plainBlob,
        &cipherBlob);

    ASSERT_TRUE(ret == HKS_ERROR_NOT_EXIST) << "ret is " << ret;

    ret = HksTestDeleteNewKeyInOldPath(&keyAlias);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest007
 * @tc.desc: have key in old path with new version, test to delete key, expect fail
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest007");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);
    (void)HksTestDeleteNewKeyInOldPath(&keyAlias);

    int32_t ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = TestGenerateNewKeyInOldPath(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    ret = HksDeleteKey(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    (void)HksTestDeleteNewKeyInOldPath(&keyAlias);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest008
 * @tc.desc: not have key in old or new path, test to delete key, expect fail
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest008");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    int32_t ret = HksDeleteKey(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);
}

static void FreeKeyInfoList(struct HksKeyInfo **infoList, uint32_t listCount)
{
    for (uint32_t i = 0; i < listCount; ++i) {
        if ((*infoList)[i].alias.data == nullptr) {
            break;
        }
        HKS_FREE((*infoList)[i].alias.data);
        if ((*infoList)[i].paramSet == nullptr) {
            break;
        }
        HksFreeParamSet(&((*infoList)[i].paramSet));
    }
    HKS_FREE(*infoList);
}

static int32_t BuildKeyInfoList(struct HksKeyInfo **outKeyInfoList, uint32_t listCount)
{
    struct HksKeyInfo *infoList = (struct HksKeyInfo *)HksMalloc(sizeof(struct HksKeyInfo) * listCount);
    if (infoList == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(infoList, sizeof(struct HksKeyInfo) * listCount, 0, sizeof(struct HksKeyInfo) * listCount);
    int32_t ret = HKS_SUCCESS;
    for (uint32_t i = 0; i < listCount; ++i) {
        infoList[i].alias.data = (uint8_t *)HksMalloc(HKS_MAX_KEY_ALIAS_LEN);
        if (infoList[i].alias.data == nullptr) {
            FreeKeyInfoList(&infoList, listCount);
            return HKS_ERROR_MALLOC_FAIL;
        }
        infoList[i].alias.size = HKS_MAX_KEY_ALIAS_LEN;
        ret = HksInitParamSet(&(infoList[i].paramSet));
        if (ret != HKS_SUCCESS) {
            FreeKeyInfoList(&infoList, listCount);
            return ret;
        }
        infoList[i].paramSet->paramSetSize = HKS_DEFAULT_PARAM_SET_SIZE;
    }
    *outKeyInfoList = infoList;
    return ret;
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest009
 * @tc.desc: generate key1 in old path and generate key2 in new path, get key info list
 *           with white list, get list including key1 and key2
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest009");
    struct HksBlob keyAlias1 = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    const char *alias2 = "alias2_for_compatibily_test";
    struct HksBlob keyAlias2 = { .size = strlen(alias2), .data = (uint8_t *)alias2};

    // generate key1 in old path
    int32_t ret = TestGenerateOldkey(&keyAlias1, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    // generate key2 in new path
    ret = TestGenerateNewkey(&keyAlias2, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    // get key info list with white list, get list including key 1 and key 2
    const uint32_t keyInfoListMaxSize = 3;
    uint32_t keyInfoListSize = keyInfoListMaxSize;
    struct HksKeyInfo *keyInfoList = nullptr;
    ret = BuildKeyInfoList(&keyInfoList, keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksGetKeyInfoList(nullptr, keyInfoList, &keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ASSERT_EQ(keyInfoListSize, 2) << "keyInfoListSize is " << keyInfoListSize;

    uint32_t hitCnt = 0;
    for (uint32_t i = 0; i < keyInfoListSize; ++i) {
        if (keyInfoList[i].alias.data != nullptr) {
            if (HksMemCmp(keyInfoList[i].alias.data, KEY_ALIAS, keyInfoList[i].alias.size) == 0 ||
                HksMemCmp(keyInfoList[i].alias.data, alias2, keyInfoList[i].alias.size) == 0) {
                ++hitCnt;
            }
            HKS_LOG_I("get key : %s", keyInfoList[i].alias.data);
        }
    }
    ASSERT_EQ(hitCnt, 2) << "hit cnt is " << hitCnt;
    (void)HksTestDeleteOldKey(&keyAlias1, &OLD_PROCESS_INFO);
    (void)HksDeleteKey(&keyAlias2, nullptr);
    FreeKeyInfoList(&keyInfoList, keyInfoListMaxSize);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest010
 * @tc.desc: generate key1 in old path, get key info list
 *           with white list, get list including key1
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest010");
    struct HksBlob keyAlias1 = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    // generate key1 in old path
    int32_t ret = TestGenerateOldkey(&keyAlias1, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    // get key info list with white list, get list including key 1
    const uint32_t keyInfoListMaxSize = 3;
    uint32_t keyInfoListSize = keyInfoListMaxSize;
    struct HksKeyInfo *keyInfoList = nullptr;
    ret = BuildKeyInfoList(&keyInfoList, keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ret = HksGetKeyInfoList(nullptr, keyInfoList, &keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ASSERT_EQ(keyInfoListSize, 1) << "keyInfoListSize is " << keyInfoListSize;

    uint32_t hitCnt = 0;
    for (uint32_t i = 0; i < keyInfoListSize; ++i) {
        if (keyInfoList[i].alias.data != nullptr) {
            if (HksMemCmp(keyInfoList[i].alias.data, KEY_ALIAS, keyInfoList[i].alias.size) == 0) {
                ++hitCnt;
            }
            HKS_LOG_I("get key : %s", keyInfoList[i].alias.data);
        }
    }
    ASSERT_EQ(hitCnt, 1) << "hit cnt is " << hitCnt;

    (void)HksTestDeleteOldKey(&keyAlias1, &OLD_PROCESS_INFO);
    FreeKeyInfoList(&keyInfoList, keyInfoListMaxSize);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest011
 * @tc.desc: generate key1 in old path with new version, expect getting empty list
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest011");
    struct HksBlob keyAlias1 = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    // generate key1 in old path with new version
    int32_t ret = TestGenerateNewKeyInOldPath(&keyAlias1, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    // get key info list with white list, get empty list
    const uint32_t keyInfoListMaxSize = 3;
    uint32_t keyInfoListSize = keyInfoListMaxSize;
    struct HksKeyInfo *keyInfoList = nullptr;
    ret = BuildKeyInfoList(&keyInfoList, keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ret = HksGetKeyInfoList(nullptr, keyInfoList, &keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    ASSERT_EQ(keyInfoListSize, 0) << "keyInfoListSize is " << keyInfoListSize;

    uint32_t hitCnt = 0;

    for (uint32_t i = 0; i < keyInfoListSize; ++i) {
        if (keyInfoList[i].alias.data != nullptr) {
            if (HksMemCmp(keyInfoList[i].alias.data, KEY_ALIAS, keyInfoList[i].alias.size) == 0) {
                ++hitCnt;
            }
            HKS_LOG_I("get key : %s", keyInfoList[i].alias.data);
        }
    }
    ASSERT_EQ(hitCnt, 0) << "hit cnt is " << hitCnt;

    (void)HksTestDeleteOldKey(&keyAlias1, &OLD_PROCESS_INFO);
    FreeKeyInfoList(&keyInfoList, keyInfoListMaxSize);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest012
 * @tc.desc: generate key1 in old path and generate key2 key3 in new path, get key info list
 *           with white list, get list including key1 and key2, with too small buffer
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest012");
    struct HksBlob keyAlias1 = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    const char *aliasName2 = "alias2_for_compatibily_test";
    struct HksBlob keyAlias2 = { .size = strlen(aliasName2), .data = (uint8_t *)aliasName2};
    const char *aliasName3 = "alias3_for_compatibily_test";
    struct HksBlob keyAlias3 = { .size = strlen(aliasName3), .data = (uint8_t *)aliasName3};

    // generate key1 in old path
    int32_t ret = TestGenerateOldkey(&keyAlias1, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    // generate key2 in new path
    ret = TestGenerateNewkey(&keyAlias2, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    // generate key3 in new path
    ret = TestGenerateNewkey(&keyAlias3, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    // get key info list with white list, get list including key 1 and key 2
    const uint32_t keyInfoListMaxSize = 2;
    uint32_t keyInfoListSize = keyInfoListMaxSize;
    struct HksKeyInfo *keyInfoList = nullptr;
    ret = BuildKeyInfoList(&keyInfoList, keyInfoListSize);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksGetKeyInfoList(nullptr, keyInfoList, &keyInfoListSize);
    ASSERT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL);

    (void)HksTestDeleteOldKey(&keyAlias1, &OLD_PROCESS_INFO);
    (void)HksDeleteKey(&keyAlias2, nullptr);
    (void)HksDeleteKey(&keyAlias3, nullptr);
    FreeKeyInfoList(&keyInfoList, keyInfoListMaxSize);
}

/**
 * @tc.name: HksCompatibilityTest.HksCompatibilityTest013
 * @tc.desc: test and have key in old path and new path, delete expect success and both keys are deleted
 * @tc.type: FUNC
 */
HWTEST_F(HksCompatibilityTest, HksCompatibilityTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCompatibilityTest013");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksTestDeleteOldKey(&keyAlias, &OLD_PROCESS_INFO);

    int32_t ret = TestGenerateOldkey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner("/storage/data/service/el1/public/huks_service/maindata", HUKS_UID);

    ret = TestGenerateNewkey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksDeleteKey(&keyAlias, nullptr);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksKeyExist(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = HksTestOldKeyExist(&keyAlias);
    ASSERT_EQ(ret, HKS_ERROR_NOT_EXIST);
}
}
