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
#include "hks_param.h"
#include "hks_type.h"
#include "hks_template.h"
#include "hks_three_stage_test_common.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::CeUpdateTest {
class HksCeUpdateTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCeUpdateTest::SetUpTestCase(void)
{
}

void HksCeUpdateTest::TearDownTestCase(void)
{
}

void HksCeUpdateTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksCeUpdateTest::TearDown()
{
}

static const std::vector<HksBlob> g_validKeyAlias = {
#ifdef HKS_INTERACT_ABILITY
    {
        sizeof("HksValidTestKey001"),
        (uint8_t *)"HksValidTestKey001"
    }, {
        sizeof("HksValidTestKey002"),
        (uint8_t *)"HksValidTestKey002"
    }, {
        sizeof("HksValidTestKey003"),
        (uint8_t *)"HksValidTestKey003"
    }, {
        sizeof("HksValidTestKey004"),
        (uint8_t *)"HksValidTestKey004"
    }, {
        sizeof("HksValidTestKey005"),
        (uint8_t *)"HksValidTestKey005"
    }, {
        sizeof("HksValidTestKey006"),
        (uint8_t *)"HksValidTestKey006"
    },
#endif
    {
        sizeof("HksValidTestKey007"),
        (uint8_t *)"HksValidTestKey007"
    }, {
        sizeof("HksValidTestKey008"),
        (uint8_t *)"HksValidTestKey008"
    }
};

static const std::vector<HksBlob> g_invalidKeyAlias = {
#ifdef HKS_INTERACT_ABILITY
    {
        sizeof("HksInvalidTestKey001"),
        (uint8_t *)"HksInvalidTestKey001"
    }, {
        sizeof("HksInvalidTestKey002"),
        (uint8_t *)"HksInvalidTestKey002"
    }, {
        sizeof("HksInvalidTestKey003"),
        (uint8_t *)"HksInvalidTestKey003"
    }, {
        sizeof("HksInvalidTestKey004"),
        (uint8_t *)"HksInvalidTestKey004"
    }, {
        sizeof("HksInvalidTestKey005"),
        (uint8_t *)"HksInvalidTestKey005"
    }, {
        sizeof("HksInvalidTestKey006"),
        (uint8_t *)"HksInvalidTestKey006"
    },
#endif
    {
        sizeof("HksInvalidTestKey007"),
        (uint8_t *)"HksInvalidTestKey007"
    }, {
        sizeof("HksInvalidTestKey008"),
        (uint8_t *)"HksInvalidTestKey008"
    }
};

static const std::vector<HksBlob> g_validKeyAliasEcc = {
#ifdef HKS_INTERACT_ABILITY
    {
        sizeof("HksValidTestKeyEcc001"),
        (uint8_t *)"HksValidTestKeyEcc001"
    }, {
        sizeof("HksValidTestKeyEcc002"),
        (uint8_t *)"HksValidTestKeyEcc002"
    }, {
        sizeof("HksValidTestKeyEcc003"),
        (uint8_t *)"HksValidTestKeyEcc003"
    }, {
        sizeof("HksValidTestKeyEcc004"),
        (uint8_t *)"HksValidTestKeyEcc004"
    }, {
        sizeof("HksValidTestKeyEcc005"),
        (uint8_t *)"HksValidTestKeyEcc005"
    }, {
        sizeof("HksValidTestKeyEcc006"),
        (uint8_t *)"HksValidTestKeyEcc006"
    },
#endif
    {
        sizeof("HksValidTestKeyEcc007"),
        (uint8_t *)"HksValidTestKeyEcc007"
    }, {
        sizeof("HksValidTestKeyEcc008"),
        (uint8_t *)"HksValidTestKeyEcc008"
    }
};

static const std::vector<HksBlob> g_invalidKeyAliasEcc = {
#ifdef HKS_INTERACT_ABILITY
    {
        sizeof("HksInvalidTestKeyEcc001"),
        (uint8_t *)"HksInvalidTestKeyEcc001"
    }, {
        sizeof("HksInvalidTestKeyEcc002"),
        (uint8_t *)"HksInvalidTestKeyEcc002"
    }, {
        sizeof("HksInvalidTestKeyEcc003"),
        (uint8_t *)"HksInvalidTestKeyEcc003"
    }, {
        sizeof("HksInvalidTestKeyEcc004"),
        (uint8_t *)"HksInvalidTestKeyEcc004"
    }, {
        sizeof("HksInvalidTestKeyEcc005"),
        (uint8_t *)"HksInvalidTestKeyEcc005"
    }, {
        sizeof("HksInvalidTestKeyEcc006"),
        (uint8_t *)"HksInvalidTestKeyEcc006"
    },
#endif
    {
        sizeof("HksInvalidTestKeyEcc007"),
        (uint8_t *)"HksInvalidTestKeyEcc007"
    }, {
        sizeof("HksInvalidTestKeyEcc008"),
        (uint8_t *)"HksInvalidTestKeyEcc008"
    }
};

static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = {0};

static const std::vector<std::vector<HksParam>> g_validParam = {
#ifdef HKS_INTERACT_ABILITY
    {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 0 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 1 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
    },
#endif
    {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    }, {
    },
};

static const std::vector<std::vector<HksParam>> g_invalidParam = {
#ifdef HKS_INTERACT_ABILITY
    {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 0 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 0 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 1 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 1 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 0 },
    }, {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 1 },
    },
#endif
    {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    }, {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    },
};

static const struct HksParam g_genParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
};

static const struct HksParam g_encryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
};

static const struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
};

static const struct HksParam g_exportParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
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
    infoInstance.processName = "test_movece";
    tokenId = GetAccessTokenId(&infoInstance);
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("SetSelfTokenID fail, ret is %" LOG_PUBLIC "x!", ret);
    }
    return ret;
}
#endif

static int32_t BuildParamSet(const struct HksParam *param, const std::vector<HksParam> &tagParam,
    uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (param != nullptr && paramCnt > 0) {
            ret = HksAddParams(paramSet, param, paramCnt);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }

        for (std::size_t i = 0; i < tagParam.size(); i++) {
            ret = HksAddParams(paramSet, &tagParam[i], 1);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}

static void FreeKeyInfoList(struct HksKeyInfo **keyInfoList, uint32_t listCount)
{
    for (uint32_t i = 0; i < listCount; ++i) {
        if ((*keyInfoList)[i].alias.data == nullptr) {
            break;
        }
        HKS_FREE((*keyInfoList)[i].alias.data);
        if ((*keyInfoList)[i].paramSet == nullptr) {
            break;
        }
        HksFreeParamSet(&((*keyInfoList)[i].paramSet));
    }
    HKS_FREE(*keyInfoList);
}

static int32_t BuildKeyInfoList(struct HksKeyInfo **outKeyInfoList, uint32_t listCount)
{
    struct HksKeyInfo *keyInfoList = (struct HksKeyInfo *)HksMalloc(sizeof(struct HksKeyInfo) * listCount);
    if (keyInfoList == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(keyInfoList, sizeof(struct HksKeyInfo) * listCount, 0, sizeof(struct HksKeyInfo) * listCount);
    int32_t ret = HKS_SUCCESS;
    for (uint32_t i = 0; i < listCount; ++i) {
        keyInfoList[i].alias.data = (uint8_t *)HksMalloc(HKS_MAX_KEY_ALIAS_LEN);
        if (keyInfoList[i].alias.data == nullptr) {
            FreeKeyInfoList(&keyInfoList, listCount);
            return HKS_ERROR_MALLOC_FAIL;
        }
        keyInfoList[i].alias.size = HKS_MAX_KEY_ALIAS_LEN;
        ret = HksInitParamSet(&(keyInfoList[i].paramSet));
        if (ret != HKS_SUCCESS) {
            FreeKeyInfoList(&keyInfoList, listCount);
            return ret;
        }
        keyInfoList[i].paramSet->paramSetSize = HKS_DEFAULT_PARAM_SET_SIZE;
    }
    *outKeyInfoList = keyInfoList;
    return ret;
}

static void EncryptOnThreeStage(const struct HksParamSet *encryptParamSet, const struct HksBlob *keyAlias,
    struct HksBlob *plainBlob, struct HksBlob *cipherBlob, bool expectSuccess)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    if (expectSuccess) {
        ASSERT_EQ(ret, HKS_SUCCESS);
    } else {
        ASSERT_NE(ret, HKS_SUCCESS);
    }

    ret = TestUpdateLoopFinish(&handleEncrypt, encryptParamSet, plainBlob, cipherBlob);
    if (expectSuccess) {
        ASSERT_EQ(ret, HKS_SUCCESS);
    } else {
        ASSERT_NE(ret, HKS_SUCCESS);
    }
}

static void DecryptOnThreeStage(const struct HksParamSet *decryptParamSet, const struct HksBlob *keyAlias,
    struct HksBlob *cipherBlob, struct HksBlob *decryptedBlob, bool expectSuccess)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    if (expectSuccess) {
        ASSERT_EQ(ret, HKS_SUCCESS);
    } else {
        ASSERT_NE(ret, HKS_SUCCESS);
    }

    ret = TestUpdateLoopFinish(&handleDecrypt, decryptParamSet, cipherBlob, decryptedBlob);
    if (expectSuccess) {
        ASSERT_EQ(ret, HKS_SUCCESS);
    } else {
        ASSERT_NE(ret, HKS_SUCCESS);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest001");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_genParams, g_validParam[i], HKS_ARRAY_SIZE(g_genParams), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGenerateKey(&g_validKeyAlias[i], paramSet, nullptr);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAlias[i], paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSet);
    }

    struct HksParamSet *paramSetEcc = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_exportParams, g_validParam[i], HKS_ARRAY_SIZE(g_exportParams), &paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGenerateKey(&g_validKeyAliasEcc[i], paramSetEcc, nullptr);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAliasEcc[i], paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSetEcc);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest002");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(g_genParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_genParams), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGenerateKey(&g_invalidKeyAlias[i], paramSet, nullptr);
        ASSERT_NE(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_invalidKeyAlias[i], paramSet);
        ASSERT_NE(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSet);
    }

    struct HksParamSet *paramSetEcc = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(g_exportParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_exportParams), &paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGenerateKey(&g_invalidKeyAliasEcc[i], paramSetEcc, nullptr);
        ASSERT_NE(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_invalidKeyAliasEcc[i], paramSetEcc);
        ASSERT_NE(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSetEcc);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest003");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_encryptParams, g_validParam[i], HKS_ARRAY_SIZE(g_encryptParams), &encryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t plainText[] = "plainText123456";
        uint8_t cipherText[1024] = { 0 };
        struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
        struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};
        ret = HksEncrypt(&g_validKeyAlias[i], encryptParamSet, &plainBlob, &cipherBlob);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = BuildParamSet(g_decryptParams, g_validParam[i], HKS_ARRAY_SIZE(g_decryptParams), &decryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};
        ret = HksDecrypt(&g_validKeyAlias[i], decryptParamSet, &cipherBlob, &decryptedBlob);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&encryptParamSet);
        HksFreeParamSet(&decryptParamSet);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest004");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;

    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(g_encryptParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_encryptParams), &encryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t plainText[] = "plainText123456";
        uint8_t cipherText[1024] = { 0 };
        struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
        struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};
        ret = HksEncrypt(&g_invalidKeyAlias[i], encryptParamSet, &plainBlob, &cipherBlob);
        ASSERT_NE(ret, HKS_SUCCESS);

        ret = BuildParamSet(g_decryptParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_decryptParams), &decryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};
        ret = HksDecrypt(&g_invalidKeyAlias[i], decryptParamSet, &cipherBlob, &decryptedBlob);
        ASSERT_NE(ret, HKS_SUCCESS);

        HksFreeParamSet(&encryptParamSet);
        HksFreeParamSet(&decryptParamSet);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest005");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_encryptParams, g_validParam[i], HKS_ARRAY_SIZE(g_encryptParams), &encryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t plainText[] = "plainText123456";
        uint8_t cipherText[1024] = { 0 };
        struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
        struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

        EncryptOnThreeStage(encryptParamSet, &g_validKeyAlias[i], &plainBlob, &cipherBlob, true);

        uint8_t cipherTextOneStage[1024] = { 0 };
        struct HksBlob cipherBlobOneStage = { .size = HKS_ARRAY_SIZE(cipherTextOneStage), .data = cipherTextOneStage};
        ret = HksEncrypt(&g_validKeyAlias[i], encryptParamSet, &plainBlob, &cipherBlobOneStage);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksMemCmp(cipherTextOneStage, cipherText, HKS_ARRAY_SIZE(cipherTextOneStage));
        ASSERT_EQ(ret, HKS_SUCCESS);

        /* Decrypt */
        ret = BuildParamSet(g_decryptParams, g_validParam[i], HKS_ARRAY_SIZE(g_decryptParams), &decryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

        DecryptOnThreeStage(decryptParamSet, &g_validKeyAlias[i], &cipherBlob, &decryptedBlob, true);

        uint8_t decryptedTextOneStage[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlobOneStage = { .size = HKS_ARRAY_SIZE(decryptedTextOneStage),
            .data = decryptedTextOneStage};
        ret = HksDecrypt(&g_validKeyAlias[i], decryptParamSet, &cipherBlob, &decryptedBlobOneStage);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksMemCmp(decryptedText, decryptedTextOneStage, HKS_ARRAY_SIZE(decryptedText));
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&encryptParamSet);
        HksFreeParamSet(&decryptParamSet);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest006");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(g_encryptParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_encryptParams), &encryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t plainText[] = "plainText123456";
        uint8_t cipherText[1024] = { 0 };
        struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
        struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

        EncryptOnThreeStage(encryptParamSet, &g_invalidKeyAlias[i], &plainBlob, &cipherBlob, false);

        uint8_t cipherTextOneStage[1024] = { 0 };
        struct HksBlob cipherBlobOneStage = { .size = HKS_ARRAY_SIZE(cipherTextOneStage), .data = cipherTextOneStage};
        ret = HksEncrypt(&g_invalidKeyAlias[i], encryptParamSet, &plainBlob, &cipherBlobOneStage);
        ASSERT_NE(ret, HKS_SUCCESS);

        /* Decrypt */
        ret = BuildParamSet(g_decryptParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_decryptParams), &decryptParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

        DecryptOnThreeStage(decryptParamSet, &g_invalidKeyAlias[i], &cipherBlob, &decryptedBlob, false);

        uint8_t decryptedTextOneStage[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
        struct HksBlob decryptedBlobOneStage = { .size = HKS_ARRAY_SIZE(decryptedTextOneStage),
            .data = decryptedTextOneStage};
        ret = HksDecrypt(&g_invalidKeyAlias[i], decryptParamSet, &cipherBlob, &decryptedBlobOneStage);
        ASSERT_NE(ret, HKS_SUCCESS);

        HksFreeParamSet(&encryptParamSet);
        HksFreeParamSet(&decryptParamSet);
    }
}

static const uint32_t g_initKeyInfoListNum = 15;
HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest007");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *infoListParamSet = nullptr;
    struct HksKeyInfo *keyInfoList = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(nullptr, g_validParam[i], 0, &infoListParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint32_t listCount = g_initKeyInfoListNum;
        ret = BuildKeyInfoList(&keyInfoList, g_initKeyInfoListNum);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGetKeyInfoList(infoListParamSet, keyInfoList, &listCount);
        ASSERT_EQ(ret, HKS_SUCCESS);

        for (uint32_t i = 0; i < listCount; ++i) {
            if (keyInfoList[i].alias.data != nullptr) {
                HKS_LOG_I("get key : %" LOG_PUBLIC "s", keyInfoList[i].alias.data);
            }
        }
        HksFreeParamSet(&infoListParamSet);
        FreeKeyInfoList(&keyInfoList, g_initKeyInfoListNum);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest008");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    struct HksKeyInfo *keyInfoList = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(g_genParams, g_invalidParam[i], HKS_ARRAY_SIZE(g_genParams), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        uint32_t listCount = g_initKeyInfoListNum;
        ret = BuildKeyInfoList(&keyInfoList, g_initKeyInfoListNum);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGetKeyInfoList(paramSet, keyInfoList, &listCount);
        ASSERT_NE(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSet);
        FreeKeyInfoList(&keyInfoList, g_initKeyInfoListNum);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest009");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *exportParamSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        HksBlob publicKey = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)HksMalloc(HKS_ECC_KEY_SIZE_256) };
        ret = BuildParamSet(nullptr, g_validParam[i], 0, &exportParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksExportPublicKey(&g_validKeyAliasEcc[i], exportParamSet, &publicKey);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HKS_FREE(publicKey.data);
        HksFreeParamSet(&exportParamSet);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest010");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *exportParamSet = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        HksBlob publicKey = { .size = HKS_ECC_KEY_SIZE_256, .data = (uint8_t *)HksMalloc(HKS_ECC_KEY_SIZE_256) };
        ret = BuildParamSet(nullptr, g_invalidParam[i], 0, &exportParamSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksExportPublicKey(&g_invalidKeyAliasEcc[i], exportParamSet, &publicKey);
        ASSERT_NE(ret, HKS_SUCCESS);
        HKS_FREE(publicKey.data);
        HksFreeParamSet(&exportParamSet);
    }
}

static const uint32_t keyParamsetSize = 1024;
HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest011");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(nullptr, g_validParam[i], 0, &paramSetIn);
        ASSERT_EQ(ret, HKS_SUCCESS);

        struct HksParam getParam = {
            .tag = HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA,
            .blob = { .size = keyParamsetSize, .data = (uint8_t *)HksMalloc(keyParamsetSize) }
        };
        ASSERT_NE(getParam.blob.data, nullptr);

        ret = HksInitParamSet(&paramSetOut);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ret = HksAddParams(paramSetOut, &getParam, 1);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ret = HksBuildParamSet(&paramSetOut);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGetKeyParamSet(&g_validKeyAliasEcc[i], paramSetIn, paramSetOut);
        ASSERT_EQ(ret, HKS_SUCCESS);

        struct HksParam *keySizeParam = nullptr;
        ret = HksGetParam(paramSetOut, HKS_TAG_KEY_SIZE, &keySizeParam);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ASSERT_EQ(keySizeParam->uint32Param, HKS_ECC_KEY_SIZE_256);

        struct HksParam *purposeParam = nullptr;
        ret = HksGetParam(paramSetOut, HKS_TAG_PURPOSE, &purposeParam);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ASSERT_EQ(purposeParam->uint32Param, HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY);

        HKS_FREE(getParam.blob.data);
        HksFreeParamSet(&paramSetIn);
        HksFreeParamSet(&paramSetOut);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest012");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSetIn = nullptr;
    struct HksParamSet *paramSetOut = nullptr;
    for (std::size_t i = 0; i < g_invalidParam.size(); i++) {
        ret = BuildParamSet(nullptr, g_invalidParam[i], 0, &paramSetIn);
        ASSERT_EQ(ret, HKS_SUCCESS);

        struct HksParam getParam = {
            .tag = HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA,
            .blob = { .size = keyParamsetSize, .data = (uint8_t *)HksMalloc(keyParamsetSize) }
        };
        ASSERT_NE(getParam.blob.data, nullptr);

        ret = HksInitParamSet(&paramSetOut);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ret = HksAddParams(paramSetOut, &getParam, 1);
        ASSERT_EQ(ret, HKS_SUCCESS);
        ret = HksBuildParamSet(&paramSetOut);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksGetKeyParamSet(&g_invalidKeyAliasEcc[i], paramSetIn, paramSetOut);
        ASSERT_NE(ret, HKS_SUCCESS);

        HKS_FREE(getParam.blob.data);
        HksFreeParamSet(&paramSetIn);
        HksFreeParamSet(&paramSetOut);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest013, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest013");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_genParams, g_validParam[i], HKS_ARRAY_SIZE(g_genParams), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAlias[i], paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSet);
    }

    struct HksParamSet *paramSetEcc = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_exportParams, g_validParam[i], HKS_ARRAY_SIZE(g_exportParams), &paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAliasEcc[i], paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        HksFreeParamSet(&paramSetEcc);
    }
}

HWTEST_F(HksCeUpdateTest, HksCeUpdatePartTest014, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCeUpdatePartTest014");

    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    ASSERT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksParamSet *paramSet = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_genParams, g_validParam[i], HKS_ARRAY_SIZE(g_genParams), &paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksDeleteKey(&g_validKeyAlias[i], paramSet);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAlias[i], paramSet);
        ASSERT_NE(ret, HKS_SUCCESS);
        HksFreeParamSet(&paramSet);
    }

    struct HksParamSet *paramSetEcc = nullptr;
    for (std::size_t i = 0; i < g_validParam.size(); i++) {
        ret = BuildParamSet(g_exportParams, g_validParam[i], HKS_ARRAY_SIZE(g_exportParams), &paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksDeleteKey(&g_validKeyAliasEcc[i], paramSetEcc);
        ASSERT_EQ(ret, HKS_SUCCESS);

        ret = HksKeyExist(&g_validKeyAliasEcc[i], paramSetEcc);
        ASSERT_NE(ret, HKS_SUCCESS);
        HksFreeParamSet(&paramSetEcc);
    }
}
}