/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_ecdh_agree_part1_test.h"
#include "hks_ecdh_agree_test_common.h"
#include "hks_struct_macro_def.h"

#include "hks_agree_test_common.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::EcdhAgree {
class HksEcdhAgreePart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksEcdhAgreePart1Test::SetUpTestCase(void)
{
}

void HksEcdhAgreePart1Test::TearDownTestCase(void)
{
}

void HksEcdhAgreePart1Test::SetUp()
{
}

void HksEcdhAgreePart1Test::TearDown()
{
}

static struct HksBlob g_keyAlias01002 = {
    strlen("HksECDHAgreeKeyAliasTest002_1"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest002_1"
};
static struct HksBlob g_keyAlias02002 = {
    strlen("HksECDHAgreeKeyAliasTest002_2"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest002_2"
};
static struct HksBlob g_keyAliasFinal1002 = {
    strlen("HksECDHAgreeKeyAliasTest002_1_final"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest002_1_final"
};
static struct HksBlob g_keyAliasFinal2002 = {
    strlen("HksECDHAgreeKeyAliasTest002_2_final"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest002_2_final"
};
static struct HksParam g_genParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ECC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};
static struct HksParam g_agreeParams01Init002[] = {
    HKS_AGREE_FINISH_ECDH_256_COMMON
};
static struct HksParam g_agreeParams01Finish002[] = {
    HKS_DERIVE_FINISH_AES_256_COMMON
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal1002
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};
static struct HksParam g_agreeParams02Init002[] = {
    HKS_AGREE_FINISH_ECDH_256_COMMON
};
static struct HksParam g_agreeParams02Finish002[] = {
    HKS_DERIVE_FINISH_AES_256_COMMON
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal2002
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksBlob g_keyAlias01005 = {
    strlen("HksECDHAgreeKeyAliasTest005_1"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest005_1"
};
static struct HksBlob g_keyAlias02005 = {
    strlen("HksECDHAgreeKeyAliasTest005_2"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest005_2"
};
static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ECC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_224
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};
static struct HksParam g_agreeParams01Init005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ECDH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_224
    }
};
static struct HksParam g_agreeParams01Finish005[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};
static struct HksParam g_agreeParams02Init005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ECDH
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_224
    }
};
static struct HksParam g_agreeParams02Finish005[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};
#endif

/**
 * @tc.name: HksEcdhAgreePart1Test.HksEcdhAgree002
 * @tc.desc: alg-EDCH, pur-AGREE, size-256
 * @tc.type: FUNC
 */
HWTEST_F(HksEcdhAgreePart1Test, HksEcdhAgree002, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init002, sizeof(g_agreeParams01Init002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish002,
        sizeof(g_agreeParams01Finish002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init002, sizeof(g_agreeParams02Init002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish002,
        sizeof(g_agreeParams02Finish002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01002, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02002, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_ECC_KEY_SIZE_256, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_ECC_KEY_SIZE_256, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksEcdhAgreeExport(&g_keyAlias01002, &g_keyAlias02002, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = ECDH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = ECDH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksEcdhAgreeFinish(&g_keyAlias01002, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEcdhAgreeFinish01 failed.";
    ret = HksEcdhAgreeFinish(&g_keyAlias02002, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEcdhAgreeFinish02 failed.";

    ret = TestAgreedKeyUse(&g_keyAliasFinal1002, &g_keyAliasFinal2002);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAgreedKeyUse failed.";

    HksDeleteKey(&g_keyAlias01002, genParamSet);
    HksDeleteKey(&g_keyAlias02002, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1002, NULL);
    HksDeleteKey(&g_keyAliasFinal2002, NULL);
    HksEcdhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksEcdhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksEcdhAgreePart1Test.HksEcdhAgree005
 * @tc.desc: alg-EDCH, pur-AGREE, size-521
 * @tc.type: FUNC
 */
HWTEST_F(HksEcdhAgreePart1Test, HksEcdhAgree005, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init005, sizeof(g_agreeParams01Init005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParams01Finish005,
        sizeof(g_agreeParams01Finish005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init005, sizeof(g_agreeParams02Init005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParams02Finish005,
        sizeof(g_agreeParams02Finish005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01005, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02005, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_ECC_KEY_SIZE_224, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_ECC_KEY_SIZE_224, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksEcdhAgreeExport(&g_keyAlias01005, &g_keyAlias02005, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = ECDH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = ECDH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksEcdhAgreeFinish(&g_keyAlias01005, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEcdhAgreeFinish01 failed.";
    ret = HksAgreeKey(initParamSet02, &g_keyAlias02005, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKey(&g_keyAlias01005, genParamSet);
    HksDeleteKey(&g_keyAlias02005, genParamSet);
    HksEcdhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksEcdhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}
#endif
} // namespace Unittest::EcdhAgree