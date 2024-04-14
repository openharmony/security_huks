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

#include "hks_hkdf_derive_x25519_part2_test.h"
#include "hks_hkdf_derive_test_common.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HkdfDerive {
class HksHkdfDeriveX25519Part2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHkdfDeriveX25519Part2Test::SetUpTestCase(void)
{
}

void HksHkdfDeriveX25519Part2Test::TearDownTestCase(void)
{
}

void HksHkdfDeriveX25519Part2Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksHkdfDeriveX25519Part2Test::TearDown()
{
}

static struct HksParam g_genParams031[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams031[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};

static struct HksParam g_genParams032[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams032[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};

static struct HksParam g_genParams033[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams033[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_hkdfFinishParams033[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHKDFX25519DeriveKeyAliasFinalTest033"),
            (uint8_t *)"HksHKDFX25519DeriveKeyAliasFinalTest033"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_AGREE
    }
};

static struct HksParam g_genParams034[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams034[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HKDF
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_hkdfFinishParams034[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHKDFX25519DeriveKeyAliasFinalTest034"),
            (uint8_t *)"HksHKDFX25519DeriveKeyAliasFinalTest034"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams034[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_X25519
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }
};

/**
 * @tc.name: HksHkdfDeriveX25519Part2Test.HksHKDFX25519Derive031
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDeriveX25519Part2Test, HksHKDFX25519Derive031, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHKDFX25519DeriveKeyAliasTest031"),
        (uint8_t *)"HksHKDFX25519DeriveKeyAliasTest031" };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams031, sizeof(g_genParams031) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams031, sizeof(g_hkdfParams031) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(&keyAlias, hkdfParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdate(&handle, hkdfParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "Update failed.";

    // Abort
    ret = HksAbort(&handle, hkdfParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
}

/**
 * @tc.name: HksHkdfDeriveX25519Part2Test.HksHKDFX25519Derive032
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDeriveX25519Part2Test, HksHKDFX25519Derive032, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHKDFX25519DeriveKeyAliasTest032"),
        (uint8_t *)"HksHKDFX25519DeriveKeyAliasTest032" };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams032, sizeof(g_genParams032) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams032, sizeof(g_hkdfParams032) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(&keyAlias, hkdfParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdate(&handle, hkdfParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "Update failed.";

    // Abort
    ret = HksAbort(&handle, hkdfParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
}

/**
 * @tc.name: HksHkdfDeriveX25519Part2Test.HksHKDFX25519Derive033
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDeriveX25519Part2Test, HksHKDFX25519Derive033, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHKDFX25519DeriveKeyAliasTest033"),
        (uint8_t *)"HksHKDFX25519DeriveKeyAliasTest033" };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams033, sizeof(g_genParams033) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams033, sizeof(g_hkdfParams033) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(&keyAlias, hkdfParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdate(&handle, hkdfParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";

    // Finish
    uint8_t outFinishD[COMMON_SIZE] = {0};
    struct HksBlob outFinishDerive = { COMMON_SIZE, outFinishD };
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams033, sizeof(g_hkdfFinishParams033) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = HksFinish(&handle, hkdfFinishParamSet, &inData, &outFinishDerive);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "Finish failed.";

    // Abort
    ret = HksAbort(&handle, hkdfParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHkdfDeriveX25519Part2Test.HksHKDFX25519Derive034
 * @tc.desc: alg-HKDF pur-Derive dig-SHA512.  Abort
 * @tc.type: FUNC
 */
HWTEST_F(HksHkdfDeriveX25519Part2Test, HksHKDFX25519Derive034, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHKDFX25519DeriveKeyAliasTest034"),
        (uint8_t *)"HksHKDFX25519DeriveKeyAliasTest034" };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams034, sizeof(g_genParams034) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams034, sizeof(g_hkdfParams034) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(&keyAlias, hkdfParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdate(&handle, hkdfParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";

    // Finish
    uint8_t outFinishD[COMMON_SIZE] = {0};
    struct HksBlob outFinishDerive = { COMMON_SIZE, outFinishD };
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams034, sizeof(g_hkdfFinishParams034) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = HksFinish(&handle, hkdfFinishParamSet, &inData, &outFinishDerive);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Finish failed.";

    // Init encrypt
    struct HksBlob deriveKeyAlias = { .size = strlen("HksHKDFX25519DeriveKeyAliasFinalTest034"),
        .data = (uint8_t *)"HksHKDFX25519DeriveKeyAliasFinalTest034"};
    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams034, sizeof(g_encryptParams034) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleBlobE = { sizeof(uint64_t), handleE };
    ret = HksInit(&deriveKeyAlias, encryptParamSet, &handleBlobE, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "Init encrypt failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    ret = HksDeleteKey(&deriveKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

} // namespace Unittest::HkdfDerive