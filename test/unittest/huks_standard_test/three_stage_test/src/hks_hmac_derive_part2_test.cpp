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

#include "hks_hmac_derive_test_common.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HmacDerive {
class HksHmacDerivePart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHmacDerivePart2Test::SetUpTestCase(void)
{
}

void HksHmacDerivePart2Test::TearDownTestCase(void)
{
}

void HksHmacDerivePart2Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksHmacDerivePart2Test::TearDown()
{
}

#ifdef L2_STANDARD
#ifndef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams010[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_hkdfParams010[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    }
};
static struct HksParam g_hkdfFinishParams010[] = {
    {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

static struct HksParam g_genParams011[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};
static struct HksParam g_hkdfParams011[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    }
};
static struct HksParam g_hkdfFinishParams011[] = {
    {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_384
    }
};

static struct HksParam g_genParams012[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ONLY_USED_IN_HUKS
    }
};
static struct HksParam g_hkdfParams012[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag =  HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    }
};
static struct HksParam g_hkdfFinishParams012[] = {
    {
        .tag =  HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_512
    }
};

/**
 * @tc.name: HksHmacDerivePart2Test.HksHMACDerive010
 * @tc.desc: alg-HMAC pur-Derive dig-SHA256 derived_key-AES/256
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart2Test, HksHMACDerive010, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest010"), (uint8_t *)"HksHMACDeriveKeyAliasTest010" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams010, sizeof(g_genParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams010, sizeof(g_hkdfParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams010, sizeof(g_hkdfFinishParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestCmpCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet);

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart2Test.HksHMACDerive011
 * @tc.desc: alg-HMAC pur-Derive dig-SHA384 derived_key-HMAC/384
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart2Test, HksHMACDerive011, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest011"), (uint8_t *)"HksHMACDeriveKeyAliasTest011" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams011, sizeof(g_genParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams011, sizeof(g_hkdfParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams011, sizeof(g_hkdfFinishParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart2Test.HksHMACDerive012
 * @tc.desc: alg-HMAC pur-Derive dig-SHA512 derived_key-HMAC/512 failed
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart2Test, HksHMACDerive012, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest012"), (uint8_t *)"HksHMACDeriveKeyAliasTest012" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams012, sizeof(g_genParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HKDF Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hkdfParams012, sizeof(g_hkdfParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hkdfFinishParams012, sizeof(g_hkdfFinishParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_ERROR_BAD_STATE);

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
#endif
#endif
} // namespace Unittest::HmacDerive