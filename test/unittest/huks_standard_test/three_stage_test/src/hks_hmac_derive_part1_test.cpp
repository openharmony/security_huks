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
class HksHmacDerivePart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHmacDerivePart1Test::SetUpTestCase(void)
{
}

void HksHmacDerivePart1Test::TearDownTestCase(void)
{
}

void HksHmacDerivePart1Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksHmacDerivePart1Test::TearDown()
{
}

#ifdef L2_STANDARD
#ifndef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams001[] = {
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
static struct HksParam g_hmacParams001[] = {
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
static struct HksParam g_hmacFinishParams001[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest001"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest001"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams002[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams002[] = {
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
static struct HksParam g_hmacFinishParams002[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest002"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest002"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

static struct HksParam g_genParams003[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams003[] = {
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
static struct HksParam g_hmacFinishParams003[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest003"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest003"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_384
    }
};

static struct HksParam g_genParams004[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams004[] = {
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
static struct HksParam g_hmacFinishParams004[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest004"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest004"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_512
    }
};

static struct HksParam g_genParams005[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams005[] = {
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
        .uint32Param = DERIVE_KEY_SIZE_32
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    }
};
static struct HksParam g_hmacFinishParams005[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest005"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest005"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

static struct HksParam g_genParams006[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams006[] = {
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
        .uint32Param = DERIVE_KEY_SIZE_48
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    }
};
static struct HksParam g_hmacFinishParams006[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest006"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest006"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ECC_KEY_SIZE_384
    }
};

static struct HksParam g_genParams007[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_hmacParams007[] = {
    {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag =  HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
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
static struct HksParam g_hmacFinishParams007[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest007"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest007"
        }
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive001
 * @tc.desc: alg-HMAC pur-Derive dig-SHA256 derived_key-AES/256
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive001, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest001"), (uint8_t *)"HksHMACDeriveKeyAliasTest001" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams001, sizeof(g_hmacParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams001, sizeof(g_hmacFinishParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest001"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest001"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive002
 * @tc.desc: alg-HMAC pur-Derive dig-SHA256 derived_key-HMAC/256
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive002, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest002"), (uint8_t *)"HksHMACDeriveKeyAliasTest002" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams002, sizeof(g_hmacParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams002, sizeof(g_hmacFinishParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest002"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest002"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive003
 * @tc.desc: alg-HMAC pur-Derive dig-SHA384 derived_key-HMAC/384
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive003, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest003"), (uint8_t *)"HksHMACDeriveKeyAliasTest003" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams003, sizeof(g_hmacParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams003, sizeof(g_hmacFinishParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest003"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest003"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive004
 * @tc.desc: alg-HMAC pur-Derive dig-SHA512 derived_key-HMAC/512
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive004, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest004"), (uint8_t *)"HksHMACDeriveKeyAliasTest004" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams004, sizeof(g_hmacParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams004, sizeof(g_hmacFinishParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase1(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest004"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest004"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive005
 * @tc.desc: alg-HMAC pur-Derive dig-SHA384 derived_key-AES/256 failed
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive005, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest005"), (uint8_t *)"HksHMACDeriveKeyAliasTest005" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams005, sizeof(g_hmacParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams005, sizeof(g_hmacFinishParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase2(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_ERROR_INVALID_KEY_SIZE);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest005"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest005"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive006
 * @tc.desc: alg-HMAC pur-Derive dig-SHA512 derived_key-HMAC/384 failed
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive006, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest006"), (uint8_t *)"HksHMACDeriveKeyAliasTest006" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams006, sizeof(g_hmacParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams006, sizeof(g_hmacFinishParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase2(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_ERROR_INVALID_KEY_SIZE);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest006"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest006"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}

/**
 * @tc.name: HksHmacDerivePart1Test.HksHMACDerive007
 * @tc.desc: alg-HMAC pur-Derive dig-SHA224 derived_key-AES/256 failed
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacDerivePart1Test, HksHMACDerive007, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksHMACDeriveKeyAliasTest007"), (uint8_t *)"HksHMACDeriveKeyAliasTest007" };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams007, sizeof(g_genParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. HMAC Three Stage */
    struct HksParamSet *hkdfParamSet = nullptr;
    struct HksParamSet *hkdfFinishParamSet = nullptr;
    ret = InitParamSet(&hkdfParamSet, g_hmacParams007, sizeof(g_hmacParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // finish paramset
    ret = InitParamSet(&hkdfFinishParamSet, g_hmacFinishParams007, sizeof(g_hmacFinishParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init-Update-final
    HksHmacDeriveTestNormalCase2(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_ERROR_INVALID_KEY_SIZE);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksHMACDeriveKeyAliasFinalTest007"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest007"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
#endif
#endif
} // namespace Unittest::HmacDerive