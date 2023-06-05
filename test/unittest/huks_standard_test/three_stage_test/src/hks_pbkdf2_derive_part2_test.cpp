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

#include "hks_pbkdf2_derive_part2_test.h"
#include "hks_pbkdf2_derive_test_common.h"
#include "file_ex.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::Pbkdf2Derive {
class HksPbkdf2DerivePart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksPbkdf2DerivePart2Test::SetUpTestCase(void)
{
    OHOS::SaveStringToFile("/sys/fs/selinux/enforce", "0");
}

void HksPbkdf2DerivePart2Test::TearDownTestCase(void)
{
    OHOS::SaveStringToFile("/sys/fs/selinux/enforce", "1");
}

void HksPbkdf2DerivePart2Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksPbkdf2DerivePart2Test::TearDown()
{
}

uint8_t g_saltdata2[16] = {0};

static struct HksParam g_pbkdf2StorageParams[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_TEMP
    }
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_pbkdf2Params010[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
#endif

static struct HksParam g_genParams011[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_pbkdf2Params011[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};
static struct HksParam g_genParams012[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_pbkdf2Params012[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_32
    }
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams013[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_pbkdf2Params013[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
static struct HksParam g_genParams014[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_pbkdf2Params014[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
#endif
static struct HksParam g_genParams015[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_pbkdf2Params015[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }
};
static struct HksParam g_pbkdf2Params016[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
static struct HksParam g_genParams017[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_pbkdf2Params017[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#endif
static struct HksParam g_genParams018[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};
static struct HksParam g_pbkdf2Params018[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#ifdef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParams019[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_pbkdf2Params019[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA512
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_64
    }
};
#endif

static struct HksParam g_genParams020[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_192
    }
};
static struct HksParam g_pbkdf2Params020[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_PBKDF2
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }, {
        .tag = HKS_TAG_ITERATION,
        .int32Param = DERIVE_ITERATION
    }, {
        .tag = HKS_TAG_SALT,
        .blob = {
            sizeof(g_saltdata2),
            (uint8_t *)g_saltdata2
        }
    }, {
        .tag = HKS_TAG_DERIVE_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }
};
static struct HksParam g_pbkdf2FinishParams020[] = {
    {
        .tag = HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksPBKDF2DeriveKeyAliasTest020_2"),
            (uint8_t *)"HksPBKDF2DeriveKeyAliasTest020_2"
        }
    }, {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = DERIVE_KEY_SIZE_48
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DERIVE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA384
    }
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0010
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0010, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0010_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0010_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams010, sizeof(g_genParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params010, sizeof(g_pbkdf2Params010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}
#endif

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0011
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0011, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0011_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0011_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams011, sizeof(g_genParams011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params011, sizeof(g_pbkdf2Params011) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0012
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0012, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0012_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0012_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams012, sizeof(g_genParams012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params012, sizeof(g_pbkdf2Params012) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0013
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0013, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0013_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0013_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams013, sizeof(g_genParams013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params013, sizeof(g_pbkdf2Params013) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0014
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0014, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0014_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0014_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams014, sizeof(g_genParams014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params014, sizeof(g_pbkdf2Params014) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}
#endif

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0015
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0015, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0015_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0015_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams015, sizeof(g_genParams015) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params015, sizeof(g_pbkdf2Params015) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0015
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0016, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0016_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0016_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams016, sizeof(g_genParams016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params016, sizeof(g_pbkdf2Params016) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0017
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0017, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0017_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0017_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams017, sizeof(g_genParams017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params017, sizeof(g_pbkdf2Params017) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}
#endif

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0018
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0018, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0018_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0018_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams018, sizeof(g_genParams018) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params018, sizeof(g_pbkdf2Params018) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
#ifdef L2_STANDARD
    HksPbkdf2DeriveTestCmpCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#else
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
#endif
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0019
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC    abort
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0019, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0019_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0019_1" };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams019, sizeof(g_genParams019) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2AbortParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params019, sizeof(g_pbkdf2Params019) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(&keyAlias, pbkdf2ParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update
    uint8_t outUpdateU[DERIVE_KEY_SIZE_64] = {0};
    struct HksBlob outUpdate = { DERIVE_KEY_SIZE_64, outUpdateU };
    ret = HksUpdate(&handle, pbkdf2ParamSet, &inData, &outUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";

    // Abort
    ret = InitParamSet(&pbkdf2AbortParamSet, g_pbkdf2StorageParams, sizeof(g_pbkdf2StorageParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = HksAbort(&handle, pbkdf2AbortParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Abort failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2AbortParamSet);
}
#endif

/**
 * @tc.name: HksPbkdf2DerivePart2Test.HksPbkdf2Derive0020
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256.
 * @tc.type: FUNC    abnormal
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive0020, TestSize.Level0)
{
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest0010_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest0010_1" };
    int32_t ret = HKS_FAILURE;
    uint8_t saltdata[16] = {0};
    struct HksBlob tagSaltValue = { sizeof(saltdata), (uint8_t *)saltdata };

    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    struct HksParam genParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
    };
    ret = InitParamSet(&genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. PBKDF2 Three Stage */
    ret = HksGenerateRandom(NULL, &tagSaltValue);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParam pbkdf2Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_PBKDF2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
#ifdef L2_STANDARD
        {.tag = HKS_TAG_ITERATION, .int32Param = DERIVE_ITERATION},
#else
        {.tag = HKS_TAG_ITERATION, .int32Param = 1},
#endif
        {.tag = HKS_TAG_SALT, .blob = tagSaltValue},
        {.tag = HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_64},
    };
    ret = InitParamSet(&pbkdf2ParamSet, pbkdf2Params, sizeof(pbkdf2Params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // Init
    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    ret = HksInit(NULL, pbkdf2ParamSet, &handle, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init failed.";

    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
}

/**
 * @tc.name: HksPbkdf2DerivePart1Test.HksPbkdf2Derive020
 * @tc.desc: alg-PBKDF2 pur-Derive dig-SHA256. and When generating the key, only the necessary parameters are passed in.
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksPbkdf2DerivePart2Test, HksPbkdf2Derive020, TestSize.Level0)
{
    HKS_LOG_E("Enter HksPbkdf2Derive020");
    struct HksBlob keyAlias = { strlen("HksPBKDF2DeriveKeyAliasTest020_1"),
        (uint8_t *)"HksPBKDF2DeriveKeyAliasTest020_1" };
    int32_t ret = HKS_FAILURE;
    /* 1. Generate Key */
    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams020, sizeof(g_genParams020) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 2. PBKDF2 Three Stage */
    struct HksParamSet *pbkdf2ParamSet = nullptr;
    struct HksParamSet *pbkdf2FinishParamSet = nullptr;
    ret = InitParamSet(&pbkdf2ParamSet, g_pbkdf2Params020, sizeof(g_pbkdf2Params020) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    struct HksParam *saltParam = nullptr;
    HksGetParam(pbkdf2ParamSet, HKS_TAG_SALT, &saltParam);
    ret = HksGenerateRandom(NULL, &(saltParam->blob));
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateRandom failed.";
    // Finish paramset
    ret = InitParamSet(&pbkdf2FinishParamSet, g_pbkdf2FinishParams020,
        sizeof(g_pbkdf2FinishParams020) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    // init-update-final
    HksPbkdf2DeriveTestNormalCase(keyAlias, genParamSet, pbkdf2ParamSet, pbkdf2FinishParamSet);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = { .size = strlen("HksPBKDF2DeriveKeyAliasTest020_2"),
        .data = (uint8_t *)"HksPBKDF2DeriveKeyAliasTest020_2"};
    ret = HksDeleteKey(&deleteKeyAlias, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&pbkdf2ParamSet);
    HksFreeParamSet(&pbkdf2FinishParamSet);
}
} // namespace Unittest::Pbkdf2Derive