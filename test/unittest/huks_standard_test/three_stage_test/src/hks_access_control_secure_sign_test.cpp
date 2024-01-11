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

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_import_wrapped_test_common.h"
#include "hks_three_stage_test_common.h"
#include "hks_access_control_test_common.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_api.h"
#include "hks_access_control_secure_sign_test.h"

using namespace testing::ext;
using namespace Unittest::HksAccessControlPartTest;
namespace Unittest::AccessControlSecureSignTest {
class HksAccessControlSecureSignTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlSecureSignTest::SetUpTestCase(void)
{
}

void HksAccessControlSecureSignTest::TearDownTestCase(void)
{
}

void HksAccessControlSecureSignTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAccessControlSecureSignTest::TearDown()
{
}

static const std::string g_inData = "Hks_SM4_Cipher_Test_000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

static const std::string g_inDataLess64 = "Hks_SM4_Cipher_Test_000000000000000000000000000000000000";

static const uint32_t g_authHeadSize = 24;

static const uint32_t g_secureUid = 1;

static const uint32_t g_enrolledIdPin = 1;

static const uint32_t g_enrolledIdFinger = 2;

static const uint32_t g_credentialId = 0;

static const uint32_t g_time = 0;

static struct HksBlob g_genKeyAlias = {
    .size = strlen("TestGenKeyForSignWithInfo"),
    .data = (uint8_t *)"TestGenKeyForSignWithInfo"
};

static struct HksBlob g_importKeyAlias = {
    .size = strlen("TestImportKeyForSignWithInfo"),
    .data = (uint8_t *)"TestImportKeyForSignWithInfo"
};

static struct HksBlob g_importKeyNoAuthAlias = {
    .size = strlen("TestImportKeyNoSignWithInfo"),
    .data = (uint8_t *)"TestImportKeyNoSignWithInfo"
};

static const uint32_t g_outDataSize = 2048;

static uint8_t g_outBuffer[g_outDataSize] = {0};

static struct HksBlob g_outDataBlob = {
    .size = g_outDataSize,
    .data = g_outBuffer
};

static struct HksBlob g_inDataBlob = { g_inData.length(), (uint8_t *)g_inData.c_str() };

static struct HksBlob g_inDataBlobTwoStage = { g_inDataLess64.length(), (uint8_t *)g_inDataLess64.c_str() };

struct HksTestSecureSignGenParams {
    struct HksBlob *keyAlias;
    struct HksParam *inputParams;
    uint32_t inputParamSize;
    int32_t expectResult;
};

struct HksTestSecureSignImportParams {
    struct HksBlob *keyAlias;
    struct HksParam *inputParams;
    struct HksBlob importKey;
    uint32_t inputParamSize;
    int32_t expectResult;
};

struct HksTestSecureSignVerifyUpdateFinishParams {
    struct HksBlob *keyAlias;
    struct HksBlob *keyAliasNoAuth;
    struct HksParam *updateParams;
    struct HksBlob *outBuffer;
    struct HksBlob *signature;
    struct HksBlob *inData;
    uint32_t inputParamSize;
    int32_t expectResult;
    bool isThreeStageUse;
};

static struct HksParam g_genRsaWithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_RSA
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = HKS_RSA_KEY_SIZE_4096
}, {
    .tag = HKS_TAG_PADDING,
    .uint32Param = HKS_PADDING_PSS
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA512
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_PIN
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};

static struct HksParam g_genEd25519WithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_ED25519
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = HKS_CURVE25519_KEY_SIZE_256
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA1
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_FACE
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};

#ifdef _USE_OPENSSL_
// mbedtls engine don't support DSA alg
static struct HksParam g_genDsaWithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_DSA
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = 1024
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA1
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_PIN
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};
#endif

static struct HksTestSecureSignGenParams g_testRsaGenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genRsaWithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genRsaWithSignAuthParams),
    .expectResult = HKS_SUCCESS
};

static struct HksTestSecureSignGenParams g_testEd25519GenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genEd25519WithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genEd25519WithSignAuthParams),
    .expectResult = HKS_SUCCESS
};

#ifdef _USE_OPENSSL_
static struct HksTestSecureSignGenParams g_testDsaGenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genDsaWithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genDsaWithSignAuthParams),
    .expectResult = HKS_SUCCESS
};
#endif

static struct HksParam g_importDsaKeyParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
    {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
        .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
    }
};


static struct HksParam g_importDsaKeyParamsNoAuthInfo[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR }
};

static struct HksParam g_importRsaKeyParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
    {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
        .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
    }
};

static struct HksParam g_importRsaKeyParamsWithBioAndClearPassword[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
    {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
        .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
    }
};

static struct HksParam g_importRsaKeyParamsNoAuth[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR }
};

static struct HksParam g_importKeyEd25519Params[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
    {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
        .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
    }
};

static struct HksParam g_importKeyEd25519ParamsNoAuth[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR }
};

static struct HksParam g_signParamsTestRsa[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PSS
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_verifyParamsTestRsa[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PSS
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_signParamsTestDsa[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_verifyParamsTestDsa[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_signParamsTestEd25519[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ED25519
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_verifyParamsTestEd25519[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ED25519
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_CURVE25519_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static const uint8_t g_eData[] = { 0x01, 0x00, 0x01 };


static const uint8_t g_ed25519PriData[] = {
    0x61, 0xd3, 0xe7, 0x53, 0x6d, 0x79, 0x5d, 0x71, 0xc2, 0x2a, 0x51, 0x2d, 0x5e, 0xcb, 0x67, 0x3d,
    0xdd, 0xde, 0xf0, 0xac, 0xdb, 0xba, 0x24, 0xfd, 0xf8, 0x3a, 0x7b, 0x32, 0x6e, 0x05, 0xe6, 0x37,
};

static const uint8_t g_ed25519PubData[] = {
    0xab, 0xc7, 0x0f, 0x99, 0x4f, 0x6a, 0x08, 0xd0, 0x9c, 0x5d, 0x10, 0x60, 0xf8, 0x93, 0xd2, 0x8e,
    0xe0, 0x63, 0x0e, 0x70, 0xbf, 0xad, 0x30, 0x41, 0x43, 0x09, 0x27, 0x2d, 0xb3, 0x30, 0x95, 0xa7,
};

static int32_t CheckSignWithInfoTag(const struct HksBlob *alias, const struct HksParamSet *paramSet)
{
    struct HksParamSet *keyParamSet = NULL;
    int32_t ret = GenParamSetAuthTest(&keyParamSet, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenParamSetAuthTest failed.";

    ret = HksGetKeyParamSet(alias, paramSet, keyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetKeyParamSet failed.";

    struct HksParam *secureParam = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &secureParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam auth access failed.";

    struct HksParam *userParam = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_USER_AUTH_TYPE, &userParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam user auth failed.";

    struct HksParam *secSignType = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SECURE_SIGN_TYPE, &secSignType);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam secure sign type failed.";
    EXPECT_EQ(secSignType->uint32Param, HKS_SECURE_SIGN_WITH_AUTHINFO) << "HksGetParam secure sign type failed.";

    HksFreeParamSet(&keyParamSet);
    return ret;
}

static int32_t BuildImportKeyParamsForRsa(struct HksTestSecureSignImportParams *importParams, bool isAuth,
    bool isClearPasswordInvalid)
{
    if (isClearPasswordInvalid) {
        importParams->inputParams = g_importRsaKeyParamsWithBioAndClearPassword;
        importParams->inputParamSize = sizeof(g_importRsaKeyParamsWithBioAndClearPassword) /
            sizeof(g_importRsaKeyParamsWithBioAndClearPassword[0]);
    } else {
        importParams->inputParams = isAuth ? g_importRsaKeyParams : g_importRsaKeyParamsNoAuth;
        importParams->inputParamSize = isAuth ? sizeof(g_importRsaKeyParams)/sizeof(g_importRsaKeyParams[0]) :
            sizeof(g_importRsaKeyParamsNoAuth)/sizeof(g_importRsaKeyParamsNoAuth[0]);
    }

    importParams->expectResult = HKS_SUCCESS;
    uint8_t *keyBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
    if (keyBuffer == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    importParams->importKey.data = keyBuffer;
    importParams->importKey.size = MAX_KEY_SIZE;
    struct HksBlob nDataBlob = { sizeof(g_nData2048), (uint8_t *)g_nData2048 };
    struct HksBlob dData2048 = { sizeof(g_dData2048), (uint8_t *)g_dData2048 };
    struct HksBlob eData = { sizeof(g_eData), (uint8_t *)g_eData };
    int32_t ret = Unittest::HksAccessControlPartTest::ConstructRsaKeyPair(&nDataBlob, &dData2048, &eData,
        HKS_RSA_KEY_SIZE_2048, &importParams->importKey);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(keyBuffer);
    }
    return ret;
}

static int32_t BuildImportKeyParamsForDSA(struct HksTestSecureSignImportParams *importParams, bool isAuth)
{
    importParams->inputParams = isAuth ? g_importDsaKeyParams : g_importDsaKeyParamsNoAuthInfo;
    importParams->inputParamSize = isAuth ? sizeof(g_importDsaKeyParams)/sizeof(g_importDsaKeyParams[0]) :
        sizeof(g_importDsaKeyParamsNoAuthInfo)/sizeof(g_importDsaKeyParamsNoAuthInfo[0]);
    importParams->expectResult = HKS_SUCCESS;
    uint8_t *keyBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
    if (keyBuffer == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    importParams->importKey.data = keyBuffer;
    importParams->importKey.size = MAX_KEY_SIZE;
    struct HksBlob xData = { sizeof(g_xData), (uint8_t *)g_xData };
    struct HksBlob yData = { sizeof(g_yData), (uint8_t *)g_yData };
    struct HksBlob pData = { sizeof(g_pData), (uint8_t *)g_pData };
    struct HksBlob qData = { sizeof(g_qData), (uint8_t *)g_qData };
    struct HksBlob gData = { sizeof(g_gData), (uint8_t *)g_gData };
    struct TestDsaKeyParams dsaKeyParams = {
        .xData = &xData,
        .yData = &yData,
        .pData = &pData,
        .qData = &qData,
        .gData = &gData
    };
    int32_t ret = Unittest::HksAccessControlPartTest::ConstructDsaKeyPair(HKS_RSA_KEY_SIZE_2048, &dsaKeyParams,
        &importParams->importKey);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(keyBuffer);
    }
    return HKS_SUCCESS;
}

static int32_t BuildImportKeyTestParams(struct HksTestSecureSignImportParams *importParams, uint32_t alg,
    bool isAuth, bool isClearPasswordInvalid)
{
    importParams->keyAlias = isAuth ? &g_importKeyAlias : &g_importKeyNoAuthAlias;
    int32_t ret;
    switch (alg) {
        case HKS_ALG_RSA: {
            ret = BuildImportKeyParamsForRsa(importParams, isAuth, isClearPasswordInvalid);
            return ret;
        }
        case HKS_ALG_DSA: {
            ret = BuildImportKeyParamsForDSA(importParams, isAuth);
            return ret;
        }
            break;
        case HKS_ALG_ED25519: {
            importParams->inputParams = isAuth ? g_importKeyEd25519Params : g_importKeyEd25519ParamsNoAuth;
            importParams->inputParamSize = isAuth ? sizeof(g_importKeyEd25519Params)/sizeof(g_importKeyEd25519Params[0])
                : sizeof(g_importKeyEd25519ParamsNoAuth) / sizeof(g_importKeyEd25519ParamsNoAuth[0]);
            importParams->expectResult = HKS_SUCCESS;
            uint8_t *keyBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
            if (keyBuffer == nullptr) {
                return HKS_ERROR_MALLOC_FAIL;
            }
            importParams->importKey.data = keyBuffer;
            importParams->importKey.size = MAX_KEY_SIZE;
            struct HksBlob ed25519PubData = { sizeof(g_ed25519PubData), (uint8_t *)g_ed25519PubData };
            struct HksBlob ed25519PriData = { sizeof(g_ed25519PriData), (uint8_t *)g_ed25519PriData };
            ret = ConstructEd25519KeyPair(HKS_CURVE25519_KEY_SIZE_256, HKS_ALG_ED25519, &ed25519PubData,
                &ed25519PriData, &importParams->importKey);
            if (ret != HKS_SUCCESS) {
                HKS_FREE(keyBuffer);
            }
            return ret;
        }
            break;
        default:
                break;
    }
    return HKS_FAILURE;
}

static int32_t BuildUpdateFinishParams(struct HksTestSecureSignVerifyUpdateFinishParams *updateFinishParams,
    uint32_t alg, bool isThreeStage)
{
    updateFinishParams->keyAlias = &g_importKeyAlias;
    updateFinishParams->keyAliasNoAuth = &g_importKeyNoAuthAlias;
    updateFinishParams->isThreeStageUse = isThreeStage;
    g_outDataBlob.data = g_outBuffer;
    g_outDataBlob.size = sizeof(g_outBuffer);
    updateFinishParams->outBuffer = &g_outDataBlob;
    updateFinishParams->inData = isThreeStage ? &g_inDataBlob : &g_inDataBlobTwoStage;
    switch (alg) {
        case HKS_ALG_RSA: {
            updateFinishParams->updateParams = g_signParamsTestRsa;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_signParamsTestRsa);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        case HKS_ALG_ED25519: {
            updateFinishParams->updateParams = g_signParamsTestEd25519;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_signParamsTestEd25519);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        case HKS_ALG_DSA: {
            updateFinishParams->updateParams = g_signParamsTestDsa;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_signParamsTestDsa);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        default:
            break;
    }
    return HKS_FAILURE;
}

static int32_t BuildUpdateFinishVerifyParams(struct HksTestSecureSignVerifyUpdateFinishParams *updateFinishParams,
    uint32_t alg, bool isThreeStage, struct HksBlob *inData, struct HksBlob *signature)
{
    updateFinishParams->keyAlias = &g_importKeyAlias;
    updateFinishParams->keyAliasNoAuth = &g_importKeyNoAuthAlias;
    updateFinishParams->isThreeStageUse = isThreeStage;
    g_outDataBlob.data = g_outBuffer;
    g_outDataBlob.size = sizeof(g_outBuffer);
    updateFinishParams->outBuffer = &g_outDataBlob;
    updateFinishParams->inData = inData;
    updateFinishParams->signature = signature;
    switch (alg) {
        case HKS_ALG_RSA: {
            updateFinishParams->updateParams = g_verifyParamsTestRsa;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_verifyParamsTestRsa);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        case HKS_ALG_ED25519: {
            updateFinishParams->updateParams = g_verifyParamsTestEd25519;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_verifyParamsTestEd25519);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        case HKS_ALG_DSA: {
            updateFinishParams->updateParams = g_verifyParamsTestDsa;
            updateFinishParams->inputParamSize = HKS_ARRAY_SIZE(g_verifyParamsTestDsa);
            updateFinishParams->expectResult = HKS_SUCCESS;
            return HKS_SUCCESS;
        }
        default:
            break;
    }
    return HKS_FAILURE;
}

static void TestGenerateKeyWithSecureSignTag(struct HksTestSecureSignGenParams *params)
{
    struct HksParamSet *genParamSet = NULL;
    int32_t ret = InitParamSet(&genParamSet, params->inputParams, params->inputParamSize);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /**
     * @tc.steps:step1. Generate a key with user_auth_type and sign_with_info tag
     */
    ret = HksGenerateKey(params->keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey rsa key failed.";

    /**
     * @tc.steps:step2. Get key paramSet check if related key tag exist
     */
    ret = CheckSignWithInfoTag(params->keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "CheckSignWithInfoTag rsa key failed.";

    /**
     * @tc.steps:step3. Delete key and free paramSet
     */
    HksDeleteKey(params->keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
}

int32_t TestImportKeyWithSecureSignTag(struct HksTestSecureSignImportParams *params, bool ifCheckTag)
{
    struct HksParamSet *importParams = nullptr;
    int32_t ret = InitParamSet(&importParams, params->inputParams, params->inputParamSize);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /**
     * @tc.steps:step1. Import a key with user_auth_type and sign_with_info tag
     */
    ret = HksImportKey(params->keyAlias, importParams, &params->importKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey key failed.";

    if (ifCheckTag) {
        /**
         * @tc.steps:step2. Get key paramSet check if related key tag exist
         */
        ret = CheckSignWithInfoTag(params->keyAlias, importParams);
        EXPECT_EQ(ret, HKS_SUCCESS) << "CheckSignWithInfoTag rsa key failed.";
    }

    /**
     * @tc.steps:step3. Free paramSet
     */
    HksFreeParamSet(&importParams);
    return ret;
}

int32_t HksTestUpdateFinishSignAuthInfo(struct HksTestSecureSignVerifyUpdateFinishParams *updateFinishParams,
    struct HksTestGenAuthTokenParams *genAuthTokenParams)
{
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    uint8_t tmpChallenge[TOKEN_SIZE] = {0};
    struct HksBlob challenge = { sizeof(tmpChallenge), tmpChallenge };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = InitParamSet(&paramSet, updateFinishParams->updateParams, updateFinishParams->inputParamSize);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksInit(updateFinishParams->keyAlias, paramSet, &handle, &challenge);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        return HKS_FAILURE;
    }

    genAuthTokenParams->authChallenge = &challenge;

    struct HksParamSet *newParamSet = nullptr;
    ret = HksBuildAuthTokenSecure(paramSet, genAuthTokenParams, &newParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksBuildAuthTokenSecure failed.";
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        return HKS_FAILURE;
    }

    struct HksParam *tmpParam = NULL;
    ret = HksGetParam(newParamSet, HKS_TAG_PURPOSE, &tmpParam);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HksFreeParamSet(&newParamSet);
        HKS_LOG_E("get tag purpose failed.");
        return HKS_FAILURE;
    }

    if (updateFinishParams->isThreeStageUse) {
        ret = TestUpdateFinish(&handle, newParamSet, tmpParam->uint32Param, updateFinishParams->inData,
            updateFinishParams->outBuffer);
    } else {
        ret = HksFinish(&handle, newParamSet, updateFinishParams->inData, updateFinishParams->outBuffer);
    }
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HksFreeParamSet(&newParamSet);
        return HKS_FAILURE;
    }

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t VerifyUpdateFinish(struct HksBlob *handle, struct HksParamSet *newParamSet, struct HksParam *purposeParam,
    struct HksTestSecureSignVerifyUpdateFinishParams *updateFinishParams, bool isSign)
{
    int32_t ret;
    if (isSign) {
        if (updateFinishParams->isThreeStageUse) {
            ret = TestUpdateFinish(handle, newParamSet, purposeParam->uint32Param, updateFinishParams->inData,
                updateFinishParams->outBuffer);
        } else {
            ret = HksFinish(handle, newParamSet, updateFinishParams->inData, updateFinishParams->outBuffer);
        }
    } else {
        if (updateFinishParams->isThreeStageUse) {
            ret = TestUpdateFinish(handle, newParamSet, purposeParam->uint32Param, updateFinishParams->inData,
                updateFinishParams->signature);
        } else {
            ret = HksFinish(handle, newParamSet, updateFinishParams->inData, updateFinishParams->signature);
        }
    }
    return ret;
}

int32_t HksTestUpdateFinishVerifySignAuthInfo(struct HksTestSecureSignVerifyUpdateFinishParams *updateFinishParams,
    struct HksTestGenAuthTokenParams *genAuthTokenParams, bool isSign)
{
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    uint8_t tmpChallenge[TOKEN_SIZE] = {0};
    struct HksBlob challenge = { sizeof(tmpChallenge), tmpChallenge };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = InitParamSet(&paramSet, updateFinishParams->updateParams, updateFinishParams->inputParamSize);
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksInit(updateFinishParams->keyAlias, paramSet, &handle, &challenge);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        return HKS_FAILURE;
    }

    genAuthTokenParams->authChallenge = &challenge;

    struct HksParamSet *newParamSet = nullptr;
    ret = HksBuildAuthTokenSecure(paramSet, genAuthTokenParams, &newParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        return HKS_FAILURE;
    }

    struct HksParam *purposeParam = NULL;
    ret = HksGetParam(newParamSet, HKS_TAG_PURPOSE, &purposeParam);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HksFreeParamSet(&newParamSet);
        HKS_LOG_E("get tag purpose failed.");
        return HKS_FAILURE;
    }

    ret = VerifyUpdateFinish(&handle, newParamSet, purposeParam, updateFinishParams, isSign);

    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";

    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HksFreeParamSet(&newParamSet);
        return HKS_FAILURE;
    }

    return ret;
}

static const uint32_t g_fingerPrintInUserIam = 4;
static const uint32_t g_pinInUserIam = 1;

static void BuildAuthTokenParams(struct HksTestGenAuthTokenParams *authTokenParams, bool isClearPasswordInvalid)
{
    if (isClearPasswordInvalid) {
        authTokenParams->secureUid = g_secureUid;
        authTokenParams->enrolledId = g_enrolledIdFinger;
        authTokenParams->credentialId = g_credentialId;
        authTokenParams->time = g_time;
        authTokenParams->authType = g_fingerPrintInUserIam;
        return;
    }
    authTokenParams->secureUid = g_secureUid;
    authTokenParams->enrolledId = g_enrolledIdPin;
    authTokenParams->credentialId = g_credentialId;
    authTokenParams->time = g_time;
    authTokenParams->authType = g_pinInUserIam;
}

static int32_t BuildSigAndIndataBlob(struct HksBlob *sigBlob, struct HksBlob *inDataBlob,
    struct HksTestSecureSignVerifyUpdateFinishParams *secureSignUpdateFinish)
{
    int32_t ret = memcpy_s(sigBlob->data, sigBlob->size,
        secureSignUpdateFinish->outBuffer->data + g_authHeadSize,
        secureSignUpdateFinish->outBuffer->size - g_authHeadSize);
    if (ret != EOK) {
        return ret;
    }
    ret = memcpy_s(inDataBlob->data, inDataBlob->size,
        secureSignUpdateFinish->outBuffer->data, g_authHeadSize);
    if (ret != EOK) {
        return ret;
    }
    ret = memcpy_s(inDataBlob->data + g_authHeadSize, inDataBlob->size - g_authHeadSize,
        secureSignUpdateFinish->inData->data, secureSignUpdateFinish->inData->size);
    return ret;
}

static void TestImportKeyWithSignTagAndTestUseKeyCommonCase(uint32_t alg, bool isThreeStage,
    bool isClearPasswordInvalid)
{
    /**
     * @tc.steps:step1. import a key with user_auth_type and sign_with_info tag
     */
    struct HksTestSecureSignImportParams importParams;
    (void)memset_s((uint8_t *)&importParams, sizeof(struct HksTestSecureSignImportParams), 0,
        sizeof(struct HksTestSecureSignImportParams));
    int32_t ret = BuildImportKeyTestParams(&importParams, alg, true, isClearPasswordInvalid);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildImportKeyTestParams failed.";
    if (ret != HKS_SUCCESS) {
        return;
    }

    ret = TestImportKeyWithSecureSignTag(&importParams, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestImportKeyWithSecureSignTag failed.";
    if (ret != HKS_SUCCESS) {
        return;
    }

    /**
     * @tc.steps:step2. Import a key without user_auth_type and sign_with_info tag
     */
    struct HksTestSecureSignImportParams importParamsWithoutSignAuth;
    (void)memset_s((uint8_t *)&importParamsWithoutSignAuth, sizeof(struct HksTestSecureSignImportParams), 0,
        sizeof(struct HksTestSecureSignImportParams));
    ret = BuildImportKeyTestParams(&importParamsWithoutSignAuth, alg, false, isClearPasswordInvalid);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildImportKeyTestParams without sign auth failed.";
    if (ret != HKS_SUCCESS) {
        return;
    }

    /**
     * @tc.steps:step3. use the key to sign:init update finish. check the sign data whether equals the expected data
     */
    ret = TestImportKeyWithSecureSignTag(&importParamsWithoutSignAuth, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestImportKeyWithSecureSignTag2 failed.";
    struct HksTestSecureSignVerifyUpdateFinishParams secureSignUpdateFinish;
    ret = BuildUpdateFinishParams(&secureSignUpdateFinish, alg, isThreeStage);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildUpdateFinishParams failed.";

    struct HksTestGenAuthTokenParams genAuthTokenParams = { 0 };
    BuildAuthTokenParams(&genAuthTokenParams, isClearPasswordInvalid);

    ret = HksTestUpdateFinishVerifySignAuthInfo(&secureSignUpdateFinish, &genAuthTokenParams, true);
    EXPECT_EQ(ret, secureSignUpdateFinish.expectResult) << "HksTestUpdateFinishSignAuthInfo failed.";

    uint8_t sigature[secureSignUpdateFinish.outBuffer->size - g_authHeadSize];
    struct HksBlob sigBlob = {secureSignUpdateFinish.outBuffer->size - g_authHeadSize, sigature};
    uint8_t inData[secureSignUpdateFinish.inData->size + g_authHeadSize];
    struct HksBlob inDataBlob = {secureSignUpdateFinish.inData->size + g_authHeadSize, inData};
    ret = BuildSigAndIndataBlob(&sigBlob, &inDataBlob, &secureSignUpdateFinish);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildSigAndIndataBlob failed.";

    struct HksTestSecureSignVerifyUpdateFinishParams secureSignUpdateFinishVerify;
    ret = BuildUpdateFinishVerifyParams(&secureSignUpdateFinishVerify, alg, true, &inDataBlob, &sigBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "BuildUpdateFinishVerifyParams failed.";
    ret = HksTestUpdateFinishVerifySignAuthInfo(&secureSignUpdateFinishVerify, &genAuthTokenParams, false);

    HKS_FREE_BLOB(importParams.importKey);
    HKS_FREE_BLOB(importParamsWithoutSignAuth.importKey);
    HksDeleteKey(secureSignUpdateFinish.keyAlias, nullptr);
    HksDeleteKey(secureSignUpdateFinish.keyAliasNoAuth, nullptr);
}

/**
 * @tc.name: HksAccessControlSecureSignTest001
 * @tc.desc: normal case to test generate a rsa key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest001, TestSize.Level0)
{
    HKS_LOG_E("enter HksAccessControlSecureSignTest001");
    TestGenerateKeyWithSecureSignTag(&g_testRsaGenParams);
}

/**
 * @tc.name: HksAccessControlSecureSignTest002
 * @tc.desc: normal case to test generate a ed25519 key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest002, TestSize.Level0)
{
    HKS_LOG_E("enter HksAccessControlSecureSignTest002");
    TestGenerateKeyWithSecureSignTag(&g_testEd25519GenParams);
}

/**
 * @tc.name: HksAccessControlSecureSignTest003
 * @tc.desc: normal case to test generate a dsa key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest003, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    HKS_LOG_E("enter HksAccessControlSecureSignTest003");
    TestGenerateKeyWithSecureSignTag(&g_testDsaGenParams);
#endif
}

/**
 * @tc.name: HksAccessControlSecureSignTest004
 * @tc.desc: normal case to test import a rsa key with user auth type and use the key
 *           to sign data, check the signature whether equals the expected
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest004, TestSize.Level0)
{
    HKS_LOG_E("enter HksAccessControlSecureSignTest004");
    TestImportKeyWithSignTagAndTestUseKeyCommonCase(HKS_ALG_RSA, true, false);
}

/**
 * @tc.name: HksAccessControlSecureSignTest005
 * @tc.desc: normal case to test import a dsa key with user auth type and use the key
 *           to sign data, check the signature whether equals the expected
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest005, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    HKS_LOG_E("enter HksAccessControlSecureSignTest005");
    TestImportKeyWithSignTagAndTestUseKeyCommonCase(HKS_ALG_DSA, true, false);
#endif
}

/**
 * @tc.name: HksAccessControlSecureSignTest006
 * @tc.desc: normal case to test import a rsa key with user auth type and use the key:init&finish
 *           to sign data, check the signature whether equals the expected
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest006, TestSize.Level0)
{
    HKS_LOG_E("enter HksAccessControlSecureSignTest006");
    TestImportKeyWithSignTagAndTestUseKeyCommonCase(HKS_ALG_RSA, false, false);
}

/**
 * @tc.name: HksAccessControlSecureSignTest007
 * @tc.desc: normal case to test import a rsa key with auth type as fingerprint and access type as invalid clear
 *           password, check the signature whether equals the expected
 * @tc.type: FUNC
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest007, TestSize.Level0)
{
    HKS_LOG_E("enter HksAccessControlSecureSignTest007");
    TestImportKeyWithSignTagAndTestUseKeyCommonCase(HKS_ALG_RSA, true, true);
}
}
