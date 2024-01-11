/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "hks_import_wrapped_test_common.h"
#include "hks_three_stage_test_common.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_type.h"

#include "hks_import_wrapped_sm2_suite_test.h"

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::ImportWrappedKey {
    class HksImportWrappedSm2SuiteTest : public testing::Test {
    public:
        static void SetUpTestCase(void);

        static void TearDownTestCase(void);

        void SetUp();

        void TearDown();
    };

    void HksImportWrappedSm2SuiteTest::SetUpTestCase(void)
    {
    }

    void HksImportWrappedSm2SuiteTest::TearDownTestCase(void)
    {
    }

    void HksImportWrappedSm2SuiteTest::SetUp()
    {
        EXPECT_EQ(HksInitialize(), 0);
    }

    void HksImportWrappedSm2SuiteTest::TearDown()
    {
    }

    /* -------- Start of sm2 unwrap algorithm suite common import key material and params define -------- */

    static struct HksParam g_genWrappingKeyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC}};

    static struct HksParam g_genCallerSm2Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3}};

    static struct HksParam g_signDataParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3},
    };

    static struct HksParam g_sm2EncryptParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
    };
    static uint8_t g_hksSm4TestIv[HKS_SM4_IV_SIZE] = {0};
    static struct HksBlob g_Iv = {
        .size = HKS_SM4_IV_SIZE,
        .data = (uint8_t *)g_hksSm4TestIv};

    static struct HksParam g_sm4EncryptParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_IV, .blob = {.size = HKS_SM4_IV_SIZE, .data = (uint8_t *)g_hksSm4TestIv}},
    };

    static struct HksParam g_sm4MacParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},

        {.tag = HKS_TAG_IV, .blob = {.size = HKS_SM4_IV_SIZE, .data = (uint8_t *)g_hksSm4TestIv}},
    };

    static struct HksParam g_sm3Params1[] = {
        {.tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_GMKDF},
        {.tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DERIVE},
        {.tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3},
        {.tag = HKS_TAG_DERIVE_KEY_SIZE,
            .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_INFO,
            .blob = {
            .size = strlen("The factor1"),
             .data = (uint8_t *)"The factor1"}}};

    static struct HksParam g_sm3Params2[] = {
        {.tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_GMKDF},
        {.tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DERIVE},
        {.tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3},
        {.tag = HKS_TAG_DERIVE_KEY_SIZE,
            .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_INFO,
            .blob = {
            .size = strlen("The factor2"),
             .data = (uint8_t *)"The factor2"}}};

    static struct HksParam g_hmacParams[] = {
        {.tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3}};

    static struct HksParam g_importWrappedSm4Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7},
        {.tag = HKS_TAG_IV, .blob = {.size = HKS_SM4_IV_SIZE, .data = (uint8_t *)g_hksSm4TestIv}}
    };

    static struct HksParam g_importWrappedSm4ParamsWithVerify[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE,
            .uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7_WITH_VERIFY_DIG_SM3},
        {.tag = HKS_TAG_IV, .blob = {.size = HKS_SM4_IV_SIZE, .data = (uint8_t *)g_hksSm4TestIv}}
    };

    static struct HksParam g_importWrappedAesParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7},
        {.tag = HKS_TAG_IV, .blob = {.size = HKS_SM4_IV_SIZE, .data = (uint8_t *)g_hksSm4TestIv}}
    };

    static struct HksParam g_importWrappedKekSm46Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3},
    };

    static struct HksParam g_importWrappedSm2Params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256 },
        { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_PRIVATE_KEY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE,
            .uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7_WITH_VERIFY_DIG_SM3},
    };

    static struct HksBlob g_importPublicKeyToEncryptData = {
        .size = strlen("test_import_Key_alias_1_1"),
        .data = (uint8_t *)"test_import_Key_alias_1_1"};

    static struct HksBlob g_importedSm4KekPlainKey = {
        .size = strlen("The imported kek"),
        .data = (uint8_t *)"The imported kek"};

    static struct HksBlob g_importedSm4KeyPlainKey = {
        .size = strlen("The imported key"),
        .data = (uint8_t *)"The imported key"};

    static struct HksBlob g_factor1 = {
        .size = strlen("The factor1"),
        .data = (uint8_t *)"The factor1"};

    static struct HksBlob g_factor2 = {
        .size = strlen("The factor2"),
        .data = (uint8_t *)"The factor2"};

    /* ------------------ 2 -------------------- */

    static struct HksBlob g_callerKeyAlias_02 = {
        .size = strlen("test_caller_key_alias_02"),
        .data = (uint8_t *)"test_caller_key_alias_02"};

    static struct HksBlob g_wrappingKeyAlias_02 = {
        .size = strlen("test_wrappingKey_02"),
        .data = (uint8_t *)"test_wrappingKey_02"};

    static struct HksBlob g_importKekAlias_02 = {
        .size = strlen("test_import_kek_alias_02"),
        .data = (uint8_t *)"test_import_kek_alias_02"};

    static struct HksBlob g_importderiveKey1Alias_02 = {
        .size = strlen("test_derive_key1_alias_02"),
        .data = (uint8_t *)"test_derive_key1_alias_02"};

    static struct HksBlob g_importderiveKey2Alias_02 = {
        .size = strlen("test_derive_key2_alias_02"),
        .data = (uint8_t *)"test_derive_key2_alias_02"};

    static struct HksBlob g_importkeyAlias_02 = {
        .size = strlen("test_import_Key_alias_02"),
        .data = (uint8_t *)"test_import_Key_alias_02"};

    /* ------------------ 3 -------------------- */

    static struct HksBlob g_callerKeyAlias_03 = {
        .size = strlen("test_caller_key_alias_03"),
        .data = (uint8_t *)"test_caller_key_alias_03"};

    static struct HksBlob g_wrappingKeyAlias_03 = {
        .size = strlen("test_wrappingKey_03"),
        .data = (uint8_t *)"test_wrappingKey_03"};

    static struct HksBlob g_importKekAlias_03 = {
        .size = strlen("test_import_kek_alias_03"),
        .data = (uint8_t *)"test_import_kek_alias_03"};

    static struct HksBlob g_importderiveKey1Alias_03 = {
        .size = strlen("test_derive_key1_alias_03"),
        .data = (uint8_t *)"test_derive_key1_alias_03"};

    static struct HksBlob g_importderiveKey2Alias_03 = {
        .size = strlen("test_derive_key2_alias_03"),
        .data = (uint8_t *)"test_derive_key2_alias_03"};

    static struct HksBlob g_importkeyAlias_03 = {
        .size = strlen("test_import_Key_alias_03"),
        .data = (uint8_t *)"test_import_Key_alias_03"};

    /* ------------------ 4 -------------------- */

    static struct HksBlob g_callerKeyAlias_04 = {
        .size = strlen("test_caller_key_alias_04"),
        .data = (uint8_t *)"test_caller_key_alias_04"};

    static struct HksBlob g_wrappingKeyAlias_04 = {
        .size = strlen("test_wrappingKey_04"),
        .data = (uint8_t *)"test_wrappingKey_04"};

    static struct HksBlob g_importKekAlias_04 = {
        .size = strlen("test_import_kek_alias_04"),
        .data = (uint8_t *)"test_import_kek_alias_04"};

    static struct HksBlob g_importderiveKey1Alias_04 = {
        .size = strlen("test_derive_key1_alias_04"),
        .data = (uint8_t *)"test_derive_key1_alias_04"};

    static struct HksBlob g_importderiveKey2Alias_04 = {
        .size = strlen("test_derive_key2_alias_04"),
        .data = (uint8_t *)"test_derive_key2_alias_04"};

    static struct HksBlob g_importkeyAlias_04 = {
        .size = strlen("test_import_Key_alias_04"),
        .data = (uint8_t *)"test_import_Key_alias_04"};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
    /* ------------------ 5 -------------------- */

    static struct HksBlob g_callerKeyAlias_05 = {
        .size = strlen("test_caller_key_alias_05"),
        .data = (uint8_t *)"test_caller_key_alias_05"};

    static struct HksBlob g_wrappingKeyAlias_05 = {
        .size = strlen("test_wrappingKey_05"),
        .data = (uint8_t *)"test_wrappingKey_05"};

    static struct HksBlob g_importKekAlias_05 = {
        .size = strlen("test_import_kek_alias_05"),
        .data = (uint8_t *)"test_import_kek_alias_05"};

    static struct HksBlob g_importderiveKey1Alias_05 = {
        .size = strlen("test_derive_key1_alias_05"),
        .data = (uint8_t *)"test_derive_key1_alias_05"};

    static struct HksBlob g_importderiveKey2Alias_05 = {
        .size = strlen("test_derive_key2_alias_05"),
        .data = (uint8_t *)"test_derive_key2_alias_05"};

    static struct HksBlob g_importkeyAlias_05 = {
        .size = strlen("test_import_Key_alias_05"),
        .data = (uint8_t *)"test_import_Key_alias_05"};
#endif

    /* ------------------ 6 -------------------- */

    static struct HksBlob g_callerKeyAlias_06 = {
        .size = strlen("test_caller_key_alias_06"),
        .data = (uint8_t *)"test_caller_key_alias_06"};

    static struct HksBlob g_wrappingKeyAlias_06 = {
        .size = strlen("test_wrappingKey_06"),
        .data = (uint8_t *)"test_wrappingKey_06"};

    static struct HksBlob g_importKekAlias_06 = {
        .size = strlen("test_import_kek_alias_06"),
        .data = (uint8_t *)"test_import_kek_alias_06"};

    static struct HksBlob g_importderiveKey1Alias_06 = {
        .size = strlen("test_derive_key1_alias_06"),
        .data = (uint8_t *)"test_derive_key1_alias_06"};

    static struct HksBlob g_importderiveKey2Alias_06 = {
        .size = strlen("test_derive_key2_alias_06"),
        .data = (uint8_t *)"test_derive_key2_alias_06"};

    static struct HksBlob g_importkeyAlias_06 = {
        .size = strlen("test_import_Key_alias_06"),
        .data = (uint8_t *)"test_import_Key_alias_06"};

    /* ------------------ 6 -------------------- */

    static struct HksBlob g_callerKeyAlias_07 = {
        .size = strlen("test_caller_key_alias_07"),
        .data = (uint8_t *)"test_caller_key_alias_07"};

    static struct HksBlob g_wrappingKeyAlias_07 = {
        .size = strlen("test_wrappingKey_07"),
        .data = (uint8_t *)"test_wrappingKey_07"};

    static struct HksBlob g_importKekAlias_07 = {
        .size = strlen("test_import_kek_alias_07"),
        .data = (uint8_t *)"test_import_kek_alias_07"};

    static struct HksBlob g_importderiveKey1Alias_07 = {
        .size = strlen("test_derive_key1_alias_07"),
        .data = (uint8_t *)"test_derive_key1_alias_07"};

    static struct HksBlob g_importderiveKey2Alias_07 = {
        .size = strlen("test_derive_key2_alias_07"),
        .data = (uint8_t *)"test_derive_key2_alias_07"};

    static struct HksBlob g_importkeyAlias_07 = {
        .size = strlen("test_import_Key_alias_07"),
        .data = (uint8_t *)"test_import_Key_alias_07"};

    static const uint8_t g_sm2XData256One[] = {
        0xa5, 0xb8, 0xa3, 0x78, 0x1d, 0x6d, 0x76, 0xe0, 0xb3, 0xf5, 0x6f, 0x43, 0x9d, 0xcf, 0x60, 0xf6,
        0x0b, 0x3f, 0x64, 0x45, 0xa8, 0x3f, 0x1a, 0x96, 0xf1, 0xa1, 0xa4, 0x5d, 0x3e, 0x2c, 0x3f, 0x13,
    };

    static const uint8_t g_sm2YData256One[] = {
        0xd7, 0x81, 0xf7, 0x2a, 0xb5, 0x8d, 0x19, 0x3d, 0x9b, 0x96, 0xc7, 0x6a, 0x10, 0xf0, 0xaa, 0xbc,
        0x91, 0x6f, 0x4d, 0xa7, 0x09, 0xb3, 0x57, 0x88, 0x19, 0x6f, 0x00, 0x4b, 0xad, 0xee, 0x34, 0x35,
    };

    static const uint8_t g_sm2ZData256One[] = {
        0xfb, 0x8b, 0x9f, 0x12, 0xa0, 0x83, 0x19, 0xbe, 0x6a, 0x6f, 0x63, 0x2a, 0x7c, 0x86, 0xba, 0xca,
        0x64, 0x0b, 0x88, 0x96, 0xe2, 0xfa, 0x77, 0xbc, 0x71, 0xe3, 0x0f, 0x0f, 0x9e, 0x3c, 0xe5, 0xf9,
    };

    static const uint8_t g_sm2PubData256One[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa5, 0xb8, 0xa3, 0x78, 0x1d,
        0x6d, 0x76, 0xe0, 0xb3, 0xf5, 0x6f, 0x43, 0x9d, 0xcf, 0x60, 0xf6, 0x0b, 0x3f, 0x64, 0x45, 0xa8,
        0x3f, 0x1a, 0x96, 0xf1, 0xa1, 0xa4, 0x5d, 0x3e, 0x2c, 0x3f, 0x13, 0xd7, 0x81, 0xf7, 0x2a, 0xb5,
        0x8d, 0x19, 0x3d, 0x9b, 0x96, 0xc7, 0x6a, 0x10, 0xf0, 0xaa, 0xbc, 0x91, 0x6f, 0x4d, 0xa7, 0x09,
        0xb3, 0x57, 0x88, 0x19, 0x6f, 0x00, 0x4b, 0xad, 0xee, 0x34, 0x35,
    };

    static void GenerateAndExportHuksPublicKey(struct HksBlob *wrappingKeyAlias,
        struct HksParamSet *genWrappingKeyParamSet, struct HksBlob *huksPublicKey)
    {
        int32_t ret = HksGenerateKey(wrappingKeyAlias, genWrappingKeyParamSet, nullptr);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Generate huks key failed.";

        huksPublicKey->size = HKS_SM2_KEY_SIZE_256;

        EXPECT_EQ(MallocAndCheckBlobData(huksPublicKey, huksPublicKey->size), HKS_SUCCESS)
            << "Malloc pub key failed.";
        ret = HksExportPublicKey(wrappingKeyAlias, nullptr, huksPublicKey);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Export huks public key failed.";
    }

    static int32_t HksTestSignVerify(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
        struct HksBlob *inData, struct HksBlob *outData)
    {
        uint8_t tmpHandle[sizeof(uint64_t)] = { 0 };
        struct HksBlob handle = {sizeof(uint64_t), tmpHandle};
        int32_t ret;

        struct HksParam *digestAlg = nullptr;
        ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestAlg);
        EXPECT_EQ(ret, HKS_SUCCESS) << "GetParam failed.";

        do {
            ret = HksInit(keyAlias, paramSet, &handle, nullptr);
            if (ret != HKS_SUCCESS) {
                break;
            }

            struct HksParam *tmpParam = NULL;
            ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &tmpParam);
            if (ret != HKS_SUCCESS) {
                break;
            }

            ret = TestUpdateFinish(&handle, paramSet, tmpParam->uint32Param, inData, outData);
            if (ret != HKS_SUCCESS) {
                break;
            }
            ret = HKS_SUCCESS;
        } while (0);

        (void)HksAbort(&handle, paramSet);
        return ret;
    }

    static int32_t HksTestEncrypt(const struct HksBlob *keyAlias,
        const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
    {
        int32_t ret = HksEncrypt(keyAlias, encryptParamSet, inData, cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
        return ret;
    }

    static int32_t BuildWrappedKeyData(struct HksBlob **blobArray, uint32_t size,
        bool isSigned, struct HksBlob *outData)
    {
        uint32_t totalLength = size * sizeof(uint32_t);

        /* counter size */
        for (uint32_t i = 0; i < size; ++i) {
            totalLength += blobArray[i]->size;
        }

        struct HksBlob outBlob = {0, nullptr};
        outBlob.size = totalLength;
        (void)MallocAndCheckBlobData(&outBlob, outBlob.size);

        uint32_t offsetTest = 0;

        /* copy data */
        for (uint32_t i = 0; i < size; ++i) {
            if (memcpy_s(outBlob.data + offsetTest, totalLength - offsetTest,
                reinterpret_cast<uint8_t *>(&blobArray[i]->size), sizeof(blobArray[i]->size)) != EOK) {
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            offsetTest += sizeof(blobArray[i]->size);

            if (memcpy_s(outBlob.data + offsetTest, totalLength - offsetTest, blobArray[i]->data,
                blobArray[i]->size) != EOK) {
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            offsetTest += blobArray[i]->size;
        }

        outData->size = outBlob.size;
        outData->data = outBlob.data;
        return HKS_SUCCESS;
    }

    static int32_t GenerateWrapKeyAndCallerKey(struct HksSmTestParams *generateParms,
        struct HksBlob *huksPublicKey, struct HksBlob *callerSelfPublicKey)
    {
        if (generateParms == nullptr) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        GenerateAndExportHuksPublicKey(generateParms->wrappingKeyAlias,
            generateParms->genWrappingKeyParam, huksPublicKey);
        GenerateAndExportHuksPublicKey(generateParms->callerKeyAlias,
            generateParms->genCallerKeyParam, callerSelfPublicKey);
        return HKS_SUCCESS;
    }

    static void AppendArray(struct HksBlob *kekData, struct HksBlob *signData, struct HksBlob *outArray, bool isSigned)
    {
        struct HksBlob kekAndSignDataBlob = {0, nullptr};
        kekAndSignDataBlob.size = isSigned ? signData->size + kekData->size : kekData->size;
        uint8_t *kekAndSignData = (uint8_t *)HksMalloc(kekAndSignDataBlob.size);
        kekAndSignDataBlob.data = kekAndSignData;
        (void)memcpy_s(kekAndSignDataBlob.data, kekAndSignDataBlob.size, kekData->data, kekData->size);
        if (isSigned) {
            (void)memcpy_s(kekAndSignDataBlob.data + kekData->size, kekAndSignDataBlob.size,
                signData->data, signData->size);
        }
        outArray->size = kekAndSignDataBlob.size;
        outArray->data = kekAndSignDataBlob.data;
    }

    static void DeriveKeyBySmKdf(struct HksSmTestParams *params, struct HksBlob *deriveKey1, struct HksBlob *deriveKey2)
    {
        int32_t ret = HksDeriveKey(params->deriveKey1Param, params->importKekAlias, deriveKey1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeriveKey1 failed.";
        ret = HksDeriveKey(params->deriveKey2Param, params->importKekAlias, deriveKey2);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeriveKey2 failed.";
    }

    static int32_t importSmKey(struct HksSmTestParams *params, struct HksBlob *kekData, bool isSigned)
    {
        struct HksBlob huksPublicKey = { 0, nullptr };
        struct HksBlob callerSelfPublicKey = { 0, nullptr };
        uint8_t outDataS[SM2_COMMON_SIZE] = { 0 };
        struct HksBlob outDataSign = {SM2_COMMON_SIZE, outDataS};
        HKS_LOG_I("start GenerateWrapKeyAndCallerKey");
        GenerateWrapKeyAndCallerKey(params, &huksPublicKey, &callerSelfPublicKey);
        int32_t ret = HKS_SUCCESS;
        ret = HksImportKey(&g_importPublicKeyToEncryptData, params->sm2EncryptParam, &huksPublicKey);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import public key failed.";

        if (isSigned) {
            HKS_LOG_I("start HksTestSignVerify");
            ret = HksTestSignVerify(params->callerKeyAlias, params->signParam, kekData, &outDataSign);
            EXPECT_EQ(ret, HKS_SUCCESS) << "HksTestEncrypt sign data failed.";
        }

        struct HksBlob kekAndSignDataBlob = { 0, nullptr };
        uint8_t cipher[SM2_COMMON_SIZE] = { 0 };
        struct HksBlob cipherText = {SM2_COMMON_SIZE, cipher};
        AppendArray(kekData, &outDataSign, &kekAndSignDataBlob, isSigned);
        HKS_LOG_I("start sm2 HksTestEncrypt");
        ret = HksTestEncrypt(&g_importPublicKeyToEncryptData, params->sm2EncryptParam,
            &kekAndSignDataBlob, &cipherText);
        HKS_FREE_BLOB(kekAndSignDataBlob);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksTestEncrypt sm2 failed.";

        ret = HksImportKey(params->importKekAlias, params->importKekParam, kekData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import kek failed.";
        uint8_t deriveKey1[HKS_SM4_DERIVE_KEY_SIZE] = { 0 };
        struct HksBlob deriveKey1Blob = {HKS_SM4_DERIVE_KEY_SIZE, deriveKey1};
        uint8_t deriveKey2[HKS_SM4_DERIVE_KEY_SIZE] = { 0 };
        struct HksBlob deriveKey2Blob = {HKS_SM4_DERIVE_KEY_SIZE, deriveKey2};
        HKS_LOG_I("start DeriveKeyBySmKdf");
        DeriveKeyBySmKdf(params, &deriveKey1Blob, &deriveKey2Blob);
        ret = HksImportKey(params->importderiveKey1Alias, params->importderiveKey1Param, &deriveKey1Blob);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import deriveKey1 failed.";
        ret = HksImportKey(params->importderiveKey2Alias, params->importderiveKey2Param, &deriveKey2Blob);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import kek failed.";

        uint8_t sm4Cipher[HKS_SM4_CIPHER_SIZE] = { 0 };
        struct HksBlob sm4CipherText = {HKS_SM4_CIPHER_SIZE, sm4Cipher};
        HKS_LOG_I("start sm4 HksTestEncrypt");
        ret = HksTestEncrypt(params->importderiveKey1Alias, params->sm4EncryptParam,
            params->keyImportPlainText, &sm4CipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "encrypt sm4 failed.";
        uint8_t tmpMac[HKS_COMMON_MAC_SIZE] = { 0 };
        struct HksBlob mac = {HKS_COMMON_MAC_SIZE, tmpMac};
        ret = HksMac(params->importderiveKey2Alias, params->importderiveKey2Param, &sm4CipherText, &mac);
        EXPECT_EQ(ret, HKS_SUCCESS) << "hmac failed.";

        struct HksBlob keysignlLen = {.size = sizeof(uint32_t), .data = (uint8_t *)&outDataSign.size};
        struct HksBlob kekMaterialLen = {.size = sizeof(uint32_t), .data = (uint8_t *)&kekData->size};
        struct HksBlob keyMaterialLen = {.size = sizeof(uint32_t), .data = (uint8_t *)&params->keyMaterialLen};
        struct HksBlob wrappedKeyData = {0, nullptr};
        if (isSigned) {
            struct HksBlob *blobArray[] = {&callerSelfPublicKey, &keysignlLen, &cipherText, &kekMaterialLen, &g_factor1,
                &g_factor2, &mac, &sm4CipherText, &g_Iv, &keyMaterialLen};
            ret = BuildWrappedKeyData(blobArray, HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, isSigned, &wrappedKeyData);
        } else {
            struct HksBlob *blobArray[] = {&cipherText, &kekMaterialLen, &g_factor1, &g_factor2,
                &mac, &sm4CipherText, &g_Iv, &keyMaterialLen};
            ret = BuildWrappedKeyData(blobArray, HKS_IMPORT_WRAPPED_KEY_NO_VERIFY_TOTAL_BLOBS,
                isSigned, &wrappedKeyData);
        }

        EXPECT_EQ(ret, HKS_SUCCESS) << "BuildWrappedKeyData failed.";
        HKS_LOG_I("start HksImportWrappedKey");
        ret = HksImportWrappedKey(params->importKeyAlias, params->wrappingKeyAlias,
            params->importKeyParam, &wrappedKeyData);
        HKS_FREE_BLOB(huksPublicKey);
        HKS_FREE_BLOB(callerSelfPublicKey);
        HKS_FREE_BLOB(wrappedKeyData);
        return ret;
    }

    static int32_t InitCommonParamSetTestParams(struct HksSmTestParams *params, struct HksBlob *kekData,
        const struct HksParam *importedKeyParams, uint32_t arraySize, bool isSigned)
    {
        struct HksParamSet *generateWrapKeyParamSet = nullptr;
        int32_t ret = InitParamSet(&generateWrapKeyParamSet, g_genWrappingKeyParams,
            sizeof(g_genWrappingKeyParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(generateWrapKeyParamSet) failed.";
        params->genWrappingKeyParam = generateWrapKeyParamSet;

        struct HksParamSet *generateCallerKeyParamSet = nullptr;
        ret = InitParamSet(&generateCallerKeyParamSet, g_genCallerSm2Params,
            sizeof(g_genCallerSm2Params) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(generateCallerKeyParamSet) failed.";
        params->genCallerKeyParam = generateCallerKeyParamSet;

        struct HksParamSet *signParamSet = nullptr;
        ret = InitParamSet(&signParamSet, g_signDataParams, sizeof(g_signDataParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(signParamSet) failed.";
        params->signParam = signParamSet;

        struct HksParamSet *encryptSm2ParamSet = nullptr;
        ret = InitParamSet(&encryptSm2ParamSet, g_sm2EncryptParams, sizeof(g_sm2EncryptParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encryptSm2ParamSet) failed.";
        params->sm2EncryptParam = encryptSm2ParamSet;

        struct HksParamSet *importKekParams = nullptr;
        ret = InitParamSet(&importKekParams, g_importWrappedKekSm46Params,
            sizeof(g_importWrappedKekSm46Params) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(importKekParams) failed.";
        params->importKekParam = importKekParams;

        struct HksParamSet *deriveParamSet1 = nullptr;
        ret = InitParamSet(&deriveParamSet1, g_sm3Params1, sizeof(g_sm3Params1) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(deriveParamSet1) failed.";
        params->deriveKey1Param = deriveParamSet1;

        struct HksParamSet *deriveParamSet2 = nullptr;
        ret = InitParamSet(&deriveParamSet2, g_sm3Params2, sizeof(g_sm3Params2) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(deriveParamSet2) failed.";
        params->deriveKey2Param = deriveParamSet2;

        struct HksParamSet *encryptSm4ParamSet = nullptr;
        ret = InitParamSet(&encryptSm4ParamSet, g_sm4EncryptParams, sizeof(g_sm4EncryptParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encryptSm4ParamSet) failed.";
        params->sm4EncryptParam = encryptSm4ParamSet;
        params->importderiveKey1Param = encryptSm4ParamSet;

        struct HksParamSet *macParamSet1 = nullptr;
        ret = InitParamSet(&macParamSet1, g_sm4MacParams, sizeof(g_sm4MacParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(macParamSet1) failed.";
        params->importderiveKey2Param = macParamSet1;

        struct HksParamSet *hmacParamSet = nullptr;
        ret = InitParamSet(&hmacParamSet, g_hmacParams, sizeof(g_hmacParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(hmacParamSet) failed.";
        params->hmacParam = hmacParamSet;

        struct HksParamSet *importKeyPara = nullptr;
        ret = InitParamSet(&importKeyPara, importedKeyParams, arraySize);
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(importKeyPara) failed.";
        params->importKeyParam = importKeyPara;

        ret = importSmKey(params, kekData, isSigned);
        HksFreeParamSet(&generateWrapKeyParamSet);
        HksFreeParamSet(&generateCallerKeyParamSet);
        HksFreeParamSet(&signParamSet);
        HksFreeParamSet(&encryptSm2ParamSet);
        HksFreeParamSet(&importKekParams);
        HksFreeParamSet(&deriveParamSet1);
        HksFreeParamSet(&deriveParamSet2);
        HksFreeParamSet(&encryptSm4ParamSet);
        HksFreeParamSet(&macParamSet1);
        HksFreeParamSet(&hmacParamSet);
        HksFreeParamSet(&importKeyPara);
        (void)HksDeleteKey(&g_importPublicKeyToEncryptData, nullptr);
        return ret;
    }

    struct TestImportKeyData {
        struct HksBlob x509PublicKey;
        struct HksBlob publicOrXData;
        struct HksBlob privateOrYData;
        struct HksBlob zData;
    };

    static int32_t CopyKey(const uint8_t *key, uint32_t size, struct HksBlob *outKey)
    {
        uint8_t *outData = (uint8_t *)HksMalloc(size);
        if (outData == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }

        (void)memcpy_s(outData, size, key, size);
        outKey->data = outData;
        outKey->size = size;

        return HKS_SUCCESS;
    }

    static int32_t ConstructEccKey(struct TestImportKeyData *keyTest,
        uint32_t keySize, uint32_t importType, struct HksBlob *outKey)
    {
        if (importType == HKS_KEY_TYPE_PUBLIC_KEY) {
            return CopyKey(keyTest->x509PublicKey.data, keyTest->x509PublicKey.size, outKey);
        }

        bool isPriKey = (importType == HKS_KEY_TYPE_PRIVATE_KEY) ? true : false;

        struct HksKeyMaterialEcc material;
        material.keyAlg = HKS_ALG_SM2;
        material.keySize = keySize;
        material.xSize = isPriKey ? 0 : keyTest->publicOrXData.size;
        material.ySize = isPriKey ? 0 : keyTest->privateOrYData.size;
        material.zSize = keyTest->zData.size;

        uint32_t size = sizeof(material) + material.xSize + material.ySize + material.zSize;
        uint8_t *data = (uint8_t *)HksMalloc(size);
        if (data == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }

        // copy struct material
        if (memcpy_s(data, size, &material, sizeof(material)) != EOK) {
            HKS_FREE(data);
            return HKS_ERROR_BAD_STATE;
        }

        uint32_t offset = sizeof(material);
        if (!isPriKey) {
            // copy xData
            if (memcpy_s(data + offset, size - offset, keyTest->publicOrXData.data,
                keyTest->publicOrXData.size) != EOK) {
                HKS_FREE(data);
                return HKS_ERROR_BAD_STATE;
            }

            offset += material.xSize;
            // copy yData
            if (memcpy_s(data + offset, size - offset, keyTest->privateOrYData.data,
                keyTest->privateOrYData.size) != EOK) {
                HKS_FREE(data);
                return HKS_ERROR_BAD_STATE;
            }
            offset += material.ySize;
        }

        // copy zData
        if (memcpy_s(data + offset, size - offset, keyTest->zData.data, keyTest->zData.size) != EOK) {
            HKS_FREE(data);
            return HKS_ERROR_BAD_STATE;
        }

        outKey->data = data;
        outKey->size = size;
        return HKS_SUCCESS;
    }

    static int32_t ConstructImportedSm2Key(uint32_t keySize, uint32_t importType,
        struct HksBlob *outKey)
    {
        struct TestImportKeyData key;
        (void)memset_s(&key, sizeof(key), 0, sizeof(key));
        key.privateOrYData.data = (uint8_t *)g_sm2XData256One;
        key.privateOrYData.size = sizeof(g_sm2XData256One);
        key.publicOrXData.data = (uint8_t *)g_sm2YData256One;
        key.publicOrXData.size = sizeof(g_sm2YData256One);
        key.zData.data = (uint8_t *)g_sm2ZData256One;
        key.zData.size = sizeof(g_sm2ZData256One);
        key.x509PublicKey.data = (uint8_t *)g_sm2PubData256One;
        key.x509PublicKey.size = sizeof(g_sm2PubData256One);

        return ConstructEccKey(&key, keySize, importType, outKey);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite001
     * @tc.desc: Test import wrapped sm4-cbc-no_padding key including generate&export SM2 key, generate kek,
     * sign, encrypt, of which generate kek, encrypt should done by caller self.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite001, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite001");
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_02;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_02;
        smTestParams.importKekAlias = &g_importKekAlias_02;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_02;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_02;
        smTestParams.importKeyAlias = &g_importkeyAlias_02;
        smTestParams.keyMaterialLen = g_importedSm4KeyPlainKey.size;
        smTestParams.keyImportPlainText = &g_importedSm4KeyPlainKey;
        int32_t ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey,
            g_importWrappedSm4ParamsWithVerify,
            sizeof(g_importWrappedSm4ParamsWithVerify) / sizeof(struct HksParam), true);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import key failed.";
        (void)HksDeleteKey(&g_callerKeyAlias_02, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_02, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_02, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_02, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_02, nullptr);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite002
     * @tc.desc: Test import wrapped sm4-cbc key including generate&export SM2 key, generate kek,
     *  encrypt, of which generate kek, encrypt should done by caller self.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite002, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite002");
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_03;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_03;
        smTestParams.importKekAlias = &g_importKekAlias_03;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_03;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_03;
        smTestParams.importKeyAlias = &g_importkeyAlias_03;
        smTestParams.keyMaterialLen = g_importedSm4KeyPlainKey.size;
        smTestParams.keyImportPlainText = &g_importedSm4KeyPlainKey;
        int32_t ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey, g_importWrappedSm4Params,
            sizeof(g_importWrappedSm4Params) / sizeof(struct HksParam), false);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import key failed.";
        (void)HksDeleteKey(&g_callerKeyAlias_03, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_03, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_03, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_03, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_03, nullptr);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite003
     * @tc.desc: Using import key alias1 to encrypt data.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite003, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite003");
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_04;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_04;
        smTestParams.importKekAlias = &g_importKekAlias_04;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_04;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_04;
        smTestParams.importKeyAlias = &g_importkeyAlias_04;
        smTestParams.keyMaterialLen = g_importedSm4KeyPlainKey.size;
        smTestParams.keyImportPlainText = &g_importedSm4KeyPlainKey;
        int32_t ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey, g_importWrappedAesParams,
            sizeof(g_importWrappedAesParams) / sizeof(struct HksParam), false);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "alg is invalid.";
        (void)HksDeleteKey(&g_callerKeyAlias_04, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_04, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_04, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_04, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_04, nullptr);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite004
     * @tc.desc: Using import key alias1 to encrypt data.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite004, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite004");
        struct HksParamSet *encryptSm4ParamSet = nullptr;
        int32_t ret = InitParamSet(&encryptSm4ParamSet, g_importWrappedSm4ParamsWithVerify,
            sizeof(g_importWrappedSm4ParamsWithVerify) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(HksImportWrappedKeyTestSm2Suite003) failed.";
        struct HksBlob plainText = {
            .size = strlen("1111111111"),
            .data = (uint8_t *)"11111111"};
        uint8_t sm4Cipher[HKS_SM4_CIPHER_SIZE] = { 0 };
        struct HksBlob sm4CipherText = { HKS_SM4_CIPHER_SIZE, sm4Cipher };
        ret = HksTestEncrypt(&g_importkeyAlias_02, encryptSm4ParamSet, &plainText, &sm4CipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "using wrapped key to encrypt data failed.";

        struct HksBlob importKeyAlias = {
        .size = strlen("test_derive_key1_alias_03"),
        .data = (uint8_t *)"test_derive_key1_alias_03"};

        ret = HksImportKey(&importKeyAlias, encryptSm4ParamSet, &g_importedSm4KeyPlainKey);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import key failed!";

        uint8_t sm4Cipher1[HKS_SM4_CIPHER_SIZE] = { 0 };
        struct HksBlob sm4CipherText1 = {HKS_SM4_CIPHER_SIZE, sm4Cipher1};
        ret = HksTestEncrypt(&importKeyAlias, encryptSm4ParamSet, &plainText, &sm4CipherText1);
        EXPECT_EQ(ret, HKS_SUCCESS) << "using import key to encrypt data failed.";

        ret = memcmp(sm4CipherText1.data, sm4CipherText.data, sm4CipherText.size);
        EXPECT_EQ(ret, HKS_SUCCESS) << "compare failed .";

        (void)HksDeleteKey(&importKeyAlias, nullptr);
    }

#ifdef HKS_UNTRUSTED_RUNNING_ENV
    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite005
     * @tc.desc: import sm2 private key.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite005, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite005");
        struct HksBlob key = { 0, nullptr };
        // The caller guarantees that the access will not cross the border
        int32_t ret = ConstructImportedSm2Key(HKS_SM2_KEY_SIZE_256, HKS_KEY_TYPE_PRIVATE_KEY, &key);
        EXPECT_EQ(ret, HKS_SUCCESS) << "init sm2 key failed .";

        g_importWrappedSm2Params[TAG_ALG_PURPOSE_TYPE_ID].uint32Param = HKS_KEY_PURPOSE_SIGN;
        g_importWrappedSm2Params[TAG_ALG_SUIT_ID].uint32Param =
            HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7_WITH_VERIFY_DIG_SM3;
        g_importWrappedSm2Params[TAG_ALG_IMPORT_KEY_TYPE_ID].uint32Param = HKS_KEY_TYPE_PRIVATE_KEY;
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_05;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_05;
        smTestParams.importKekAlias = &g_importKekAlias_05;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_05;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_05;
        smTestParams.importKeyAlias = &g_importkeyAlias_05;
        smTestParams.keyMaterialLen = key.size;
        smTestParams.keyImportPlainText = &key;
        ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey, g_importWrappedSm2Params,
            sizeof(g_importWrappedSm2Params) / sizeof(struct HksParam), true);
        HKS_FREE_BLOB(key);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import key failed.";
        (void)HksDeleteKey(&g_callerKeyAlias_05, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_05, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_05, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_05, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_05, nullptr);
    }
#endif

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite005
     * @tc.desc: import sm2 public key.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite006, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite006");
        struct HksBlob key = { 0, nullptr };
        // The caller guarantees that the access will not cross the border
        int32_t ret = ConstructImportedSm2Key(HKS_SM2_KEY_SIZE_256, HKS_KEY_TYPE_PUBLIC_KEY, &key);
        EXPECT_EQ(ret, HKS_SUCCESS) << "init sm2 key failed .";

        g_importWrappedSm2Params[TAG_ALG_PURPOSE_TYPE_ID].uint32Param = HKS_KEY_PURPOSE_VERIFY;
        g_importWrappedSm2Params[TAG_ALG_SUIT_ID].uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7;
        g_importWrappedSm2Params[TAG_ALG_IMPORT_KEY_TYPE_ID].uint32Param = HKS_KEY_TYPE_PUBLIC_KEY;
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_06;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_06;
        smTestParams.importKekAlias = &g_importKekAlias_06;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_06;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_06;
        smTestParams.importKeyAlias = &g_importkeyAlias_06;
        smTestParams.keyMaterialLen = key.size;
        smTestParams.keyImportPlainText = &key;
        ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey, g_importWrappedSm2Params,
            sizeof(g_importWrappedSm2Params) / sizeof(struct HksParam), false);
        HKS_FREE_BLOB(key);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "import key failed.";
        (void)HksDeleteKey(&g_callerKeyAlias_06, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_06, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_06, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_06, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_06, nullptr);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite007
     * @tc.desc: import sm2 key pair.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite007, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite007");
        struct HksBlob key = { 0, nullptr };
        // The caller guarantees that the access will not cross the border
        int32_t ret = ConstructImportedSm2Key(HKS_SM2_KEY_SIZE_256, HKS_KEY_TYPE_KEY_PAIR, &key);
        EXPECT_EQ(ret, HKS_SUCCESS) << "init sm2 key failed .";

        g_importWrappedSm2Params[TAG_ALG_PURPOSE_TYPE_ID].uint32Param = HKS_KEY_PURPOSE_ENCRYPT;
        g_importWrappedSm2Params[TAG_ALG_SUIT_ID].uint32Param = HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7;
        g_importWrappedSm2Params[TAG_ALG_IMPORT_KEY_TYPE_ID].uint32Param = HKS_KEY_TYPE_KEY_PAIR;
        struct HksSmTestParams smTestParams = { 0 };
        smTestParams.callerKeyAlias = &g_callerKeyAlias_07;
        smTestParams.wrappingKeyAlias = &g_wrappingKeyAlias_07;
        smTestParams.importKekAlias = &g_importKekAlias_07;
        smTestParams.importderiveKey1Alias = &g_importderiveKey1Alias_07;
        smTestParams.importderiveKey2Alias = &g_importderiveKey2Alias_07;
        smTestParams.importKeyAlias = &g_importkeyAlias_07;
        smTestParams.keyMaterialLen = key.size;
        smTestParams.keyImportPlainText = &key;
        ret = InitCommonParamSetTestParams(&smTestParams, &g_importedSm4KekPlainKey, g_importWrappedSm2Params,
            sizeof(g_importWrappedSm2Params) / sizeof(struct HksParam), false);
        HKS_FREE_BLOB(key);
        EXPECT_EQ(ret, HKS_SUCCESS) << "import key failed.";
        (void)HksDeleteKey(&g_callerKeyAlias_07, nullptr);
        (void)HksDeleteKey(&g_wrappingKeyAlias_07, nullptr);
        (void)HksDeleteKey(&g_importKekAlias_07, nullptr);
        (void)HksDeleteKey(&g_importderiveKey1Alias_07, nullptr);
        (void)HksDeleteKey(&g_importderiveKey2Alias_07, nullptr);
    }

    /**
     * @tc.name: HksImportWrappedSm2SuiteTest.HksImportWrappedKeyTestSm2Suite008
     * @tc.desc: import sm2 key pair.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedSm2SuiteTest, HksImportWrappedKeyTestSm2Suite008, TestSize.Level0)
    {
        HKS_LOG_I("HksImportWrappedKeyTestSm2Suite008");
        (void)HksDeleteKey(&g_importkeyAlias_02, nullptr);
        (void)HksDeleteKey(&g_importkeyAlias_03, nullptr);
        (void)HksDeleteKey(&g_importkeyAlias_04, nullptr);
        #ifdef HKS_UNTRUSTED_RUNNING_ENV
        (void)HksDeleteKey(&g_importkeyAlias_05, nullptr);
        #endif
        (void)HksDeleteKey(&g_importkeyAlias_06, nullptr);
        (void)HksDeleteKey(&g_importkeyAlias_07, nullptr);
        int32_t ret = HksInitialize();
        ASSERT_TRUE(ret == HKS_SUCCESS);
    }
}
