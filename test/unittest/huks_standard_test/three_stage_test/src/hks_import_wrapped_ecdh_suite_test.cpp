/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_import_wrapped_ecdh_suite_test.h"

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::ImportWrappedKey {
    class HksImportWrappedEcdhSuiteTest : public testing::Test {
    public:
        static void SetUpTestCase(void);

        static void TearDownTestCase(void);

        void SetUp();

        void TearDown();
    };

    void HksImportWrappedEcdhSuiteTest::SetUpTestCase(void)
    {
    }

    void HksImportWrappedEcdhSuiteTest::TearDownTestCase(void)
    {
    }

    void HksImportWrappedEcdhSuiteTest::SetUp()
    {
        EXPECT_EQ(HksInitialize(), 0);
    }

    void HksImportWrappedEcdhSuiteTest::TearDown()
    {
    }


    /* -------- Start of Ecdh unwrap algorithm suite common import key material and params define -------- */
    static char g_agreeKeyAlgName[] = "ECDH";

    static struct HksBlob g_agreeKeyAlgNameBlob = {
        .size = sizeof(g_agreeKeyAlgName),
        .data = (uint8_t *) g_agreeKeyAlgName
    };

    static const uint32_t g_ecdhPubKeySize = HKS_ECC_KEY_SIZE_256;

    static struct HksParam g_genWrappingKeyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC}
    };

    static struct HksParam g_genCallerEcdhParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC}
    };

    static struct HksParam g_callerAgreeParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256}
    };

    static struct HksParam g_importParamsCallerKek[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_IV, .blob =
            {.size = Unittest::ImportWrappedKey::IV_SIZE, .data = (uint8_t *) Unittest::ImportWrappedKey::IV}
        }
    };
    /* -------- End of x25519 unwrap algorithm suite common import key material and params define -------- */

    /* ------------------ Start of AES-256 import key material and params define ------------------ */
    static struct HksBlob g_importedAes192PlainKey = {
        .size = strlen("The aes192 key to import"),
        .data = (uint8_t *) "The aes192 key to import"
    };

    static struct HksBlob g_callerAes256Kek = {
        .size = strlen("The is kek to encrypt aes192 key"),
        .data = (uint8_t *) "The is kek to encrypt aes192 key"
    };

    static struct HksParam g_importWrappedAes256Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING},
        {.tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV} },
    };

    static struct HksBlob g_importedKeyAliasAes256 = {
        .size = strlen("test_import_key_ecdh_aes256"),
        .data = (uint8_t *) "test_import_key_ecdh_aes256"
    };

    static struct HksBlob g_wrappingKeyAliasAes256 = {
        .size = strlen("test_wrappingKey_ecdh_aes256"),
        .data = (uint8_t *) "test_wrappingKey_ecdh_aes256"
    };

    static struct HksBlob g_callerKeyAliasAes256 = {
        .size = strlen("test_caller_key_ecdh_aes256"),
        .data = (uint8_t *) "test_caller_key_ecdh_aes256"
    };

    static struct HksBlob g_callerKekAliasAes256 = {
        .size = strlen("test_caller_kek_ecdh_aes256"),
        .data = (uint8_t *) "test_caller_kek_ecdh_aes256"
    };

    static struct HksBlob g_callerAgreeKeyAliasAes256 = {
        .size = strlen("test_caller_agree_key_ecdh_aes256"),
        .data = (uint8_t *) "test_caller_agree_key_ecdh_aes256"
    };
    /* ------------------ End of AES-256 import key material and params define ------------------ */

    /* ------------------ Start of RSA-4096 import key material and params define -------------------- */
    static struct HksBlob g_callerRsa4096Kek = {
        .size = strlen("This  is  Rsa4096 kek to encrypt"),
        .data = (uint8_t *) "This  is  Rsa4096 kek to encrypt"
    };

    static const uint8_t g_eData[] = {0x01, 0x00, 0x01};

    static struct HksParam g_importRsa4096KeyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING},
    };

    static struct HksParam g_encRsa4096KeyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING},
    };

    static struct HksBlob g_importedKeyAliasRsa4096 = {
        .size = strlen("test_import_key_ecdh_Rsa4096"),
        .data = (uint8_t *) "test_import_key_ecdh_Rsa4096"
    };

    static struct HksBlob g_wrappingKeyAliasRsa4096 = {
        .size = strlen("test_wrappingKey_ecdh_Rsa4096"),
        .data = (uint8_t *) "test_wrappingKey_ecdh_Rsa4096"
    };

    static struct HksBlob g_callerKeyAliasRsa4096 = {
        .size = strlen("test_caller_key_ecdh_Rsa4096"),
        .data = (uint8_t *) "test_caller_key_ecdh_Rsa4096"
    };

    static struct HksBlob g_callerKekAliasRsa4096 = {
        .size = strlen("test_caller_kek_ecdh_Rsa4096"),
        .data = (uint8_t *) "test_caller_kek_ecdh_Rsa4096"
    };

    static struct HksBlob g_callerAgreeKeyAliasRsa4096 = {
        .size = strlen("test_caller_agree_key_ecdh_Rsa4096"),
        .data = (uint8_t *) "test_caller_agree_key_ecdh_Rsa4096"
    };

    struct TestImportKeyData {
        struct HksBlob x509PublicKey;
        struct HksBlob publicOrXData;
        struct HksBlob privateOrYData;
        struct HksBlob zData;
    };
    /* ------------------ End of RSA-4096 import key material and params define -------------------- */

    /* ------------------ Start of hmac256 pair import key material and params define -------------------- */
    static struct HksBlob g_importHmac256Key = {
        .size = strlen("This is hmac256 key to be import"),
        .data = (uint8_t *) "This is hmac256 key to be import"
    };

    static struct HksBlob g_callerHmac256Kek = {
        .size = strlen("This is hmac256 pair kek encrypt"),
        .data = (uint8_t *) "This is hmac256 pair kek encrypt"
    };

    static struct HksParam g_importHmac256KeyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING},
    };

    static struct HksParam g_importHmac256KeyAtherParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256},
        {.tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING},
    };

    static struct HksBlob g_importedKeyAliasHmac256 = {
        .size = strlen("test_import_key_ecdh_hmac256"),
        .data = (uint8_t *) "test_import_key_ecdh_hmac256"
    };

    static struct HksBlob g_wrappingKeyAliasHmac256 = {
        .size = strlen("test_wrappingKey_ecdh_hmac256"),
        .data = (uint8_t *) "test_wrappingKey_ecdh_hmac256"
    };

    static struct HksBlob g_callerKeyAliasHmac256 = {
        .size = strlen("test_caller_key_ecdh_hmac256"),
        .data = (uint8_t *) "test_caller_key_ecdh_hmac256"
    };

    static struct HksBlob g_callerKekAliasHmac256 = {
        .size = strlen("test_caller_kek_ecdh_hmac256"),
        .data = (uint8_t *) "test_caller_kek_ecdh_hmac256"
    };

    static struct HksBlob g_callerAgreeKeyAliasHmac256 = {
        .size = strlen("test_caller_agree_key_ecdh_hmac256"),
        .data = (uint8_t *) "test_caller_agree_key_ecdh_hmac256"
    };
    /* ------------------ End of hmac256 pair import key material and params define -------------------- */

    static int32_t ConstructKey(const struct HksBlob *nDataBlob, const struct HksBlob *dDataBlob,
        uint32_t keySize, struct HksBlob *outKey, bool isPriKey)
    {
        struct HksKeyMaterialRsa material;
        material.keyAlg = HKS_ALG_RSA;
        material.keySize = keySize;
        material.nSize = nDataBlob->size;
        material.eSize = isPriKey ? 0 : sizeof(g_eData);
        material.dSize = dDataBlob->size;

        uint32_t size = sizeof(material) + material.nSize + material.eSize + material.dSize;
        uint8_t *dataTest = (uint8_t *) HksMalloc(size);
        if (dataTest == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }

        // copy struct material
        if (memcpy_s(dataTest, size, &material, sizeof(material)) != EOK) {
            HKS_FREE(dataTest);
            return HKS_ERROR_BAD_STATE;
        }

        uint32_t offset = sizeof(material);
        // copy nData
        if (memcpy_s(dataTest + offset, size - offset, nDataBlob->data, nDataBlob->size) != EOK) {
            HKS_FREE(dataTest);
            return HKS_ERROR_BAD_STATE;
        }

        offset += material.nSize;
        // copy eData
        if (!isPriKey) {
            if (memcpy_s(dataTest + offset, size - offset, &g_eData, sizeof(g_eData)) != EOK) {
                HKS_FREE(dataTest);
                return HKS_ERROR_BAD_STATE;
            }
            offset += material.eSize;
        }

        // copy dData
        if (memcpy_s(dataTest + offset, size - offset, dDataBlob->data, dDataBlob->size) != EOK) {
            HKS_FREE(dataTest);
            return HKS_ERROR_BAD_STATE;
        }

        outKey->data = dataTest;
        outKey->size = size;
        return HKS_SUCCESS;
    }

    static void InitCommonTestParamsAndDoImport(struct HksImportWrappedKeyTestParams *importWrappedKeyTestParams,
        const struct HksParam *importedKeyParamSetArray, uint32_t arraySize)
    {
        int32_t ret = 0;
        importWrappedKeyTestParams->agreeKeyAlgName = &g_agreeKeyAlgNameBlob;

        struct HksParamSet *genEcdhKeyParamSet = nullptr;
        ret = InitParamSet(&genEcdhKeyParamSet, g_genWrappingKeyParams,
                           sizeof(g_genWrappingKeyParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen huks ecdh) failed.";
        importWrappedKeyTestParams->genWrappingKeyParamSet = genEcdhKeyParamSet;
        importWrappedKeyTestParams->publicKeySize = g_ecdhPubKeySize;

        struct HksParamSet *genCallerKeyParamSet = nullptr;
        ret = InitParamSet(&genCallerKeyParamSet, g_genCallerEcdhParams,
                           sizeof(g_genCallerEcdhParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen caller Ecdh) failed.";
        importWrappedKeyTestParams->genCallerKeyParamSet = genCallerKeyParamSet;

        struct HksParamSet *callerImportParamsKek = nullptr;
        ret = InitParamSet(&callerImportParamsKek, g_importParamsCallerKek,
                           sizeof(g_importParamsCallerKek) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(import call kek) failed.";
        importWrappedKeyTestParams->importCallerKekParamSet = callerImportParamsKek;

        struct HksParamSet *agreeParamSet = nullptr;
        ret = InitParamSet(&agreeParamSet, g_callerAgreeParams,
                           sizeof(g_callerAgreeParams) / sizeof(HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(agreeParamSet) failed.";
        importWrappedKeyTestParams->agreeParamSet = agreeParamSet;

        struct HksParamSet *importPlainKeyParams = nullptr;
        ret = InitParamSet(&importPlainKeyParams, importedKeyParamSetArray, arraySize);
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(import plain key) failed.";
        importWrappedKeyTestParams->importWrappedKeyParamSet = importPlainKeyParams;

        HksImportWrappedKeyTestCommonCase(importWrappedKeyTestParams);

        HksFreeParamSet(&genEcdhKeyParamSet);
        HksFreeParamSet(&genCallerKeyParamSet);
        HksFreeParamSet(&callerImportParamsKek);
        HksFreeParamSet(&importPlainKeyParams);
    }

    /**
     * @tc.name: HksImportWrappedEcdhSuiteTest.HksImportWrappedKeyTestEcdhSuite001
     * @tc.desc: Test import wrapped aes256-gcm-no_padding key including generate&export ecdh p256 key, generate kek,
     * agree, encrypt, of which generate kek, agree, encrypt should done by caller self.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedEcdhSuiteTest, HksImportWrappedKeyTestEcdhSuite001, TestSize.Level0)
    {
        struct HksImportWrappedKeyTestParams importWrappedKeyTestParams001 = {0};

        importWrappedKeyTestParams001.wrappingKeyAlias = &g_wrappingKeyAliasAes256;
        importWrappedKeyTestParams001.keyMaterialLen = g_importedAes192PlainKey.size;
        importWrappedKeyTestParams001.callerKeyAlias = &g_callerKeyAliasAes256;
        importWrappedKeyTestParams001.callerKekAlias = &g_callerKekAliasAes256;
        importWrappedKeyTestParams001.callerKek = &g_callerAes256Kek;
        importWrappedKeyTestParams001.callerAgreeKeyAlias = &g_callerAgreeKeyAliasAes256;
        importWrappedKeyTestParams001.importedKeyAlias = &g_importedKeyAliasAes256;
        importWrappedKeyTestParams001.importedPlainKey = &g_importedAes192PlainKey;
        InitCommonTestParamsAndDoImport(&importWrappedKeyTestParams001, g_importWrappedAes256Params,
                                        sizeof(g_importWrappedAes256Params) / sizeof(struct HksParam));
        HksClearKeysForWrappedKeyTest(&importWrappedKeyTestParams001);
    }

    /**
     * @tc.name: HksImportWrappedEcdhSuiteTest.HksImportWrappedKeyTestEcdhSuite002
     * @tc.desc: Test import wrapped rsa key pair including generate&export ecdh p256 key, generate kek, agree, encrypt,
     *           of which generate kek, agree, encrypt should done by caller self.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedEcdhSuiteTest, HksImportWrappedKeyTestEcdhSuite002, TestSize.Level0)
    {
        struct HksBlob nDataBlob = {sizeof(g_nData4096), (uint8_t *) g_nData4096};
        struct HksBlob dDataBlob = {sizeof(g_dData4096), (uint8_t *) g_dData4096};
        struct HksBlob plainKey = {0, nullptr};

        int32_t ret = ConstructKey(&nDataBlob, &dDataBlob, HKS_RSA_KEY_SIZE_4096, &plainKey, false);
        EXPECT_EQ(ret, HKS_SUCCESS) << "construct rsa 2048 failed.";

        struct HksImportWrappedKeyTestParams importWrappedKeyTestParams002 = {0};

        importWrappedKeyTestParams002.wrappingKeyAlias = &g_wrappingKeyAliasRsa4096;
        importWrappedKeyTestParams002.keyMaterialLen = plainKey.size;
        importWrappedKeyTestParams002.callerKeyAlias = &g_callerKeyAliasRsa4096;
        importWrappedKeyTestParams002.callerKekAlias = &g_callerKekAliasRsa4096;
        importWrappedKeyTestParams002.callerKek = &g_callerRsa4096Kek;
        importWrappedKeyTestParams002.callerAgreeKeyAlias = &g_callerAgreeKeyAliasRsa4096;
        importWrappedKeyTestParams002.importedKeyAlias = &g_importedKeyAliasRsa4096;
        importWrappedKeyTestParams002.importedPlainKey = &plainKey;
        InitCommonTestParamsAndDoImport(&importWrappedKeyTestParams002, g_importRsa4096KeyParams,
                                        sizeof(g_importRsa4096KeyParams) / sizeof(struct HksParam));

        struct HksParamSet *encParams = nullptr;
        ret = InitParamSet(&encParams, g_encRsa4096KeyParams,
            sizeof(g_encRsa4096KeyParams) / sizeof(struct HksParam));
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
        uint8_t handleE[sizeof(uint64_t)] = {0};
        struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
        ret = HksInit(importWrappedKeyTestParams002.importedKeyAlias, encParams, &handleEncrypt, nullptr);
        EXPECT_EQ(ret, HKS_SUCCESS) << "importted key init failed!";
        (void)HksAbort(&handleEncrypt, encParams);
        HksFreeParamSet(&encParams);
        HksClearKeysForWrappedKeyTest(&importWrappedKeyTestParams002);
    }

    /**
     * @tc.name: HksImportWrappedEcdhSuiteTest.HksImportWrappedKeyTestEcdhSuite003
     * @tc.desc: Test import wrapped hmac256 key pair including generate&export ecdh p256 key, generate kek, agree,
     *           encrypt, of which generate kek, agree, encrypt should done by caller self.
     * @tc.type: FUNC
     */
    HWTEST_F(HksImportWrappedEcdhSuiteTest, HksImportWrappedKeyTestEcdhSuite003, TestSize.Level0)
    {
        struct HksImportWrappedKeyTestParams importWrappedKeyTestParams003 = {0};

        importWrappedKeyTestParams003.wrappingKeyAlias = &g_wrappingKeyAliasHmac256;
        importWrappedKeyTestParams003.keyMaterialLen = g_importHmac256Key.size;
        importWrappedKeyTestParams003.callerKeyAlias = &g_callerKeyAliasHmac256;
        importWrappedKeyTestParams003.callerKekAlias = &g_callerKekAliasHmac256;
        importWrappedKeyTestParams003.callerKek = &g_callerHmac256Kek;
        importWrappedKeyTestParams003.callerAgreeKeyAlias = &g_callerAgreeKeyAliasHmac256;
        importWrappedKeyTestParams003.importedKeyAlias = &g_importedKeyAliasHmac256;
        importWrappedKeyTestParams003.importedPlainKey = &g_importHmac256Key;
        InitCommonTestParamsAndDoImport(&importWrappedKeyTestParams003, g_importHmac256KeyParams,
                                        sizeof(g_importHmac256KeyParams) / sizeof(struct HksParam));
        HksClearKeysForWrappedKeyTest(&importWrappedKeyTestParams003);
    }

    /**
     * @tc.name: HksImportWrappedEcdhSuiteTest.HksImportWrappedKeyTestEcdhSuite004
     * @tc.desc: Test import wrapped hmac256 key pair including generate&export ecdh p256 key, generate kek, agree,
     *           encrypt, of which generate kek, agree, encrypt should done by caller self. When importing the key,
     *           only the necessary parameters are passed in.
     * @tc.type: FUNC
     * @tc.require:issueI611S5
     */
    HWTEST_F(HksImportWrappedEcdhSuiteTest, HksImportWrappedKeyTestEcdhSuite004, TestSize.Level0)
    {
        HKS_LOG_E("Enter HksImportWrappedKeyTestEcdhSuite004");
        struct HksImportWrappedKeyTestParams importWrappedKeyTestParams004 = {0};

        importWrappedKeyTestParams004.wrappingKeyAlias = &g_wrappingKeyAliasHmac256;
        importWrappedKeyTestParams004.keyMaterialLen = g_importHmac256Key.size;
        importWrappedKeyTestParams004.callerKeyAlias = &g_callerKeyAliasHmac256;
        importWrappedKeyTestParams004.callerKekAlias = &g_callerKekAliasHmac256;
        importWrappedKeyTestParams004.callerKek = &g_callerHmac256Kek;
        importWrappedKeyTestParams004.callerAgreeKeyAlias = &g_callerAgreeKeyAliasHmac256;
        importWrappedKeyTestParams004.importedKeyAlias = &g_importedKeyAliasHmac256;
        importWrappedKeyTestParams004.importedPlainKey = &g_importHmac256Key;
        InitCommonTestParamsAndDoImport(&importWrappedKeyTestParams004, g_importHmac256KeyAtherParams,
                                        sizeof(g_importHmac256KeyAtherParams) / sizeof(struct HksParam));
        HksClearKeysForWrappedKeyTest(&importWrappedKeyTestParams004);
    }
}
