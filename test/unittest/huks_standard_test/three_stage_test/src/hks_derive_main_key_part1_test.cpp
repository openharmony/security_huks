/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "hks_derive_main_key_test_common.h"
#include "hks_three_stage_test_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksDeriveMainKeyTest {
class HksDeriveMainKeyPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDeriveMainKeyPart1Test::SetUpTestCase(void)
{
}

void HksDeriveMainKeyPart1Test::TearDownTestCase(void)
{
}

void HksDeriveMainKeyPart1Test::SetUp()
{
}

void HksDeriveMainKeyPart1Test::TearDown()
{
}

/**
 * @tc.name: HksDeriveMainKeyPart1Test.HksDeriveMainKeyPart1Test001
 * @tc.desc: generate de key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart1Test, HksDeriveMainKeyPart1Test001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksDeriveMainKeyPart1Test001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart1Test.HksDeriveMainKeyPart1Test002
 * @tc.desc: generate ce key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart1Test, HksDeriveMainKeyPart1Test002, TestSize.Level0)
{
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksDeriveMainKeyPart1Test002";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart1Test.HksDeriveMainKeyPart1Test003
 * @tc.desc: import ece key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart1Test, HksDeriveMainKeyPart1Test003, TestSize.Level0)
{
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    char tmpKeyAlias[] = "HksDeriveMainKeyPart1Test003";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksImportKey(&keyAlias, genParamSet, &keyImported);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams003, sizeof(g_encryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams003, sizeof(g_decryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

static const uint32_t DH_COMMON_SIZE = 2048;
static struct HksParam g_genParams010[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
    { .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_agreeParams01Init004[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_agreeParams02Init004[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_agreeParamsFinish010[] = {
    {
        .tag = HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_ALLOW_KEY_EXPORTED
    }
};
static struct HksBlob g_keyAlias01010 = {
    strlen("HksDHAgreeKeyAliasTest010_1"),
    (uint8_t *)"HksDHAgreeKeyAliasTest010_1"
};
static struct HksBlob g_keyAlias02010 = {
    strlen("HksDHAgreeKeyAliasTest010_2"),
    (uint8_t *)"HksDHAgreeKeyAliasTest010_2"
};

int32_t HksDhAgreeFinish(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
                         const struct HksParamSet *initParamSet, const struct HksParamSet *finishParamSet,
                         struct HksBlob *outData)
{
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };

    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    int32_t ret = HksInit(keyAlias, initParamSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    uint8_t outDataU[DH_COMMON_SIZE] = {0};
    struct HksBlob outDataUpdate = { DH_COMMON_SIZE, outDataU };
    ret = HksUpdate(&handle, initParamSet, publicKey, &outDataUpdate);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    return HksFinish(&handle, finishParamSet, &inData, outData);
}

int32_t HksDhAgreeExport(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2,
                         struct HksBlob *publicKey1, struct HksBlob *publicKey2,
                         const struct HksParamSet *genParamSet)
{
    int32_t ret = HksExportPublicKey(keyAlias1, genParamSet, publicKey1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey01 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    ret = HksExportPublicKey(keyAlias2, genParamSet, publicKey2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey02 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

void HksDhAgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
                            struct HksParamSet *paramSet3, struct HksParamSet *paramSet4,
                            struct HksParamSet *paramSet5)
{
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
    HksFreeParamSet(&paramSet3);
    HksFreeParamSet(&paramSet4);
    HksFreeParamSet(&paramSet5);
}

void HksDhAgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2, struct HksBlob *blob3, struct HksBlob *blob4)
{
    HKS_FREE(blob1->data);
    HKS_FREE(blob2->data);
    HKS_FREE(blob3->data);
    HKS_FREE(blob4->data);
}

/**
 * @tc.name: HksDeriveMainKeyPart1Test.HksDeriveMainKeyPart1Test004
 * @tc.desc: agree key
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart1Test, HksDeriveMainKeyPart1Test004, TestSize.Level0)
{
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams010, sizeof(g_genParams010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_agreeParams01Init004, sizeof(g_agreeParams01Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_agreeParamsFinish010, sizeof(g_agreeParamsFinish010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_agreeParams02Init004, sizeof(g_agreeParams02Init004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_agreeParamsFinish010, sizeof(g_agreeParamsFinish010) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01010, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02010, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksDhAgreeExport(&g_keyAlias01010, &g_keyAlias02010, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksDhAgreeFinish(&g_keyAlias01010, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAgreeKey(initParamSet02, &g_keyAlias02010, &publicKey01, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAgreeKey02 failed.";
    EXPECT_EQ(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "outData01 not equals outData02";

    HksDeleteKey(&g_keyAlias01010, genParamSet);
    HksDeleteKey(&g_keyAlias02010, genParamSet);
    HksDhAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksDhAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

static const std::string g_deriveInfo = "Hks_HMAC_Derive_Test_0000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t COMMON_SIZE = 2048;
static const uint32_t DERIVE_KEY_SIZE_32 = 32;
static struct HksParam g_genParams005[] = {
    { .tag =  HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag =  HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
    { .tag =  HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_hmacParams005[] = {
    { .tag =  HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
    { .tag =  HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
    { .tag =  HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag =  HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_32 },
    {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = g_deriveInfo.length(),
            .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_deriveInfo.c_str()))
        }
    },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_hmacFinishParams005[] = {
    { .tag =  HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = {
            strlen("HksHMACDeriveKeyAliasFinalTest001"),
            (uint8_t *)"HksHMACDeriveKeyAliasFinalTest001"
        }
    },
    { .tag =  HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag =  HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    { .tag =  HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};

int32_t HksHmacDeriveTestNormalCase(const struct HksBlob keyAlias, const struct HksParamSet *genParamSet,
    struct HksParamSet *deriveParamSet, struct HksParamSet *deriveFinalParamsSet, int32_t cmpRet)
{
    struct HksBlob inData = { 0, nullptr };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    // Generate Key
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Derive Three Stage */
    // Init
    uint8_t handleDTest[sizeof(uint64_t)] = {0};
    struct HksBlob handleDerive = { sizeof(uint64_t), handleDTest };
    ret = HksInit(&keyAlias, deriveParamSet, &handleDerive, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    // Update
    uint8_t tmpOut[COMMON_SIZE] = {0};
    struct HksBlob outData = { COMMON_SIZE, tmpOut };
    ret = HksUpdate(&handleDerive, deriveParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
    // Finish
    uint8_t outDataD[COMMON_SIZE] = {0};
    struct HksBlob outDataDerive = { COMMON_SIZE, outDataD };
    ret = HksFinish(&handleDerive, deriveFinalParamsSet, &inData, &outDataDerive);
    EXPECT_EQ(ret, cmpRet) << "Finish failed.";

    return ret;
}

/**
 * @tc.name: HksDeriveMainKeyPart1Test.HksDeriveMainKeyPart1Test005
 * @tc.desc: derive key, alg-HMAC pur-Derive dig-SHA256 derived_key-AES/256
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart1Test, HksDeriveMainKeyPart1Test005, TestSize.Level0)
{
    int32_t ret;
#ifdef HKS_INTERACT_ABILITY
    ret = SetIdsToken();
    EXPECT_EQ(ret, HKS_SUCCESS);
#endif

    struct HksBlob keyAlias = { strlen("HksDeriveMainKeyPart1Test005"), (uint8_t *)"HksDeriveMainKeyPart1Test005" };
    ret = HKS_FAILURE;

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
    HksHmacDeriveTestNormalCase(keyAlias, genParamSet, hkdfParamSet, hkdfFinishParamSet, HKS_SUCCESS);
    /* 3. Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    struct HksBlob deleteKeyAlias = {
        .size = strlen("HksHMACDeriveKeyAliasFinalTest001"),
        .data = (uint8_t *)"HksHMACDeriveKeyAliasFinalTest001"
    };
    ret = HksDeleteKey(&deleteKeyAlias, hkdfFinishParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Delete Final Key failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hkdfParamSet);
    HksFreeParamSet(&hkdfFinishParamSet);
}
}
