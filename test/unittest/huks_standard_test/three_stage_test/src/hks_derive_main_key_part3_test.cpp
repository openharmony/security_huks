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
#include "hks_apply_permission_test_common.h"
#include "hks_derive_main_key_test_common.h"
#include "hks_three_stage_test_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksDeriveMainKeyTest {
class HksDeriveMainKeyPart3Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDeriveMainKeyPart3Test::SetUpTestCase(void)
{
}

void HksDeriveMainKeyPart3Test::TearDownTestCase(void)
{
}

void HksDeriveMainKeyPart3Test::SetUp()
{
}

void HksDeriveMainKeyPart3Test::TearDown()
{
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test001
 * @tc.desc: de key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test001, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias1 = { strlen(g_tmpKeyAlias1), (uint8_t *)g_tmpKeyAlias1 };
    ret = HksKeyExist(&keyAlias1, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias1, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias1, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias1, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test002
 * @tc.desc: ce key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test002, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias2 = { strlen(g_tmpKeyAlias2), (uint8_t *)g_tmpKeyAlias2 };
    ret = HksKeyExist(&keyAlias2, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias2, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias2, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias2, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test003
 * @tc.desc: ece key, encrypt and decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test003, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias3 = { strlen(g_tmpKeyAlias3), (uint8_t *)g_tmpKeyAlias3 };
    ret = HksKeyExist(&keyAlias3, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams003, sizeof(g_encryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    uint8_t cipher[AES_COMMON_SIZE] = { 0 };
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(&keyAlias3, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams003, sizeof(g_decryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    ret = HksAesCipherTestDecrypt(&keyAlias3, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias3, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test004
 * @tc.desc: de key, decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test004, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias4 = { strlen(g_tmpKeyAlias4), (uint8_t *)g_tmpKeyAlias4 };
    ret = HksKeyExist(&keyAlias4, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    struct HksBlob cipherText = { AES_COMMON_SIZE, g_cipher };
    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    ret = HksAesCipherTestDecrypt(&keyAlias4, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias4, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test005
 * @tc.desc: ce key, decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test005, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias5 = { strlen(g_tmpKeyAlias5), (uint8_t *)g_tmpKeyAlias5 };
    ret = HksKeyExist(&keyAlias5, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    struct HksBlob cipherText = { AES_COMMON_SIZE, g_cipher };
    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    ret = HksAesCipherTestDecrypt(&keyAlias5, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias5, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart3Test.HksDeriveMainKeyPart3Test006
 * @tc.desc: ece key, decrypt after upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart3Test, HksDeriveMainKeyPart3Test006, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias6 = { strlen(g_tmpKeyAlias6), (uint8_t *)g_tmpKeyAlias6 };
    ret = HksKeyExist(&keyAlias6, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyExist failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams003, sizeof(g_decryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    struct HksBlob cipherText = { AES_COMMON_SIZE, g_cipher };
    uint8_t out[AES_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { AES_COMMON_SIZE, out };
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };
    ret = HksAesCipherTestDecrypt(&keyAlias6, decryptParamSet, &cipherText, &outData, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    ret = HksDeleteKey(&keyAlias6, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&decryptParamSet);
}
}
