/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>

#include "hks_modify_key_test_c.h"

#include "file_ex.h"
#include "hks_file_operator.h"

using namespace testing::ext;
namespace {
class HksModifyKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksModifyKeyTest::SetUpTestCase(void)
{
}

void HksModifyKeyTest::TearDownTestCase(void)
{
}

void HksModifyKeyTest::SetUp()
{
}

void HksModifyKeyTest::TearDown()
{
}

const int DEFAULT_AES_CIPHER_PLAIN_SIZE = 1000;
const int AES_DEFAULT_GCM_NONCE_LENGTH = 12;
const int AES_DEFAULT_AAD_LEN = 4;

const char *g_storePath = HKS_KEY_STORE_PATH "/+0+0+0+0/key";

const char *g_testName = "TestName";

static const struct HksTestCipherParams g_testCipherParams[] = {
    /* success: aes256-gcm-none */
    G_TEST_CIPHER_PARAMS
};

static int32_t ModifyKey(struct HksBlob *keyAlias)
{
    uint32_t sizeOne = HksFileSize(g_storePath, (char *)keyAlias->data);
    uint8_t *bufOne = (uint8_t *)HksTestMalloc(sizeOne);
    if (bufOne == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob blobOne = { .size = sizeOne, .data = bufOne };
    uint32_t sizeRead = 0;
    int32_t ret = HksFileRead(g_storePath, (char *)keyAlias->data, 0, &blobOne, &sizeRead);
    (void)memset_s(bufOne, sizeRead, 0, sizeRead);

    ret = HksFileWrite(g_storePath, (char *)keyAlias->data, 0, bufOne, sizeOne);
    HksTestFree(bufOne);

    return ret;
}


int32_t BaseTestCipher(struct HksBlob *keyAlias, uint32_t index)
{
    struct HksBlob *plainData = NULL;
    struct HksBlob *cipherData = NULL;
    struct HksBlob *decryptedData = NULL;
    int32_t ret = ConstructDataToBlob(&plainData, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    EXPECT_TRUE(ret == 0);
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;
    /* 2. encrypt */
    do {
        struct CipherEncryptStructure testEncryptStruct = {
            keyAlias, &g_testCipherParams[index].encryptParamSetParams,
            plainData, cipherData, &ivData, &nonceData, &aadData, 1
        };
        ret = Encrypt(&testEncryptStruct);
        if (ret != g_testCipherParams[index].expectResult) {
            break;
        }
        /* 3. decrypt */
        struct CipherDecryptStructure testDecryptStruct = {
            keyAlias, &g_testCipherParams[index], cipherData,
            &decryptedData, ivData, nonceData, aadData, 1
        };
        ret = DecryptCipher(&testDecryptStruct);
        if (ret != g_testCipherParams[index].expectResult) {
            break;
        }

        if (ret == g_testCipherParams[index].expectResult) {
            if (plainData->size != decryptedData->size) {
                break;
            }
            ret = memcmp(plainData->data, decryptedData->data, plainData->size);
        }
    } while (0);
    TestFreeBlob(&plainData);
    TestFreeBlob(&cipherData);
    TestFreeBlob(&decryptedData);
    TestFreeBlob(&ivData);
    TestFreeBlob(&nonceData);
    TestFreeBlob(&aadData);
    return ret;
}

/**
 * @tc.name: HksModifyKeyTest.HksModifyKeyTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksModifyKeyTest, HksModifyKeyTest001, TestSize.Level0)
{
    uint32_t index = 0;
    struct HksBlob keyAlias = { strlen(g_testName), (uint8_t *)g_testName };
    int32_t ret = GenerateKeyTwo(&keyAlias, &g_testCipherParams[index].keyAliasParams,
            &g_testCipherParams[index].genKeyParamSetParams, &g_testCipherParams[index].genKeyParamSetParamsOut);
    ASSERT_TRUE(ret == 0);

    ret = BaseTestCipher(&keyAlias, 0);
    ASSERT_TRUE(ret == 0);

    struct HksBlob *plainData = NULL;
    struct HksBlob *cipherData = NULL;
    ret = ConstructDataToBlob(&plainData, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    EXPECT_TRUE(ret == 0);
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;

    /* 2. encrypt */
    struct CipherEncryptStructure testEncryptStruct = {
        &keyAlias, &g_testCipherParams[index].encryptParamSetParams,
        plainData, cipherData, &ivData, &nonceData, &aadData, 1
    };
    ret = Encrypt(&testEncryptStruct);
    ret = ModifyKey(&keyAlias);
    /* 3. decrypt */
    struct HksBlob *decryptedData = NULL;
    struct CipherDecryptStructure testDecryptStruct = {
        &keyAlias, &g_testCipherParams[index], cipherData,
        &decryptedData, ivData, nonceData, aadData, 1
    };
    ret = DecryptCipher(&testDecryptStruct);

    EXPECT_TRUE(ret != g_testCipherParams[index].expectResult);
    (void)HksDeleteKey(&keyAlias, NULL);
    TestFreeBlob(&plainData);
    TestFreeBlob(&cipherData);
    TestFreeBlob(&decryptedData);
    TestFreeBlob(&ivData);
    TestFreeBlob(&nonceData);
    TestFreeBlob(&aadData);
    ASSERT_TRUE(ret != 0);
}
}
