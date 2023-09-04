/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "securec.h"

using namespace testing::ext;
namespace {
#ifndef _CUT_AUTHENTICATE_

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
    EXPECT_EQ(HksInitialize(), 0);
}

void HksModifyKeyTest::TearDown()
{
}

const int DEFAULT_AES_CIPHER_PLAIN_SIZE = 1000;
const int AES_DEFAULT_GCM_NONCE_LENGTH = 12;
const int AES_DEFAULT_AAD_LEN = 4;
const char *g_storePath = "/storage/data/service/el1/public/huks_service/maindata/+0+0+0+0/key";
const char *g_testName = "TestName";

const struct HksTestCipherParams g_testCipherParams[] = {
    /* success: aes256-gcm-none */
    G_TEST_CIPHER_PARAMS
};

static int32_t ModifyKey(struct HksBlob *keyAlias)
{
    uint32_t sizeOne = HksTestFileSize(g_storePath, (char *)keyAlias->data);
    uint8_t *bufOne = (uint8_t *)HksTestMalloc(sizeOne);
    if (bufOne == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    uint32_t sizeRead = HksTestFileRead(g_storePath, (char *)keyAlias->data, 0, bufOne, sizeOne);
    (void)memset_s(bufOne, sizeRead, 0, sizeRead);

    int32_t ret = HksTestFileWrite(g_storePath, (char *)keyAlias->data, 0, bufOne, sizeOne);
    HksTestFree(bufOne);

    return ret;
}

int32_t BaseTestCipherProcess(struct HksBlob *keyAlias, uint32_t index)
{
    struct HksBlob *plainDataTest = NULL;
    struct HksBlob *cipherData = NULL;
    int32_t ret = ConstructDataToBlob(&plainDataTest, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    HKS_TEST_ASSERT(ret == 0);
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;
    struct HksBlob *decryptedData = NULL;
    /* 2. encrypt */
    do {
        struct CipherEncryptStructure testEncryptStruct = {
            keyAlias, &g_testCipherParams[index].encryptParamSetParams,
            plainDataTest, cipherData, &ivData, &nonceData, &aadData, 1
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
            if (plainDataTest->size != decryptedData->size) {
                break;
            }
            ret = memcmp(plainDataTest->data, decryptedData->data, plainDataTest->size);
        }
    } while (0);
    TestFreeBlob(&plainDataTest);
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
    struct HksBlob keyAlias = { strlen(g_testName), (uint8_t *)g_testName };
    uint32_t index = 0;
    int32_t ret = GenerateKeyTwo(&keyAlias, &g_testCipherParams[index].keyAliasParams,
            &g_testCipherParams[index].genKeyParamSetParams, &g_testCipherParams[index].genKeyParamSetParamsOut);
    EXPECT_EQ(ret, 0);

    ret = BaseTestCipherProcess(&keyAlias, 0);
    EXPECT_EQ(ret, 0);

    struct HksBlob *plainData = NULL;
    struct HksBlob *cipherData = NULL;
    ret = ConstructDataToBlob(&plainData, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    EXPECT_EQ(ret, 0);
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;

    /* 2. encrypt */
    struct CipherEncryptStructure testEncryptStruct = {
        &keyAlias, &g_testCipherParams[index].encryptParamSetParams,
        plainData, cipherData, &ivData, &nonceData, &aadData, 1
    };
    ret = Encrypt(&testEncryptStruct);
    EXPECT_EQ(ret, 0);
    ret = ModifyKey(&keyAlias);
    EXPECT_EQ(ret, 0);
    /* 3. decrypt */
    struct HksBlob *decryptedData = NULL;
    struct CipherDecryptStructure testDecryptStruct = {
        &keyAlias, &g_testCipherParams[index], cipherData,
        &decryptedData, ivData, nonceData, aadData, 1
    };
    ret = DecryptCipher(&testDecryptStruct);

    HKS_TEST_ASSERT(ret != g_testCipherParams[index].expectResult);
    TestFreeBlob(&plainData);
    TestFreeBlob(&cipherData);
    TestFreeBlob(&decryptedData);
    TestFreeBlob(&ivData);
    TestFreeBlob(&nonceData);
    TestFreeBlob(&aadData);
    EXPECT_NE(ret, 0);

    (void)HksDeleteKey(&keyAlias, nullptr);
}
#endif /* _CUT_AUTHENTICATE_ */
}
