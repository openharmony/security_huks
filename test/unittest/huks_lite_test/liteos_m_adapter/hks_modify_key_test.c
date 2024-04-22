/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef _CUT_AUTHENTICATE_

#include "hks_modify_key_test_c.h"

#include <hctest.h>
#include "hi_watchdog.h"

#include "stdlib.h"

#define DEFAULT_AES_CIPHER_PLAIN_SIZE 1000
#define AES_DEFAULT_GCM_NONCE_LENGTH 12
#define AES_DEFAULT_AAD_LEN 4
static const char *g_storePath = "./hks_store/";
static const char *g_testName = "TestName";

static const struct HksTestCipherParams g_testCipherParams[] = {
    /* success: aes256-gcm-none */
    G_TEST_CIPHER_PARAMS
};

/*
 * @tc.register: register a test suit named "CalcMultiTest"
 * @param: test subsystem name
 * @param: c_example module name
 * @param: CalcMultiTest test suit name
 */
LITE_TEST_SUIT(husk, huks_lite, HksModifyKeyTest);

/**
 * @tc.setup: define a setup for test suit, format:"CalcMultiTest + SetUp"
 * @return: true——setup success
 */
static BOOL HksModifyKeyTestSetUp()
{
    LiteTestPrint("setup\n");
    hi_watchdog_disable();
    TEST_ASSERT_TRUE(HksInitialize() == 0);
    return TRUE;
}

static void HksTestRemoveFile(void)
{
}

/**
 * @tc.teardown: define a setup for test suit, format:"CalcMultiTest + TearDown"
 * @return: true——teardown success
 */
static BOOL HksModifyKeyTestTearDown()
{
    LiteTestPrint("tearDown\n");
    HksTestRemoveFile();
    hi_watchdog_enable();
    return TRUE;
}

int32_t BaseTestCipherProcess(const struct HksBlob *keyAlias, uint32_t index)
{
    struct HksBlob *plainData = NULL;
    struct HksBlob *cipherData = NULL;
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;
    struct HksBlob *decryptedData = NULL;
    int32_t ret = ConstructDataToBlob(&plainData, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    HKS_TEST_ASSERT(ret == 0);
    /* 2. encrypt */
    do {
        struct CipherDecryptStructure testDecryptStruct = {
            keyAlias, &g_testCipherParams[index], cipherData,
            &decryptedData, ivData, nonceData, aadData, 1
        };
        struct CipherEncryptStructure testEncryptStruct = {
            keyAlias, &g_testCipherParams[index].encryptParamSetParams,
            plainData, cipherData, &ivData, &nonceData, &aadData, 1
        };
        ret = Encrypt(&testEncryptStruct);
        if (ret != g_testCipherParams[index].expectResult) {
            break;
        }
        /* 3. decrypt */
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

enum HksStorageType {
    HKS_STORAGE_TYPE_KEY = 0,
    HKS_STORAGE_TYPE_ROOT_KEY,
};

extern int32_t HksStoreKeyBlob(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    uint32_t storageType, const struct HksBlob *keyBlob);
int32_t __attribute__((weak)) HksStoreKeyBlob(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    uint32_t storageType, const struct HksBlob *keyBlob)
{
    (void)processName;
    (void)keyAlias;
    (void)storageType;
    (void)keyBlob;
    return HKS_SUCCESS;
}

/**
 * @tc.name: HksModifyKeyTest.HksModifyKeyTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
LITE_TEST_CASE(HksModifyKeyTest, HksModifyKeyTest001, Level1)
{
    uint32_t index = 0;
    struct HksBlob keyAlias = { strlen(g_testName), (uint8_t *)g_testName };
    int32_t ret = GenerateKeyTwo(&keyAlias, &g_testCipherParams[index].keyAliasParams,
        &g_testCipherParams[index].genKeyParamSetParams, &g_testCipherParams[index].genKeyParamSetParamsOut);
    TEST_ASSERT_TRUE(ret == 0);

    ret = BaseTestCipherProcess(&keyAlias, 0);
    TEST_ASSERT_TRUE(ret == 0);

    struct HksBlob *plainData = NULL;
    struct HksBlob *cipherData = NULL;
    ret = ConstructDataToBlob(&plainData, &cipherData,
        &g_testCipherParams[index].plainTextParams, &g_testCipherParams[index].cipherTextParams);
    TEST_ASSERT_TRUE(ret == 0);
    struct HksBlob *ivData = NULL;
    struct HksBlob *nonceData = NULL;
    struct HksBlob *aadData = NULL;

    /* 2. encrypt */
    struct CipherEncryptStructure testEncryptStruct = {
        &keyAlias, &g_testCipherParams[index].encryptParamSetParams,
        plainData, cipherData, &ivData, &nonceData, &aadData, 1
    };
    ret = Encrypt(&testEncryptStruct);
    TEST_ASSERT_TRUE(ret == 0);

    ret = GenerateKeyTwo(&keyAlias, &g_testCipherParams[index].keyAliasParams,
        &g_testCipherParams[index].genKeyParamSetParams, &g_testCipherParams[index].genKeyParamSetParamsOut);
    TEST_ASSERT_TRUE(ret == 0);

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
    TEST_ASSERT_TRUE(ret != 0);
}

RUN_TEST_SUITE(HksModifyKeyTest);
#endif /* _CUT_AUTHENTICATE_ */

