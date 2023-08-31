/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hks_test_aes_c.h"

#define TEST_AES_32 32

int32_t TestAes256ByLocal()
{
    HKS_TEST_LOG_I("enter");

    /* generate aes key 1 */
    char testKey[TEST_AES_32];
    struct HksBlob keyBlob;

    for (int i = 0; i < TEST_AES_32; ++i) {
        testKey[i] = i + TEST_AES_32;
    }

    keyBlob.data = (uint8_t *)testKey;
    keyBlob.size = sizeof(testKey);

    /* encrypt by aes key 1 */
    struct HksParamSet *paramSet = NULL;
    struct HksParam algParam = {
        .tag = HKS_TAG_IS_KEY_ALIAS,
        .uint32Param = 0
    };

    int32_t ret = ConstructParamSetEncryptDecryptAes(HKS_MODE_GCM, HKS_PADDING_NONE, true, &paramSet);
    HKS_TEST_ASSERT(ret == 0);

    ret = HksAddParams(paramSet, (const struct HksParam *)&algParam, 1);
    if (ret != 0) {
        HKS_TEST_LOG_E("HksAddParam algParam failed!\n");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    struct HksBlob plainText1 = { strlen(TEST_PLAIN_TEST) + 1, (uint8_t*)TEST_PLAIN_TEST };
    struct HksBlob cipherText1 = { TEST_AES_256, g_buffer };
    (void)memset_s(cipherText1.data, cipherText1.size, 0, cipherText1.size);
    HKS_TEST_ASSERT(HksEncrypt(&keyBlob, paramSet, &plainText1, &cipherText1) == 0);
    g_bufferSize = cipherText1.size;

    HksFreeParamSet(&paramSet);

    /* decrypt by aes key 2 */
    ret = ConstructParamSetEncryptDecryptAes(HKS_MODE_GCM, HKS_PADDING_NONE, false, &paramSet);
    HKS_TEST_ASSERT(ret == 0);
    algParam.tag = HKS_TAG_IS_KEY_ALIAS;
    algParam.uint32Param = 0;
    ret = HksAddParams(paramSet, (const struct HksParam *)&algParam, 1);
    if (ret != 0) {
        HKS_TEST_LOG_E("HksAddParam algParam failed!\n");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    struct HksBlob cipherText = { g_bufferSize, g_buffer };
    uint8_t tmp[TEST_AES_256] = {0};
    struct HksBlob plainText = { TEST_AES_256, tmp };
    ret = HksDecrypt(&keyBlob, paramSet, &cipherText, &plainText);
    HKS_TEST_ASSERT(ret == 0);
    HKS_TEST_ASSERT(plainText1.size == plainText.size);
    HKS_TEST_ASSERT(memcmp(plainText.data, plainText1.data, plainText.size) == 0);
    HksFreeParamSet(&paramSet);

    HKS_TEST_LOG_I("end");
    return ret;
}

