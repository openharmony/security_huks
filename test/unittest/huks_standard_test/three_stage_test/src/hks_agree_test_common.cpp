/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_agree_test_common.h"
#include "hks_three_stage_test_common.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"

#define HKS_SHA256_CBC \
{ \
    .tag = HKS_TAG_DIGEST, \
    .uint32Param = HKS_DIGEST_SHA256 \
}, { \
    .tag = HKS_TAG_PADDING, \
    .uint32Param = HKS_PADDING_NONE \
}, { \
    .tag = HKS_TAG_BLOCK_MODE, \
    .uint32Param = HKS_MODE_CBC \
}, { \
    .tag = HKS_TAG_IV, \
    .blob = { \
        .size = AGREE_TEST_IV_SIZE, \
        .data = (uint8_t *)AGREE_TEST_IV \
    } \
}

const static uint32_t AGREE_TEST_IV_SIZE = 16;
const static uint8_t AGREE_TEST_IV[AGREE_TEST_IV_SIZE] = { 0 };

static struct HksParam g_agreedKeyEncrypt001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    },
    HKS_SHA256_CBC
};

static struct HksParam g_agreedKeyDecrypt001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    },
    HKS_SHA256_CBC
};

static int32_t TestAgreedKeyEncryptDecrypt(const struct HksBlob *keyAlias1, const struct HksParamSet *encryptParamSet,
    const struct HksBlob *keyAlias2, struct HksParamSet *decryptParamSet)
{
    const char *plainTest = "test_plain_test_";
    struct HksBlob plaindata = { .size = (uint32_t)strlen(plainTest), .data = (uint8_t *)plainTest };
    const uint32_t cipherMaxSize = 1024;
    uint8_t cipherBuffer[cipherMaxSize] = { 0 };
    struct HksBlob cipherData = { .size = cipherMaxSize, .data = (uint8_t *)cipherBuffer };

    int32_t ret = HksEncrypt(keyAlias1, encryptParamSet, &plaindata, &cipherData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksEncrypt failed.")

    uint8_t decrypedBuffer[cipherMaxSize] = { 0 };
    struct HksBlob decrypedData = { .size = cipherMaxSize, .data = (uint8_t *)decrypedBuffer };

    ret = HksDecrypt(keyAlias2, decryptParamSet, &cipherData, &decrypedData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksDecrypt failed.")

    if (decrypedData.size != plaindata.size ||
        HksMemCmp(decrypedData.data, plaindata.data, plaindata.size) != HKS_SUCCESS) {
        printf("compare decrypedData.data and plaindata.data failed!\n");
        return HKS_FAILURE;
    }
    return ret;
}

int32_t TestAgreedKeyUse(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2)
{
    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret;
    do {
        ret = InitParamSet(&encryptParamSet, g_agreedKeyEncrypt001, HKS_ARRAY_SIZE(g_agreedKeyEncrypt001));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "InitParamSet g_agreedKeyEncrypt001 failed.");

        ret = InitParamSet(&decryptParamSet, g_agreedKeyDecrypt001, HKS_ARRAY_SIZE(g_agreedKeyDecrypt001));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "InitParamSet g_agreedKeyDecrypt001 failed.");

        ret = TestAgreedKeyEncryptDecrypt(keyAlias1, encryptParamSet, keyAlias2, decryptParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "InitParamSet g_agreedKeyDecrypt001 failed.");
    } while (0);

    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
    return ret;
}

int32_t TestDerivedKeyUse(const struct HksBlob *keyAlias)
{
    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret;
    do {
        ret = InitParamSet(&encryptParamSet, g_agreedKeyEncrypt001, HKS_ARRAY_SIZE(g_agreedKeyEncrypt001));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "InitParamSet g_agreedKeyEncrypt001 failed.");

        ret = InitParamSet(&decryptParamSet, g_agreedKeyDecrypt001, HKS_ARRAY_SIZE(g_agreedKeyDecrypt001));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "InitParamSet g_agreedKeyDecrypt001 failed.");

        ret = TestAgreedKeyEncryptDecrypt(keyAlias, encryptParamSet, keyAlias, decryptParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "InitParamSet g_agreedKeyDecrypt001 failed.");
    } while (0);

    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
    return ret;
}