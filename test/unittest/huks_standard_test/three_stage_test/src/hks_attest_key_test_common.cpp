/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_attest_key_test_common.h"

#include <cstdlib>
#include <gtest/gtest.h>

using namespace testing::ext;

namespace Unittest::AttestKey {
static const uint32_t g_paramCount = 6;
static const uint32_t g_paramCountInKeyAttest = 5;
static const uint32_t g_paramCountInIdAttest = 7;
static const uint32_t g_index0 = 0;
static const uint32_t g_index1 = 1;
static const uint32_t g_index2 = 2;
static const uint32_t g_index3 = 3;
static const uint32_t g_index4 = 4;
static const uint32_t g_index5 = 5;
static const uint32_t g_index6 = 6;

void FreeCertChain(struct HksCertChain **certChain, const uint32_t pos)
{
    if (certChain == nullptr || *certChain == nullptr) {
        return;
    }

    if ((*certChain)->certs == nullptr) {
        HKS_FREE(*certChain);
        *certChain = nullptr;
        return;
    }
    for (uint32_t j = 0; j < pos; j++) {
        if ((*certChain)->certs[j].data != nullptr) {
            HKS_FREE((*certChain)->certs[j].data);
            (*certChain)->certs[j].data = nullptr;
        }
    }

    if ((*certChain)->certs != nullptr) {
        HKS_FREE((*certChain)->certs);
        (*certChain)->certs = nullptr;
    }

    if (*certChain != nullptr) {
        HKS_FREE(*certChain);
        *certChain = nullptr;
    }
}

int32_t GenerateParamSet(struct HksParamSet **paramSet, const struct HksParam tmpParams[], uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    if (tmpParams != nullptr) {
        ret = HksAddParams(*paramSet, tmpParams, paramCount);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAddParams failed");
            HksFreeParamSet(paramSet);
            return ret;
        }
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksBuildParamSet failed");
        HksFreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

int32_t TestGenerateKeyCommon(const struct HksBlob *keyAlias, const struct HksParam tmpParams[], uint32_t paramCount)
{
    struct HksParamSet *paramSet = nullptr;

    int32_t ret = GenerateParamSet(&paramSet, tmpParams, paramCount);

    ret = HksGenerateKey(keyAlias, paramSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksGenerateKey failed");
    }
    HksFreeParamSet(&paramSet);
    return ret;
}

int32_t TestGenerateKey(const struct HksBlob *keyAlias, uint32_t keyPadding)
{
    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = keyPadding },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };

    int32_t ret = TestGenerateKeyCommon(keyAlias, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksGenerateKey failed");
    }
    return ret;
}

int32_t ConstructDataToCertChain(struct HksCertChain **certChain,
    const struct HksTestCertChain *certChainParam)
{
    if (!certChainParam->certChainExist) {
        return 0;
    }
    *certChain = static_cast<struct HksCertChain *>(HksMalloc(sizeof(struct HksCertChain)));
    if (*certChain == nullptr) {
        HKS_LOG_E("malloc fail");
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (!certChainParam->certCountValid) {
        (*certChain)->certsCount = 0;
        (*certChain)->certs = nullptr;
        return 0;
    }
    (*certChain)->certsCount = CERT_COUNT;
    if (!certChainParam->certDataExist) {
        (*certChain)->certs = nullptr;
        return 0;
    }
    (*certChain)->certs = static_cast<struct HksBlob *>(HksMalloc(sizeof(struct HksBlob) *
    ((*certChain)->certsCount)));
    if ((*certChain)->certs == nullptr) {
        HKS_FREE(*certChain);
        *certChain = nullptr;
        return HKS_ERROR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < (*certChain)->certsCount; i++) {
        (*certChain)->certs[i].size = certChainParam->certDataSize;
        (*certChain)->certs[i].data = static_cast<uint8_t *>(HksMalloc((*certChain)->certs[i].size));
        if ((*certChain)->certs[i].data == nullptr) {
            HKS_LOG_E("malloc fail");
            FreeCertChain(certChain, i);
            return HKS_ERROR_MALLOC_FAIL;
        }
        memset_s((*certChain)->certs[i].data, certChainParam->certDataSize, 0, certChainParam->certDataSize);
    }
    return 0;
}

static int32_t ValidataAndCompareCertInfo(ParamType type, const struct HksCertChain *certChain,
    struct HksParamSet *paramSet)
{
    if (certChain == nullptr || paramSet == nullptr) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HksValidateCertChain(certChain, paramSet);
    HKS_LOG_I("validate cert chain result is %" LOG_PUBLIC "x", ret);
    HKS_LOG_I("paramsSet count is : %" LOG_PUBLIC "d", paramSet->paramsCnt);
    HKS_LOG_I("secinfo is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index0].blob.data));
    HKS_LOG_I("challenge is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index1].blob.data));
    HKS_LOG_I("version is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index2].blob.data));
    HKS_LOG_I("alias is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index3].blob.data));
    HKS_LOG_I("appId is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index4].blob.data));
    if (ret == HKS_SUCCESS) {
        ret |= strcmp(SEC_INFO_DATA, reinterpret_cast<char *>(paramSet->params[g_index0].blob.data));
        ret |= strcmp(CHALLENGE_DATA, reinterpret_cast<char *>(paramSet->params[g_index1].blob.data));
        ret |= strcmp(VERSION_DATA, reinterpret_cast<char *>(paramSet->params[g_index2].blob.data));
        ret |= strcmp(ALIAS, reinterpret_cast<char *>(paramSet->params[g_index3].blob.data));
        ret |= strcmp(APP_ID, reinterpret_cast<char *>(paramSet->params[g_index4].blob.data));
    }
    if (type == IDS_PARAM) {
        HKS_LOG_I("udid is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index4].blob.data));
        HKS_LOG_I("sn is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index5].blob.data));
        HKS_LOG_I("device id is %" LOG_PUBLIC "s\n", reinterpret_cast<char *>(paramSet->params[g_index6].blob.data));
        if (ret == HKS_SUCCESS) {
            ret |= strcmp(UDID_DATA, reinterpret_cast<char *>(paramSet->params[g_index4].blob.data));
            ret |= strcmp(SN_DATA, reinterpret_cast<char *>(paramSet->params[g_index5].blob.data));
            ret |= strcmp(DEVICE_ID, reinterpret_cast<char *>(paramSet->params[g_index6].blob.data));
        }
    }
    return ret;
}

int32_t ValidateCertChainTest(const struct HksCertChain *certChain,
    const struct HksParam tmpParam[], ParamType type)
{
    int32_t ret = HKS_ERROR_MALLOC_FAIL;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        uint32_t paramCount = 0;
        if (type == IDS_PARAM) {
            paramCount = g_paramCountInIdAttest;
        } else if (type == NON_IDS_PARAM) {
            paramCount = g_paramCountInKeyAttest;
        } else if (type == NON_IDS_BASE64_PARAM) {
            paramCount = g_paramCount;
        }
        ret = HksAddParams(paramSet, tmpParam, paramCount);
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksBuildParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = ValidataAndCompareCertInfo(type, certChain, paramSet);
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}
}
