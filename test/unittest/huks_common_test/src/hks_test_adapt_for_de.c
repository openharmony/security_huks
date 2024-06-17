/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_test_adapt_for_de.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

static int32_t GenerateParamSet(struct HksParamSet **paramSet, const struct HksParam tmpParams[], uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    if (tmpParams != NULL) {
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

int32_t ConstructNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **newParamSet)
{
    int32_t ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check paramSet fail");
        return ret;
    }
    ret = HksInitParamSet(newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init paramSet fail");
        return ret;
    }
    do {
        ret = HksAddParams(*newParamSet, paramSet->params, paramSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("copy params fail");
            break;
        }
        struct HksParam storageLevel = {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        };
        ret = HksAddParams(*newParamSet, &storageLevel, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add param attestMode fail");
            break;
        }
        ret = HksBuildParamSet(newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("build paramSet fail");
            break;
        }
        return HKS_SUCCESS;
    } while (false);
    HksFreeParamSet(newParamSet);
    return ret;
}

int32_t HksGenerateKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksGenerateKey(keyAlias, newParamSet, paramSetOut);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksImportKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksImportKey(keyAlias, newParamSet, key);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksImportWrappedKeyForDe(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksImportWrappedKey(keyAlias, wrappingKeyAlias, newParamSet, wrappedKeyData);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksExportPublicKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksExportPublicKey(keyAlias, newParamSet, key);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksDeleteKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct or generate new paramSet fail");
        return ret;
    }
    ret = HksDeleteKey(keyAlias, newParamSet);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksGetKeyParamSetForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksGetKeyParamSet(keyAlias, newParamSet, paramSetOut);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksKeyExistForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksKeyExist(keyAlias, newParamSet);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksSignForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksSign(key, newParamSet, srcData, signature);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksVerifyForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksVerify(key, newParamSet, srcData, signature);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksEncryptForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksEncrypt(key, newParamSet, plainText, cipherText);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksDecryptForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksDecrypt(key, newParamSet, cipherText, plainText);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksAgreeKeyForDe(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksAgreeKey(newParamSet, privateKey, peerPublicKey, agreedKey);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksDeriveKeyForDe(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksDeriveKey(newParamSet, mainKey, derivedKey);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksMacForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksMac(key, newParamSet, srcData, mac);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksGetKeyInfoListForDe(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksGetKeyInfoList(newParamSet, keyInfoList, listCount);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksAttestKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksAttestKey(keyAlias, newParamSet, certChain);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksAnonAttestKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksAnonAttestKey(keyAlias, newParamSet, certChain);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksInitForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksInit(keyAlias, newParamSet, handle, token);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksUpdateForDe(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksUpdate(handle, newParamSet, inData, outData);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksFinishForDe(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    if (paramSet != NULL) {
        ret = ConstructNewParamSet(paramSet, &newParamSet);
    } else {
        struct HksParam tmpParams[] = {
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
        };
        ret = GenerateParamSet(&newParamSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet fail");
        return ret;
    }
    ret = HksFinish(handle, newParamSet, inData, outData);
    HksFreeParamSet(&newParamSet);
    return ret;
}
