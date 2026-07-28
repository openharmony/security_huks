/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_error_code.h"
#include "huks_hdi_wrapper.h"
#include <pthread.h>
#include <string.h>
#include "hks_log.h"
#include "hks_template.h"
#include "v1_1/ihuks.h"

static struct IHuks *gInstanceV1_1 = NULL;
static struct HuksHdiWrapper gWrapperV1_1;
static pthread_mutex_t gMutexV1_1 = PTHREAD_MUTEX_INITIALIZER;
static bool gInitialized = false;

static int32_t WrapperV1_1_ModuleInit(void)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ModuleInit == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ModuleInit(gInstanceV1_1);
}

static int32_t WrapperV1_1_ModuleDestroy(void)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ModuleDestroy == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ModuleDestroy(gInstanceV1_1);
}

static int32_t WrapperV1_1_GenerateKey(const struct HuksBlob *keyAlias, const struct HuksParamSet *paramSet,
    const struct HuksBlob *keyIn, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->GenerateKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->GenerateKey(gInstanceV1_1, keyAlias, paramSet, keyIn, keyOut);
}

static int32_t WrapperV1_1_ImportKey(const struct HuksBlob *keyAlias, const struct HuksBlob *key,
    const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ImportKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ImportKey(gInstanceV1_1, keyAlias, key, paramSet, keyOut);
}

static int32_t WrapperV1_1_ImportWrappedKey(const struct HuksBlob *wrappingKeyAlias, const struct HuksBlob *key,
    const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ImportWrappedKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ImportWrappedKey(gInstanceV1_1, wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

static int32_t WrapperV1_1_ExportPublicKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ExportPublicKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ExportPublicKey(gInstanceV1_1, key, paramSet, keyOut);
}

static int32_t WrapperV1_1_Init(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *handle, struct HuksBlob *token)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Init == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Init(gInstanceV1_1, key, paramSet, handle, token);
}

static int32_t WrapperV1_1_Update(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Update == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Update(gInstanceV1_1, handle, paramSet, inData, outData);
}

static int32_t WrapperV1_1_Finish(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Finish == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Finish(gInstanceV1_1, handle, paramSet, inData, outData);
}

static int32_t WrapperV1_1_Abort(const struct HuksBlob *handle, const struct HuksParamSet *paramSet)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Abort == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Abort(gInstanceV1_1, handle, paramSet);
}

static int32_t WrapperV1_1_CheckKeyValidity(const struct HuksParamSet *paramSet, const struct HuksBlob *key)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->CheckKeyValidity == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->CheckKeyValidity(gInstanceV1_1, paramSet, key);
}

static int32_t WrapperV1_1_AttestKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *certChain)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->AttestKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->AttestKey(gInstanceV1_1, key, paramSet, certChain);
}

static int32_t WrapperV1_1_GenerateRandom(const struct HuksParamSet *paramSet, struct HuksBlob *random)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->GenerateRandom == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->GenerateRandom(gInstanceV1_1, paramSet, random);
}

static int32_t WrapperV1_1_Sign(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *signature)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Sign == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Sign(gInstanceV1_1, key, paramSet, srcData, signature);
}

static int32_t WrapperV1_1_Verify(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, const struct HuksBlob *signature)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Verify == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Verify(gInstanceV1_1, key, paramSet, srcData, signature);
}

static int32_t WrapperV1_1_Encrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *plainText, struct HuksBlob *cipherText)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Encrypt == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Encrypt(gInstanceV1_1, key, paramSet, plainText, cipherText);
}

static int32_t WrapperV1_1_Decrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *cipherText, struct HuksBlob *plainText)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Decrypt == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Decrypt(gInstanceV1_1, key, paramSet, cipherText, plainText);
}

static int32_t WrapperV1_1_AgreeKey(const struct HuksParamSet *paramSet, const struct HuksBlob *privateKey,
    const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->AgreeKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->AgreeKey(gInstanceV1_1, paramSet, privateKey, peerPublicKey, agreedKey);
}

static int32_t WrapperV1_1_DeriveKey(const struct HuksParamSet *paramSet, const struct HuksBlob *kdfKey,
    struct HuksBlob *derivedKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->DeriveKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->DeriveKey(gInstanceV1_1, paramSet, kdfKey, derivedKey);
}

static int32_t WrapperV1_1_Mac(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *mac)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->Mac == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->Mac(gInstanceV1_1, key, paramSet, srcData, mac);
}

static int32_t WrapperV1_1_UpgradeKey(const struct HuksBlob *oldKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *newKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->UpgradeKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->UpgradeKey(gInstanceV1_1, oldKey, paramSet, newKey);
}

static int32_t WrapperV1_1_ExportChipsetPlatformPublicKey(const struct HuksBlob *salt,
    enum HuksChipsetPlatformDecryptScene scene, struct HuksBlob *publicKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->ExportChipsetPlatformPublicKey == NULL),
        HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->ExportChipsetPlatformPublicKey(gInstanceV1_1, salt, scene, publicKey);
}

static int32_t WrapperV1_1_GetErrorInfo(struct HuksBlob *errorInfo)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->GetErrorInfo == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->GetErrorInfo(gInstanceV1_1, errorInfo);
}

static int32_t WrapperV1_1_GetStatInfo(struct HuksBlob *statInfo)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->GetStatInfo == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->GetStatInfo(gInstanceV1_1, statInfo);
}

static int32_t WrapperV1_1_GetVersion(uint32_t *majorVer, uint32_t *minorVer)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_1 == NULL || gInstanceV1_1->GetVersion == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_1->GetVersion(gInstanceV1_1, majorVer, minorVer);
}

static void FillWrapperV1_1(void)
{
    gWrapperV1_1.hdiInstance = gInstanceV1_1;
    gWrapperV1_1.version = HUKS_HDI_VERSION_V1_1;

    gWrapperV1_1.ModuleInit = WrapperV1_1_ModuleInit;
    gWrapperV1_1.ModuleDestroy = WrapperV1_1_ModuleDestroy;
    gWrapperV1_1.GenerateKey = WrapperV1_1_GenerateKey;
    gWrapperV1_1.ImportKey = WrapperV1_1_ImportKey;
    gWrapperV1_1.ImportWrappedKey = WrapperV1_1_ImportWrappedKey;
    gWrapperV1_1.ExportPublicKey = WrapperV1_1_ExportPublicKey;
    gWrapperV1_1.Init = WrapperV1_1_Init;
    gWrapperV1_1.Update = WrapperV1_1_Update;
    gWrapperV1_1.Finish = WrapperV1_1_Finish;
    gWrapperV1_1.Abort = WrapperV1_1_Abort;
    gWrapperV1_1.CheckKeyValidity = WrapperV1_1_CheckKeyValidity;
    gWrapperV1_1.AttestKey = WrapperV1_1_AttestKey;
    gWrapperV1_1.GenerateRandom = WrapperV1_1_GenerateRandom;
    gWrapperV1_1.Sign = WrapperV1_1_Sign;
    gWrapperV1_1.Verify = WrapperV1_1_Verify;
    gWrapperV1_1.Encrypt = WrapperV1_1_Encrypt;
    gWrapperV1_1.Decrypt = WrapperV1_1_Decrypt;
    gWrapperV1_1.AgreeKey = WrapperV1_1_AgreeKey;
    gWrapperV1_1.DeriveKey = WrapperV1_1_DeriveKey;
    gWrapperV1_1.Mac = WrapperV1_1_Mac;
    gWrapperV1_1.UpgradeKey = WrapperV1_1_UpgradeKey;
    gWrapperV1_1.ExportChipsetPlatformPublicKey = WrapperV1_1_ExportChipsetPlatformPublicKey;
    gWrapperV1_1.GetErrorInfo = WrapperV1_1_GetErrorInfo;
    gWrapperV1_1.GetStatInfo = WrapperV1_1_GetStatInfo;
    gWrapperV1_1.GetVersion = WrapperV1_1_GetVersion;
    gWrapperV1_1.Encapsulate = NULL;
    gWrapperV1_1.Decapsulate = NULL;
}

int32_t HuksHdiWrapperV1_1_Init(void)
{
    if (gInitialized) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&gMutexV1_1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "v1_1 mutex lock failed");

    if (gInitialized) {
        pthread_mutex_unlock(&gMutexV1_1);
        return HKS_SUCCESS;
    }

    gInstanceV1_1 = IHuksGetInstance("hdi_service", true);
    if (gInstanceV1_1 == NULL) {
        HKS_LOG_E("IHuksGetInstance v1_1 failed");
        pthread_mutex_unlock(&gMutexV1_1);
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    if (gInstanceV1_1->GetVersion == NULL) {
        HKS_LOG_E("GetVersion funciton is null");
        IHuksReleaseInstance("hdi_service", gInstanceV1_1, true);
        gInstanceV1_1 = NULL;
        pthread_mutex_unlock(&gMutexV1_1);
        return HKS_ERROR_NULL_POINTER;
    }

    ret = gInstanceV1_1->GetVersion(gInstanceV1_1, &majorVer, &minorVer);
    if (ret != HKS_SUCCESS || majorVer != IHUKS_MAJOR_VERSION || minorVer != IHUKS_MINOR_VERSION) {
        HKS_LOG_E("version mismatch, got %" LOG_PUBLIC "u.%" LOG_PUBLIC "u, expected 1.1",
            majorVer, minorVer);
        IHuksReleaseInstance("hdi_service", gInstanceV1_1, true);
        gInstanceV1_1 = NULL;
        pthread_mutex_unlock(&gMutexV1_1);
        return HKS_ERROR_NULL_POINTER;
    }

    FillWrapperV1_1();
    gInitialized = true;

    pthread_mutex_unlock(&gMutexV1_1);
    return HKS_SUCCESS;
}

struct HuksHdiWrapper *HuksHdiWrapperV1_1_Get(void)
{
    if (!gInitialized) {
        int32_t ret = HuksHdiWrapperV1_1_Init();
        if (ret != HKS_SUCCESS) {
            return NULL;
        }
    }
    return &gWrapperV1_1;
}

int32_t HuksHdiWrapperV1_1_Destroy(void)
{
    if (!gInitialized) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&gMutexV1_1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "v1.1 mutex loc failed");

    if (!gInitialized) {
        pthread_mutex_unlock(&gMutexV1_1);
        return HKS_SUCCESS;
    }

    if (gInstanceV1_1 != NULL) {
        IHuksReleaseInstance("hdi_service", gInstanceV1_1, true);
        gInstanceV1_1 = NULL;
    }

    gInitialized = false;

    pthread_mutex_unlock(&gMutexV1_1);
    return HKS_SUCCESS;
}
