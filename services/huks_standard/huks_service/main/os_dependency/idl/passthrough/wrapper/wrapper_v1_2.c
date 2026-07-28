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
#include "v1_2/ihuks.h"

static struct IHuks *gInstanceV1_2 = NULL;
static struct HuksHdiWrapper gWrapperV1_2;
static pthread_mutex_t gMutexV1_2 = PTHREAD_MUTEX_INITIALIZER;
static bool gInitializedV1_2 = false;

static int32_t WrapperV1_2_ModuleInit(void)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ModuleInit == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ModuleInit(gInstanceV1_2);
}

static int32_t WrapperV1_2_ModuleDestroy(void)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ModuleDestroy == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ModuleDestroy(gInstanceV1_2);
}

static int32_t WrapperV1_2_GenerateKey(const struct HuksBlob *keyAlias, const struct HuksParamSet *paramSet,
    const struct HuksBlob *keyIn, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->GenerateKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->GenerateKey(gInstanceV1_2, keyAlias, paramSet, keyIn, keyOut);
}

static int32_t WrapperV1_2_ImportKey(const struct HuksBlob *keyAlias, const struct HuksBlob *key,
    const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ImportKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ImportKey(gInstanceV1_2, keyAlias, key, paramSet, keyOut);
}

static int32_t WrapperV1_2_ImportWrappedKey(const struct HuksBlob *wrappingKeyAlias, const struct HuksBlob *key,
    const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ImportWrappedKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ImportWrappedKey(gInstanceV1_2, wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

static int32_t WrapperV1_2_ExportPublicKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *keyOut)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ExportPublicKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ExportPublicKey(gInstanceV1_2, key, paramSet, keyOut);
}

static int32_t WrapperV1_2_Init(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *handle, struct HuksBlob *token)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Init == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Init(gInstanceV1_2, key, paramSet, handle, token);
}

static int32_t WrapperV1_2_Update(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Update == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Update(gInstanceV1_2, handle, paramSet, inData, outData);
}

static int32_t WrapperV1_2_Finish(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Finish == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Finish(gInstanceV1_2, handle, paramSet, inData, outData);
}

static int32_t WrapperV1_2_Abort(const struct HuksBlob *handle, const struct HuksParamSet *paramSet)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Abort == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Abort(gInstanceV1_2, handle, paramSet);
}

static int32_t WrapperV1_2_CheckKeyValidity(const struct HuksParamSet *paramSet, const struct HuksBlob *key)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->CheckKeyValidity == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->CheckKeyValidity(gInstanceV1_2, paramSet, key);
}

static int32_t WrapperV1_2_AttestKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *certChain)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->AttestKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->AttestKey(gInstanceV1_2, key, paramSet, certChain);
}

static int32_t WrapperV1_2_GenerateRandom(const struct HuksParamSet *paramSet, struct HuksBlob *random)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->GenerateRandom == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->GenerateRandom(gInstanceV1_2, paramSet, random);
}

static int32_t WrapperV1_2_Sign(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *signature)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Sign == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Sign(gInstanceV1_2, key, paramSet, srcData, signature);
}

static int32_t WrapperV1_2_Verify(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, const struct HuksBlob *signature)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Verify == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Verify(gInstanceV1_2, key, paramSet, srcData, signature);
}

static int32_t WrapperV1_2_Encrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *plainText, struct HuksBlob *cipherText)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Encrypt == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Encrypt(gInstanceV1_2, key, paramSet, plainText, cipherText);
}

static int32_t WrapperV1_2_Decrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *cipherText, struct HuksBlob *plainText)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Decrypt == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Decrypt(gInstanceV1_2, key, paramSet, cipherText, plainText);
}

static int32_t WrapperV1_2_AgreeKey(const struct HuksParamSet *paramSet, const struct HuksBlob *privateKey,
    const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->AgreeKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->AgreeKey(gInstanceV1_2, paramSet, privateKey, peerPublicKey, agreedKey);
}

static int32_t WrapperV1_2_DeriveKey(const struct HuksParamSet *paramSet, const struct HuksBlob *kdfKey,
    struct HuksBlob *derivedKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->DeriveKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->DeriveKey(gInstanceV1_2, paramSet, kdfKey, derivedKey);
}

static int32_t WrapperV1_2_Mac(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *mac)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Mac == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Mac(gInstanceV1_2, key, paramSet, srcData, mac);
}

static int32_t WrapperV1_2_UpgradeKey(const struct HuksBlob *oldKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *newKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->UpgradeKey == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->UpgradeKey(gInstanceV1_2, oldKey, paramSet, newKey);
}

static int32_t WrapperV1_2_ExportChipsetPlatformPublicKey(const struct HuksBlob *salt,
    enum HuksChipsetPlatformDecryptScene scene, struct HuksBlob *publicKey)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->ExportChipsetPlatformPublicKey == NULL),
        HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->ExportChipsetPlatformPublicKey(gInstanceV1_2, salt, scene, publicKey);
}

static int32_t WrapperV1_2_GetErrorInfo(struct HuksBlob *errorInfo)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->GetErrorInfo == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->GetErrorInfo(gInstanceV1_2, errorInfo);
}

static int32_t WrapperV1_2_GetStatInfo(struct HuksBlob *statInfo)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->GetStatInfo == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->GetStatInfo(gInstanceV1_2, statInfo);
}

static int32_t WrapperV1_2_GetVersion(uint32_t *majorVer, uint32_t *minorVer)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->GetVersion == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->GetVersion(gInstanceV1_2, majorVer, minorVer);
}

static int32_t WrapperV1_2_Encapsulate(const struct HuksParamSet *paramSet, const struct HuksParamSet *sharedKeyParam,
    struct HuksEncapsulationResult *encapResult)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Encapsulate == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Encapsulate(gInstanceV1_2, paramSet, sharedKeyParam, encapResult);
}

static int32_t WrapperV1_2_Decapsulate(const struct HuksParamSet *paramSet, const struct HuksParamSet *sharedKeyParam,
    const struct HuksBlob *encapsulatedData, struct HuksBlob *sharedSecret)
{
    HKS_IF_TRUE_RETURN((gInstanceV1_2 == NULL || gInstanceV1_2->Decapsulate == NULL), HKS_ERROR_NULL_POINTER)
    return gInstanceV1_2->Decapsulate(gInstanceV1_2, paramSet, sharedKeyParam, encapsulatedData, sharedSecret);
}

static void FillWrapperV1_2(void)
{
    gWrapperV1_2.hdiInstance = gInstanceV1_2;
    gWrapperV1_2.version = HUKS_HDI_VERSION_V1_2;

    gWrapperV1_2.ModuleInit = WrapperV1_2_ModuleInit;
    gWrapperV1_2.ModuleDestroy = WrapperV1_2_ModuleDestroy;
    gWrapperV1_2.GenerateKey = WrapperV1_2_GenerateKey;
    gWrapperV1_2.ImportKey = WrapperV1_2_ImportKey;
    gWrapperV1_2.ImportWrappedKey = WrapperV1_2_ImportWrappedKey;
    gWrapperV1_2.ExportPublicKey = WrapperV1_2_ExportPublicKey;
    gWrapperV1_2.Init = WrapperV1_2_Init;
    gWrapperV1_2.Update = WrapperV1_2_Update;
    gWrapperV1_2.Finish = WrapperV1_2_Finish;
    gWrapperV1_2.Abort = WrapperV1_2_Abort;
    gWrapperV1_2.CheckKeyValidity = WrapperV1_2_CheckKeyValidity;
    gWrapperV1_2.AttestKey = WrapperV1_2_AttestKey;
    gWrapperV1_2.GenerateRandom = WrapperV1_2_GenerateRandom;
    gWrapperV1_2.Sign = WrapperV1_2_Sign;
    gWrapperV1_2.Verify = WrapperV1_2_Verify;
    gWrapperV1_2.Encrypt = WrapperV1_2_Encrypt;
    gWrapperV1_2.Decrypt = WrapperV1_2_Decrypt;
    gWrapperV1_2.AgreeKey = WrapperV1_2_AgreeKey;
    gWrapperV1_2.DeriveKey = WrapperV1_2_DeriveKey;
    gWrapperV1_2.Mac = WrapperV1_2_Mac;
    gWrapperV1_2.UpgradeKey = WrapperV1_2_UpgradeKey;
    gWrapperV1_2.ExportChipsetPlatformPublicKey = WrapperV1_2_ExportChipsetPlatformPublicKey;
    gWrapperV1_2.GetErrorInfo = WrapperV1_2_GetErrorInfo;
    gWrapperV1_2.GetStatInfo = WrapperV1_2_GetStatInfo;
    gWrapperV1_2.GetVersion = WrapperV1_2_GetVersion;

    gWrapperV1_2.Encapsulate = WrapperV1_2_Encapsulate;
    gWrapperV1_2.Decapsulate = WrapperV1_2_Decapsulate;
}

int32_t HuksHdiWrapperV1_2_Init(void)
{
    if (gInitializedV1_2) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&gMutexV1_2);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "v1_2 mutex lock failed");

    if (gInitializedV1_2) {
        pthread_mutex_unlock(&gMutexV1_2);
        return HKS_SUCCESS;
    }

    gInstanceV1_2 = IHuksGetInstance("hdi_service", true);
    if (gInstanceV1_2 == NULL) {
        HKS_LOG_E("IHuksGetInstance v1_2 failed");
        pthread_mutex_unlock(&gMutexV1_2);
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    if (gInstanceV1_2->GetVersionV1_1 == NULL) {
        HKS_LOG_E("GetVersion function is null");
        IHuksReleaseInstance("hdi_service", gInstanceV1_2, true);
        gInstanceV1_2 = NULL;
        pthread_mutex_unlock(&gMutexV1_2);
        return HKS_ERROR_NULL_POINTER;
    }

    ret = gInstanceV1_2->GetVersionV1_1(gInstanceV1_2, &majorVer, &minorVer);
    if (ret != HKS_SUCCESS || majorVer != IHUKS_MAJOR_VERSION || minorVer != IHUKS_MINOR_VERSION) {
        HKS_LOG_E("version mismatch, got %" LOG_PUBLIC "u.%" LOG_PUBLIC "u, expected 1.2",
            majorVer, minorVer);
        IHuksReleaseInstance("hdi_service", gInstanceV1_2, true);
        gInstanceV1_2 = NULL;
        pthread_mutex_unlock(&gMutexV1_2);
        return HKS_ERROR_NULL_POINTER;
    }

    FillWrapperV1_2();
    gInitializedV1_2 = true;

    pthread_mutex_unlock(&gMutexV1_2);
    return HKS_SUCCESS;
}

struct HuksHdiWrapper *HuksHdiWrapperV1_2_Get(void)
{
    if (!gInitializedV1_2) {
        int32_t ret = HuksHdiWrapperV1_2_Init();
        if (ret != HKS_SUCCESS) {
            return NULL;
        }
    }
    return &gWrapperV1_2;
}

int32_t HuksHdiWrapperV1_2_Destroy(void)
{
    if (!gInitializedV1_2) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&gMutexV1_2);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "v1.2 mutex lock failed");

    if (!gInitializedV1_2) {
        pthread_mutex_unlock(&gMutexV1_2);
        return HKS_SUCCESS;
    }

    if (gInstanceV1_2 != NULL) {
        IHuksReleaseInstance("hdi_service", gInstanceV1_2, true);
        gInstanceV1_2 = NULL;
    }

    gInitializedV1_2 = false;

    pthread_mutex_unlock(&gMutexV1_2);
    return HKS_SUCCESS;
}
