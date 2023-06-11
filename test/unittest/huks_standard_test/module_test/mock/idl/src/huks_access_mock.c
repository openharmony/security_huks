/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "huks_access.h"

#include "hks_cfi.h"
#include "hks_core_service.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#ifndef _CUT_AUTHENTICATE_
ENABLE_CFI(int32_t HuksAccessModuleInit(void))
{
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksAccessModuleDestroy(void))
{
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksAccessRefresh(void))
{
    return HksCoreRefresh();
}

ENABLE_CFI(int32_t HuksAccessGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut))
{
    return HksCoreGenerateKey(keyAlias, paramSetIn, keyIn, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    return HksCoreImportKey(keyAlias, key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    return HksCoreImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut))
{
    return HksCoreExportPublicKey(key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token))
{
    return HksCoreInit(key, paramSet, handle, token);
}

ENABLE_CFI(int32_t HuksAccessUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    return HksCoreUpdate(handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    return HksCoreFinish(handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet))
{
    return HksCoreAbort(handle, paramSet);
}

ENABLE_CFI(int32_t HuksAccessGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key))
{
    return HksCoreGetKeyProperties(paramSet, key);
}

ENABLE_CFI(int32_t HuksAccessGetAbility(int funcType))
{
    return HksCoreGetAbility(funcType);
}

ENABLE_CFI(int32_t HuksAccessGetHardwareInfo(void))
{
    return HksCoreGetHardwareInfo();
}

ENABLE_CFI(int32_t HuksAccessSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature))
{
    return HksCoreSign(key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature))
{
    return HksCoreVerify(key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText))
{
    return HksCoreEncrypt(key, paramSet, plainText, cipherText);
}

ENABLE_CFI(int32_t HuksAccessDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText))
{
    return HksCoreDecrypt(key, paramSet, cipherText, plainText);
}

ENABLE_CFI(int32_t HuksAccessAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey))
{
    return HksCoreAgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
}

ENABLE_CFI(int32_t HuksAccessDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey))
{
    return HksCoreDeriveKey(paramSet, kdfKey, derivedKey);
}

ENABLE_CFI(int32_t HuksAccessMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    return HksCoreMac(key, paramSet, srcData, mac);
}

#ifdef HKS_ENABLE_UPGRADE_KEY
ENABLE_CFI(int32_t HuksAccessUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey))
{
    return HksCoreUpgradeKey(oldKey, paramSet, newKey);
}
#endif

#ifdef _STORAGE_LITE_
ENABLE_CFI(int32_t HuksAccessCalcHeaderMac(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    return HksCoreCalcMacHeader(paramSet, salt, srcData, mac);
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
ENABLE_CFI(int32_t HuksAccessAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain))
{
    return HksCoreAttestKey(key, paramSet, certChain);
}
#endif

#endif /* _CUT_AUTHENTICATE_ */

ENABLE_CFI(int32_t HuksAccessGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random))
{
    return HksCoreGenerateRandom(paramSet, random);
}

#ifdef HKS_SUPPORT_CHIPSET_PLATFORM_DECRYPT
ENABLE_CFI(int32_t HuksAccessExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey))
{
    return HksCoreExportChipsetPlatformPublicKey(salt, scene, publicKey);
}
#endif
