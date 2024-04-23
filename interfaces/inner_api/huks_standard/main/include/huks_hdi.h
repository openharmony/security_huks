/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @file hks_hdi.h
 *
 * @brief Declares hdi interface
 *
 * @since 8
 */

#ifndef HUKS_HDI_H
#define HUKS_HDI_H

#include "hks_param.h"
#include "hks_type.h"

#define HDI_ADAPTER_PARAM(oldParamPtr, newParamPtr) ((oldParamPtr) == NULL ?  NULL : (newParamPtr))

#define HDI_CONVERTER_PARAM_IN_BLOB(fromHksBlobPtr, toHuksBlob) \
    if ((fromHksBlobPtr) != NULL) {     \
        (toHuksBlob).data = (fromHksBlobPtr)->data;            \
        (toHuksBlob).dataLen = (fromHksBlobPtr)->size;         \
    }

#define HDI_CONVERTER_PARAM_IN_PARAMSET(fromHksParamSetPtr, toHuksParamSet)               \
    if ((fromHksParamSetPtr) != NULL && (fromHksParamSetPtr)->paramSetSize >= sizeof(struct HksParamSet)) {  \
        (toHuksParamSet).data = (uint8_t *)(fromHksParamSetPtr);                         \
        (toHuksParamSet).dataLen = (fromHksParamSetPtr)->paramSetSize;                   \
    }

#define HDI_CONVERTER_PARAM_OUT_BLOB(fromHuksBlob, toHksBlobPtr)  \
    if ((toHksBlobPtr) != NULL) {       \
        (toHksBlobPtr)->data = (fromHuksBlob).data;              \
        (toHksBlobPtr)->size = (fromHuksBlob).dataLen;           \
    }


#define HDI_CONVERTER_FUNC_GENERATEKEY(keyAlias, paramSet, keyIn, keyOut, ret, func) \
    struct HuksBlob keyAliasCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob keyInCore = {0};  \
    struct HuksBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyAlias, keyAliasCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyIn, keyInCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(keyAlias, &keyAliasCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyIn, &keyInCore),        \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_IMPORTKEY(keyAlias, key, paramSet, keyOut, ret, func) \
    struct HuksBlob keyAliasCore = {0};   \
    struct HuksParamSet paramSetCore = {0};   \
    struct HuksBlob keyCore = {0};   \
    struct HuksBlob keyOutCore = {0};   \
    HDI_CONVERTER_PARAM_IN_BLOB(keyAlias, keyAliasCore)   \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)   \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)   \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, keyOutCore)   \
    ret = (func)(HDI_ADAPTER_PARAM(keyAlias, &keyAliasCore), \
                 HDI_ADAPTER_PARAM(key, &keyCore),   \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore), \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));   \
    HDI_CONVERTER_PARAM_OUT_BLOB(keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_IMPORTWRAPPEDKEY(wrappedKeyAlias, key, wrappedKeyData, paramSet, keyOut, ret, func)   \
    struct HuksBlob wrappingKeyAliasCore = {0};  \
    struct HuksBlob keyCore = {0};  \
    struct HuksBlob wrappedKeyDataCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(wrappingKeyAlias, wrappingKeyAliasCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(wrappedKeyData, wrappedKeyDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(wrappingKeyAlias, &wrappedKeyDataCore),  \
                 HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(wrappedKeyData, &wrappedKeyDataCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_EXPORTPUBLICKEY(key, paramSet, keyOut, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_INIT(key, paramSet, handle, token, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob handleCore = {0};  \
    struct HuksBlob tokenCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, handleCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(token, tokenCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(token, &tokenCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(handleCore, handle)  \
    HDI_CONVERTER_PARAM_OUT_BLOB(tokenCore, token)

#define HDI_CONVERTER_FUNC_UPDATE(handle, paramSet, inData, outData, ret, func)  \
    struct HuksBlob handleCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob inDataCore = {0};  \
    struct HuksBlob outDataCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(inData, inDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(outData, outDataCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(inData, &inDataCore),  \
                 HDI_ADAPTER_PARAM(outData, &outDataCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(outDataCore, outData)

#define HDI_CONVERTER_FUNC_FINISH(handle, paramSet, inData, outData, ret, func)  \
    struct HuksBlob handleCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob inDataCore = {0};  \
    struct HuksBlob outDataCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(inData, inDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(outData, outDataCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(inData, &inDataCore),  \
                 HDI_ADAPTER_PARAM(outData, &outDataCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(outDataCore, outData)

#define HDI_CONVERTER_FUNC_ABORT(handle, paramSet, ret, func)  \
    struct HuksBlob handleCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore));

#define HDI_CONVERTER_FUNC_CHECKKEYVALIDITY(paramSet, key, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(key, &keyCore));

#define HDI_CONVERTER_FUNC_ATTESTKEY(key, paramSet, certChain, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob certChainCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(certChain, certChainCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(certChain, &certChainCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(certChainCore, certChain)

#define HDI_CONVERTER_FUNC_GENERATERANDOM(paramSet, random, ret, func)  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob randomCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(random, randomCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(random, &randomCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(randomCore, random)

#define HDI_CONVERTER_FUNC_SIGN(key, paramSet, srcData, signature, ret, func) \
    struct HuksBlob keyCore = {0}; \
    struct HuksParamSet paramSetCore = {0}; \
    struct HuksBlob srcDataCore = {0}; \
    struct HuksBlob signatureCore = {0}; \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore) \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore) \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, srcDataCore) \
    HDI_CONVERTER_PARAM_IN_BLOB(signature, signatureCore) \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore), \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore), \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore), \
                 HDI_ADAPTER_PARAM(signature, &signatureCore)); \
    HDI_CONVERTER_PARAM_OUT_BLOB(signatureCore, signature)

#define HDI_CONVERTER_FUNC_VERIFY(key, paramSet, srcData, signature, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob srcDataCore = {0};  \
    struct HuksBlob signatureCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, srcDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(signature, signatureCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore),  \
                 HDI_ADAPTER_PARAM(signature, &signatureCore));

#define HDI_CONVERTER_FUNC_ENCRYPT(key, paramSet, plainText, cipherText, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob plainTextCore = {0};  \
    struct HuksBlob cipherTextCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(plainText, plainTextCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(cipherText, cipherTextCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(plainText, &plainTextCore),  \
                 HDI_ADAPTER_PARAM(cipherText, &cipherTextCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(cipherTextCore, cipherText)

#define HDI_CONVERTER_FUNC_DECRYPT(key, paramSet, cipherText, plainText, ret, func)  \
    struct HuksBlob keyCore = {0};  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob cipherTextCore = {0};  \
    struct HuksBlob plainTextCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(cipherText, cipherTextCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(plainText, plainTextCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(cipherText, &cipherTextCore),  \
                 HDI_ADAPTER_PARAM(plainText, &plainTextCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(plainTextCore, plainText)

#define HDI_CONVERTER_FUNC_AGREEKEY(paramSet, privateKey, peerPublicKey, agreedKey, ret, func)  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob privateKeyCore = {0};  \
    struct HuksBlob peerPublicKeyCore = {0};  \
    struct HuksBlob agreedKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(privateKey, privateKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(peerPublicKey, peerPublicKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(agreedKey, agreedKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(privateKey, &privateKeyCore),  \
                 HDI_ADAPTER_PARAM(peerPublicKey, &peerPublicKeyCore),  \
                 HDI_ADAPTER_PARAM(agreedKey, &agreedKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(agreedKeyCore, agreedKey)


#define HDI_CONVERTER_FUNC_DERIVEKEY(paramSet, kdfKey, derivedKey, ret, func)  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob kdfKeyCore = {0};  \
    struct HuksBlob derivedKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(kdfKey, kdfKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(derivedKey, derivedKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, &paramSetCore), \
                 HDI_ADAPTER_PARAM(kdfKey, &kdfKeyCore),  \
                 HDI_ADAPTER_PARAM(derivedKey, &derivedKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(derivedKeyCore, derivedKey)

#define HDI_CONVERTER_FUNC_MAC(key, paramSet, srcData, mac, ret, func)  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob keyCore = {0};  \
    struct HuksBlob srcDataCore = {0};  \
    struct HuksBlob macCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, srcDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(mac, macCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore),  \
                 HDI_ADAPTER_PARAM(mac, &macCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(macCore, mac)

#define HDI_CONVERTER_FUNC_UPGRADEKEY(oldKey, paramSet, newKey, ret, func)  \
    struct HuksParamSet paramSetCore = {0};  \
    struct HuksBlob oldKeyCore = {0};  \
    struct HuksBlob newKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(oldKey, oldKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(newKey, newKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(oldKey, &oldKeyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, &paramSetCore),  \
                 HDI_ADAPTER_PARAM(newKey, &newKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(newKeyCore, newKey)

#define HDI_CONVERTER_FUNC_EXPORTCHIPSETPLATFORMPUBLICKEY(salt, scene, publicKey, ret, func)  \
    struct HuksBlob saltCore = {0};  \
    struct HuksBlob publicKeyCore = {0};  \
    uint32_t sceneInt = (uint32_t) scene;  \
    HDI_CONVERTER_PARAM_IN_BLOB(salt, saltCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(publicKey, publicKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(salt, &saltCore),  \
              sceneInt,  \
              HDI_ADAPTER_PARAM(publicKey, &publicKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(publicKeyCore, publicKey)

struct HuksHdi {
    /**
     * @brief HUKS initialize
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiModuleInit)(void);

    /**
     * @brief HUKS destroy
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiModuleDestroy)(void);

    /**
     * @brief HUKS fresh key info
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiRefresh)(void);

    /**
     * @brief Generate key
     * @param keyAlias key alias
     * @param paramSet required parameter set
     * @param keyIn key to generate key
     * @param keyOut output key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiGenerateKey)(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
        const struct HksBlob *keyIn, struct HksBlob *keyOut);

    /**
     * @brief Import key
     * @param keyAlias key alias
     * @param key the key needs to be imported
     * @param paramSet required parameter set
     * @param keyOut output key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiImportKey)(const struct HksBlob *keyAlias, const struct HksBlob *key,
        const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    /**
     * @brief Import wrapped key
     * @param wrappingKeyAlias alias used to decrypt the key data after the wrap
     * @param key the key to wrap key
     * @param wrappedKeyData wrapped key data out
     * @param paramSet required parameter set
     * @param keyOut output key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiImportWrappedKey)(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
        const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    /**
     * @brief Export public key
     * @param key key need to export
     * @param paramSet required parameter set
     * @param keyOut exported key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiExportPublicKey)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        struct HksBlob *keyOut);

    /**
     * @brief Init operation
     * @param key the key
     * @param paramSet required parameter set
     * @param handle operation handle
     * @param token token
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiInit)(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle,
        struct HksBlob *token);

    /**
     * @brief Update operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @param inData the data to update
     * @param outData output data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiUpdate)(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);

    /**
     * @brief Finish operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @param inData the data to update
     * @param outData output data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiFinish)(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);

    /**
     * @brief Finish operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiAbort)(const struct HksBlob *handle, const struct HksParamSet *paramSet);

    /**
     * @brief Get key properties
     * @param paramSet required parameter set
     * @param key the key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiGetKeyProperties)(const struct HksParamSet *paramSet, const struct HksBlob *key);

    /**
     * @brief Attest key
     * @param key the key
     * @param paramSet required parameter set
     * @param certChain cert chain
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiAttestKey)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        struct HksBlob *certChain);

    /**
     * @brief Get ability
     * @param funcType the function type
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiGetAbility)(int32_t funcType);

    /**
     * @brief Get hardware info
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiGetHardwareInfo)(void);

    /**
     * @brief Calculate mac header
     * @param paramSet required parameter set
     * @param salt the salt value
     * @param srcData the data to calculte
     * @param mac output mac value
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiCalcMacHeader)(const struct HksParamSet *paramSet, const struct HksBlob *salt,
        const struct HksBlob *srcData, struct HksBlob *mac);

    /**
     * @brief Upgrade key info
     * @param keyAlias key alias
     * @param keyInfo key info
     * @param keyOut output key value
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiUpgradeKeyInfo)(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo,
        struct HksBlob *keyOut);

    /**
     * @brief Generate random
     * @param paramSet required parameter set
     * @param random output random
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiGenerateRandom)(const struct HksParamSet *paramSet, struct HksBlob *random);

    /**
     * @brief Sign operation
     * @param key required key to sign data
     * @param paramSet required parameter set
     * @param srcData the data needs to sign
     * @param signature signatured data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiSign)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *signature);

    /**
     * @brief Verify operation
     * @param key required key to verify data
     * @param paramSet required parameter set
     * @param srcData the data needs to verify
     * @param signature verified data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiVerify)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, const struct HksBlob *signature);

    /**
     * @brief Encrypt operation
     * @param key required key to encrypt data
     * @param paramSet required parameter set
     * @param plainText the data needs to encrypt
     * @param cipherText encrypted data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiEncrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText);

    /**
     * @brief Decrypt operation
     * @param key required key to decrypt data
     * @param paramSet required parameter set
     * @param cipherText the data needs to decrypt
     * @param plainText decrypted data
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiDecrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *cipherText, struct HksBlob *plainText);

    /**
     * @brief Agree key
     * @param paramSet required parameter set
     * @param privateKey self private key
     * @param peerPublicKey peer public key
     * @param agreedKey agreed key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiAgreeKey)(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
        const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

    /**
     * @brief Derive key
     * @param paramSet required parameter set
     * @param kdfKey main key to derive key
     * @param derivedKey derived key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiDeriveKey)(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
        struct HksBlob *derivedKey);

    /**
     * @brief Mac operation
     * @param key main key to derive key
     * @param paramSet required parameter set
     * @param srcData data needs to mac
     * @param mac mac value
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiMac)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *mac);

    /**
     * @brief Upgrade key
     * @param oldKey old key to be upgraded
     * @param paramSet required parameter set
     * @param newKey new key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiUpgradeKey)(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
        struct HksBlob *newKey);

    /**
     * @brief Export chipset platform publicKey
     * @param salt salt value
     * @param scene scene
     * @param publicKey public key
     * @return error code, see hks_type.h
     */
    int32_t (*HuksHdiExportChipsetPlatformPublicKey)(const struct HksBlob *salt,
        enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey);
};

#endif /* HUKS_HDI_H */
