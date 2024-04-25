/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

/**
 * @file hks_api.h
 *
 * @brief Declares huks operation inner interface.
 *
 * @since 8
 */

#ifndef HKS_API_H
#define HKS_API_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get HUKS sdk version
 * @param sdkVersion sdk version
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGetSdkVersion(struct HksBlob *sdkVersion);

/**
 * @brief HUKS initialize
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksInitialize(void);

/**
 * @brief HUKS initialize fresh key info
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksRefreshKeyInfo(void);

/**
 * @brief Generate key
 * @param keyAlias key alias
 * @param paramSetIn required parameter set
 * @param paramSetOut output parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut);

/**
 * @brief Import key
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param key the key needs to be imported
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksImportKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key);

/**
 * @brief Import wrapped key
 * @param keyAlias key alias
 * @param wrappingKeyAlias alias used to decrypt the key data after the wrap
 * @param paramSet required parameter set
 * @param wrappedKeyData wrapped key data out
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);

/**
 * @brief Export public key
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param key exported key
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksExportPublicKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key);

/**
 * @brief Delete key
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

/**
 * @brief Get key parameter set
 * @param keyAlias key alias
 * @param paramSetIn required parameter set
 * @param paramSetOut output parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGetKeyParamSet(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut);

/**
 * @brief Check whether the key exists
 * @param keyAlias key alias
 * @param paramSetIn required parameter set
 * @param paramSetOut output parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

/**
 * @brief Generate random
 * @param paramSet required parameter set
 * @param random output random
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random);

/**
 * @brief Sign operation
 * @param key required key to sign data
 * @param paramSet required parameter set
 * @param srcData the data needs to sign
 * @param signature signatured data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature);

/**
 * @brief Verify operation
 * @param key required key to verify data
 * @param paramSet required parameter set
 * @param srcData the data needs to verify
 * @param signature verified data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature);

/**
 * @brief Encrypt operation
 * @param key required key to encrypt data
 * @param paramSet required parameter set
 * @param plainText the data needs to encrypt
 * @param cipherText encrypted data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText);

/**
 * @brief Decrypt operation
 * @param key required key to decrypt data
 * @param paramSet required parameter set
 * @param cipherText the data needs to decrypt
 * @param plainText decrypted data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText);

/**
 * @brief Agree key
 * @param paramSet required parameter set
 * @param privateKey self private key
 * @param peerPublicKey peer public key
 * @param agreedKey agreed key
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

/**
 * @brief Derive key
 * @param paramSet required parameter set
 * @param mainKey main key to derive key
 * @param derivedKey derived key
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey);

/**
 * @brief Mac operation
 * @param key main key to derive key
 * @param paramSet required parameter set
 * @param srcData data needs to mac
 * @param mac mac value
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac);

/**
 * @brief Hash operation
 * @param paramSet required parameter set
 * @param srcData data needs to hash
 * @param mac hash value
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksHash(const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *hash);

/**
 * @brief Get key info list
 * @param paramSet required parameter set
 * @param keyInfoList key info list
 * @param listCount list count
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGetKeyInfoList(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount);

/**
 * @brief Attest key
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param certChain cert chain
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

/**
 * @brief Anonymous Attest key
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param certChain cert chain
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksAnonAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

/**
 * @brief Get certificate chain
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param certChain cert chain
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksGetCertificateChain(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

/**
 * @brief Wrap key operation
 * @param keyAlias key alias
 * @param targetKeyAlias target key alias
 * @param paramSet required parameter set
 * @param wrappedData wrapped data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksWrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedData);

/**
 * @brief Unwrap key operation
 * @param keyAlias key alias
 * @param targetKeyAlias target key alias
 * @param wrappedData wrapped data
 * @param paramSet required parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksBlob *wrappedData, const struct HksParamSet *paramSet);

/**
 * @brief Big-numble exponent mod x = a^e mod n
 * @param x result
 * @param a base
 * @param e exponent
 * @param n modulus
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n);

/**
 * @brief Check whether the device key exists
 * @param paramSet required parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HcmIsDeviceKeyExist(const struct HksParamSet *paramSet);

/**
 * @brief Validate certificate chain
 * @param certChain certificate chain needs to validate
 * @param paramSetOut parameter set out
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksValidateCertChain(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut);

/**
 * @brief Init operation
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param handle operation handle
 * @param token token
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token);

/**
 * @brief Update operation
 * @param handle operation handle
 * @param paramSet required parameter set
 * @param inData the data to update
 * @param outData output data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

/**
 * @brief Finish operation
 * @param handle operation handle
 * @param paramSet required parameter set
 * @param inData the data to update
 * @param outData output data
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

/**
 * @brief Abort operation
 * @param handle operation handle
 * @param paramSet required parameter set
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);

/**
 * @brief Export chipset platform publicKey
 * @param salt salt value
 * @param scene scene
 * @param publicKey public key
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey);

/**
 * @brief Get key alias list
 * @param paramSet required parameter set
 * @param outData key alias list
 * @return error code, see hks_type.h
 */
HKS_API_EXPORT int32_t HksListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData);

#ifdef __cplusplus
}
#endif

#endif /* HKS_API_H */
