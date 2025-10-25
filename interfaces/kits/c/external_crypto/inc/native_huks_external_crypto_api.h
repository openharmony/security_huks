
/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
 * @addtogroup HuksExternalCryptoApi
 * @{
 *
 * @brief Describes the OpenHarmony Universal KeyStore (HUKS) capabilities specifical for external crypto extensions,
 * including provider management and ukey pin management and other operations, provided for applications.
 *
 * @since 22
 */

/**
 * @file native_huks_external_crypto_api.h
 *
 * @brief Defines the Universal Keystore Kit APIs special for external crypto extension.
 *
 * @library libhuks_external_crypto.z.so
 * @syscap SystemCapability.Security.Huks.CryptoExtension
 *
 * include "huks/include/native_huks_external_crypto_type.h"
 * @kit UniversalKeystoreKit
 * @since 22
 */

#ifndef NATIVE_HUKS_EXTERNAL_CRYPTO_API_H
#define NATIVE_HUKS_EXTERNAL_CRYPTO_API_H

#include "native_huks_external_crypto_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register external key provider.
 *
 * @permission ohos.permission.CRYPTO_EXTENSION_REGISTER
 * @param providerName Indicates the name of the provider.
 * @param paramSet Indicates the pointer to the register parameters.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_PERMISSION_FAIL} 201 - - If the permission check failed,
 *             please apply for the required permissions first.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT} 12000002 - If failed to
 *         get provider argument.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If providerName or paramSet is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ITEM_NOT_EXIST} 12000019 - If the provider is already registered.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If an error occured in
 *     the dependent module.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_RegisterProvider(
    const struct OH_Huks_Blob *providerName, const OH_Huks_ExternalCryptoParamSet *paramSet);

/**
 * @brief Unregister external key provider.
 *
 * @permission ohos.permission.CRYPTO_EXTENSION_REGISTER
 * @param providerName Indicates the name of the provider.
 * @param paramSet Indicates the pointer to the register parameters.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_PERMISSION_FAIL} 201 - - If the permission check failed,
 *             please apply for the required permissions first.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#HUKS_ERR_CODE_ITEM_NOT_EXIST} 12000011 - If the provider not found.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If providerName is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If an error occured in
 *     the dependent module.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_UnregisterProvider(
    const struct OH_Huks_Blob *providerName, const OH_Huks_ExternalCryptoParamSet *paramSet);

/**
 * @brief Open resource by specific resource id.
 * NOTE: the opened resource must be closed by OH_Huks_CloseResource.
 *
 * @param resourceId Indicates the resource id of the provider.
 * @param paramSet Indicates the pointer to the handle operation parameters.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_CRYPTO_FAIL} 12000006 - If the external crypto engine failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If index or paramSet
 *     or resourceId is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If the provider exec failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_MISMATCH} 12000021 - If the new remote handle is not same with the
 *     previous cached handle.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_OpenResource(
    const struct OH_Huks_Blob *resourceId, const OH_Huks_ExternalCryptoParamSet *paramSet);

/**
 * @brief Close the resource by specific resource id.
 *
 * @param resourceId Indicates the resource id of the provider.
 * @param paramSet Indicates the pointer to the handle operation parameters.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_CRYPTO_FAIL} 12000006 - If the external crypto engine failed.
 *         {@link OH_Huks_ErrCode#HUKS_ERR_CODE_ITEM_NOT_EXIST} 12000011 - If not found the cached handle
 *     specified by index.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If index or paramSet is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If the provider exec failed.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_CloseResource(
    const struct OH_Huks_Blob *resourceId, const OH_Huks_ExternalCryptoParamSet *paramSet);

/**
 * @brief Get the pin auth state of the specified ukey resource id.
 *
 * @param resourceId Indicates the resource id of the provider.
 * @param paramSet Indicates the pointer to the pin auth parameters.
 * @param authState Indicates the auth state of the specified index.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#HUKS_ERR_CODE_ITEM_NOT_EXIST} 12000011 - If not found the cached handle
 *     specified by index.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If index or paramSet
 *     or authState is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If the provider exec failed.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_GetUkeyPinAuthState(
    const struct OH_Huks_Blob *resourceId, const OH_Huks_ExternalCryptoParamSet *paramSet, bool *authState);

/**
 * @brief The general get operations of the external provider.
 *
 * @param resourceId Indicates the resource id of the provider.
 * @param propertyId Indicates the name of the property function to operate defined in GMT 0016-2023.
 * @param paramSetIn Indicates the pointer to the input operation parameters.
 * @param paramSetOut Indicates the pointer to the output parameters and must contained the param
 * OH_HUKS_EXT_CRYPTO_TAG_EXTRA_DATA.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_NOT_SUPPORTED_API} 801 - api is not supported
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_COMMUNICATION_FAIL} 12000005 - If Ipc commuication failed.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_CRYPTO_FAIL} 12000006 - If the external crypto engine failed.
 *         {@link OH_Huks_ErrCode#HUKS_ERR_CODE_ITEM_NOT_EXIST} 12000011 - If not found the cached handle
 *     specified by index.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 12000018 - If the index or propertyId or paramSet
 *     or callback is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_EXTERNAL_ERROR} 12000020 - If the provider exec failed.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_GetProperty(const struct OH_Huks_Blob *resourceId,
    const struct OH_Huks_Blob *propertyId, const OH_Huks_ExternalCryptoParamSet *paramSetIn,
    OH_Huks_ExternalCryptoParamSet **paramSetOut);

/**
 * @brief Initializes a parameter set.
 *
 * @param paramSet Indicates the double pointer to the parameter set to initialize.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the initialization is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 401 - If the paramset is null.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_InitExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet);

/**
 * @brief Adds parameters to a parameter set.
 *
 * @param paramSet Indicates the pointer to the parameter set to which parameters are to be added.
 * @param params Indicates the pointer to the array of parameters to add.
 * @param paramCnt Indicates the number of parameters to add.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 401 - If params is null or paramSet is invalid.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_AddExternalCryptoParams(OH_Huks_ExternalCryptoParamSet *paramSet,
    const OH_Huks_ExternalCryptoParam *params, uint32_t paramCnt);

/**
 * @brief Constructs a parameter set.
 *
 * @param paramSet Indicates the double pointer to the parameter set to construct.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 401 - If paramSet is invalid.
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_INSUFFICIENT_MEMORY} 12000014 - If the memory is insufficient.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_BuildExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet);

/**
 * @brief Destroys a parameter set.
 *
 * @param paramSet Indicates the double pointer to the parameter set to destroy.
 * @since 22
 */
void OH_Huks_FreeExternalCryptoParamSet(OH_Huks_ExternalCryptoParamSet **paramSet);

/**
 * @brief Obtains parameters from a parameter set.
 *
 * @param paramSet Indicates the pointer to the target parameter set.
 * @param tag Indicates the value of the parameter to be obtained.
 * @param param Indicates the double pointer to the parameter obtained.
 * @return {@link OH_Huks_ErrCode#OH_HUKS_SUCCESS} 0 - If the operation is successful,
 *         {@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT} 401 - If paramSet or param is invalid,
 *             or if the param doesn't exist in the pararmset.
 * @since 22
 */
struct OH_Huks_Result OH_Huks_GetExternalCryptoParam(OH_Huks_ExternalCryptoParamSet *paramSet,
    const uint32_t tag, OH_Huks_ExternalCryptoParam **param);
#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HUKS_EXTERNAL_CRYPTO_API_H */