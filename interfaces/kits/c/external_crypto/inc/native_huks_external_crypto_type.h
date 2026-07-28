
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 * @addtogroup HuksExternalCryptoTypeApi
 * @{
 *
 * @brief Defines the macros, enumerated values, data structures,
 *    used by OpenHarmony Universal KeyStore (HUKS) APIs.
 *
 * @since 22
 * @version 1.0
 */

/**
 * @file native_huks_external_crypto_type.h
 *
 * @brief Defines the structure and enumeration. special for external crypto extension.
 *
 * @library libhuks_external_crypto.z.so
 * @syscap SystemCapability.Security.Huks.CryptoExtension
 *
 * include "huks/include/native_huks_type.h"
 * @kit UniversalKeystoreKit
 * @since 22
 * @version 1.0
 */

#ifndef NATIVE_HUKS_EXTERNAL_CRYPTO_TYPE_H
#define NATIVE_HUKS_EXTERNAL_CRYPTO_TYPE_H

#include "native_huks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OH_HUKS_EXTERNAL_CRYPTO_MAX_PROVIDER_NAME_LEN 100
#define OH_HUKS_EXTERNAL_CRYPTO_MAX_RESOURCE_ID_LEN   512

/**
 * @brief Defines the parameter structure in the parameter set.
 *
 * @since 22
 */
typedef struct OH_Huks_ExternalCryptoParam {
    /**
     * @brief Tag value.
     *
     * @since 22
     */
    uint32_t tag;
    /**
     * @brief Tag Content.
     *
     * @since 22
     */
    union {
        /**
         * @brief Parameter of the Boolean type.
         *
         * @since 22
         */
        bool boolParam;
        /**
         * @brief Parameter of the int32_t type.
         *
         * @since 22
         */
        int32_t int32Param;
        /**
         * @brief Parameter of the uint32_t type.
         *
         * @since 22
         */
        uint32_t uint32Param;
        /**
         * @brief Parameter of the uint64_t type.
         *
         * @since 22
         */
        uint64_t uint64Param;
        /**
         * @brief Parameter of the struct OH_Huks_Blob type.
         *
         * @since 22
         */
        struct OH_Huks_Blob blob;
    };
} OH_Huks_ExternalCryptoParam;
/**
 * @brief Defines the structure of the external crypto parameter set.
 *
 * @since 22
 */
typedef struct OH_Huks_ExternalCryptoParamSet {
    /**
    * @brief Memory size of the parameter set.
    *
    * @since 22
    */
    uint32_t paramSetSize;
    /**
    * @brief Number of parameters in the parameter set.
    *
    * @since 22
    */
    uint32_t paramsCnt;
    /**
    * @brief Parameter array.
    *
    * @since 22
    */
    OH_Huks_ExternalCryptoParam params[];
} OH_Huks_ExternalCryptoParamSet;

/**
 * @brief Enumerates the tag values used in parameter sets.
 *
 * @since 22
 */
typedef enum OH_Huks_ExternalCryptoTag {
    /**
     * @brief PIN code
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_UKEY_PIN = OH_HUKS_TAG_TYPE_BYTES | 200001,

    /**
     * @brief Ability Name
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_ABILITY_NAME = OH_HUKS_TAG_TYPE_BYTES | 200002,

    /**
     * @brief Extra data
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_EXTRA_DATA = OH_HUKS_TAG_TYPE_BYTES | 200003,

    /**
     * @brief Calling uid.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_UID = OH_HUKS_TAG_TYPE_INT | 200004,

    /**
     * @brief Purpose of the cert chain.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_PURPOSE = OH_HUKS_TAG_TYPE_INT | 200005,

    /**
     * @brief The timeout of get properity operation.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_TAG_TIMEOUT = OH_HUKS_TAG_TYPE_UINT | 200006
} OH_Huks_ExternalCryptoTag;

/**
 * @brief Enumerates the PIN auth states.
 *
 * @since 22
 */
typedef enum OH_Huks_ExternalPinAuthState {
    /**
     * @brief Ukey PIN is not authenticated.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_PIN_NO_AUTH = 0,

    /**
     * @brief Ukey PIN is authenticated.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_PIN_AUTH_SUCCEEDED = 1,

    /**
     * @brief Ukey PIN is locked.
     *
     * @since 22
     */
    OH_HUKS_EXT_CRYPTO_PIN_LOCKED = 2
} OH_Huks_ExternalPinAuthState;

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HUKS_EXTERNAL_CRYPTO_API_H */