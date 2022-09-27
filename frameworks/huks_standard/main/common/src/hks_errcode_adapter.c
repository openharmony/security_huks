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

#include "hks_errcode_adapter.h"

#include <stddef.h>

#include "hks_type.h"

static const char *g_convertErrMsg = "HksConvertErrCode Failed.";

static struct HksError g_errCodeTable[] = {
    {
        .innerErrCode = HKS_SUCCESS,
        .hksResult = {
            .errorCode = HKS_SUCCESS,
            .errorMsg = "Success.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_NO_PERMISSION,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_PERMISSION_FAIL,
            .errorMsg = "Check permission failed. User should request permission first.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_ARGUMENT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Argument is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INSUFFICIENT_DATA,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Input data is not sufficient.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_BUFFER_TOO_SMALL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "The buffer is too small.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_NULL_POINTER,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Parameter is null. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_PUBLIC_KEY,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Public key is invalid.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_KEY_INFO,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Key info is invalid.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_PARAM_NOT_EXIST,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Queried param does not exist.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_NEW_ROOT_KEY_MATERIAL_EXIST,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Root key material already exists.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_WRAPPED_FORMAT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "The format of wrapped key data is invalid.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_AUTH_TYP_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Check get auth type failed. User should add auth type in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_CHALLENGE_TYPE_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Check get challenge type failed. User should add challenge type in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_ACCESS_TYPE_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Check get access type failed. User should add access type in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_AUTH_TOKEN_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Check get auth token failed. User should add auth token in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_TIME_OUT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Time out param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_AUTH_TYPE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Auth type param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_CHALLENGE_TYPE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Challenge type param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_ACCESS_TYPE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Access type param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_AUTH_TOKEN,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Auth token param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_SECURE_SIGN_TYPE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            .errorMsg = "Secure sign type param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_API_NOT_SUPPORTED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_NOT_SUPPORTED_API,
            .errorMsg = "This api is not supported in current device.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_NOT_SUPPORTED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED,
            .errorMsg = "Feature is not support. Please make sure using the correct combination of params.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_USER_AUTH_TYPE_NOT_SUPPORT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED,
            .errorMsg = "This user auth type is not supported in current device.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_ALG_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get algorithm failed. User should add algorithm in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get key size failed. User should add key size in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_PADDING_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get padding failed. User should add padding in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_PURPOSE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get purpose failed. User should add purpose in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_DIGEST_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get digest failed. User should add digest in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_MODE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get mode failed. User should add mode in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_NONCE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get nonce failed. User should add nonce in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_AAD_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get aad failed. User should add AAD in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_IV_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get iv failed. User should add iv in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_AE_TAG_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get aead failed. User should add aead in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_SALT_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get salt failed. User should add salt in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CHECK_GET_ITERATION_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Check get iteration failed. User should add iteration in paramset.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_ALGORITHM,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Algorithm param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_KEY_SIZE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Key size param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_PADDING,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Padding param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_PURPOSE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Purpose param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_MODE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Mode param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_DIGEST,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Digest param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_SIGNATURE_SIZE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Signture size param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_IV,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "IV param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_AAD,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "AAD param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_NONCE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Nonce param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_AE_TAG,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "AEAD param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_SALT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Salt param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_ITERATION,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Iteration param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_USAGE_OF_KEY,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT,
            .errorMsg = "Purpose param is invalid. User should make sure using the correct value.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_STORAGE_FAILURE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Storage space is insufficient.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_FILE_SIZE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "The value of file size is unexpected.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_READ_FILE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Read file failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_WRITE_FILE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Write file failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_REMOVE_FILE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Remove file failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_OPEN_FILE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Open file failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CLOSE_FILE_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Close file failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_MAKE_DIR_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Make directory failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INVALID_KEY_FILE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_FILE_OPERATION_FAIL,
            .errorMsg = "Read key from file failed, for key file is invalid.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_IPC_MSG_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_COMMUNICATION_FAIL,
            .errorMsg = "Get message from IPC failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_COMMUNICATION_TIMEOUT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_COMMUNICATION_FAIL,
            .errorMsg = "IPC communication time out.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_IPC_INIT_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_COMMUNICATION_FAIL,
            .errorMsg = "IPC init failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_UNKNOWN_ERROR,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_COMMUNICATION_FAIL,
            .errorMsg = "IPC async call failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CRYPTO_ENGINE_ERROR,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_CRYPTO_FAIL,
            .errorMsg = "Errors occured in crypto engine.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_KEY_AUTH_PERMANENTLY_INVALIDATED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED,
            .errorMsg = "This credential is already invalidated permanently.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_KEY_AUTH_VERIFY_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED,
            .errorMsg = "Verify authtoken failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_KEY_AUTH_TIME_OUT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_KEY_AUTH_TIME_OUT,
            .errorMsg = "This authtoken is already timeout.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_SESSION_REACHED_LIMIT,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_SESSION_LIMIT,
            .errorMsg = "The number of sessions has reached limit.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_NOT_EXIST,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_ITEM_NOT_EXIST,
            .errorMsg = "Queried entity does not exist.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_FAILURE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_EXTERNAL_ERROR,
            .errorMsg = "General error.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_BAD_STATE,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_EXTERNAL_ERROR,
            .errorMsg = "System error.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INTERNAL_ERROR,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_EXTERNAL_ERROR,
            .errorMsg = "System internal error.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_CREDENTIAL_NOT_EXIST,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST,
            .errorMsg = "Queried credential does not exist.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_INSUFFICIENT_MEMORY,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INSUFFICIENT_MEMORY,
            .errorMsg = "Memory is insufficient.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_MALLOC_FAIL,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_INSUFFICIENT_MEMORY,
            .errorMsg = "Malloc failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_GET_USERIAM_SECINFO_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_CALL_SERVICE_FAILED,
            .errorMsg = "Calling useriam to get sec info failed.",
            .data = NULL
        }
    }, {
        .innerErrCode = HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED,
        .hksResult = {
            .errorCode = HUKS_ERR_CODE_CALL_SERVICE_FAILED,
            .errorMsg = "Calling useriam to get auth info failed.",
            .data = NULL
        }
    }
};

/**
 * Convert ErrCode.
 * Convert internal error code to formal error code and return.
 * Return HUKS_ERR_CODE_EXTERNAL_ERROR in case of converting failed.
 */
struct HksResult HksConvertErrCode(int32_t ret)
{
    struct HksResult result = {HUKS_ERR_CODE_EXTERNAL_ERROR, g_convertErrMsg, NULL};
    uint32_t i = 0;
    uint32_t uErrCodeCount = sizeof(g_errCodeTable) / sizeof(g_errCodeTable[0]);
    for (; i < uErrCodeCount; ++i) {
        if (ret == g_errCodeTable[i].innerErrCode) {
            return g_errCodeTable[i].hksResult;
        }
    }
    return result;
}

