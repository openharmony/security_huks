/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "huks_napi_ml_kem.h"

#include "js_native_api_types.h"
#include "securec.h"

#include "hks_api.h"
#include "hks_errcode_adapter.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_ML_KEM_ENCAPSULATE_MIN_ARGS = 2;
constexpr int HUKS_NAPI_ML_KEM_ENCAPSULATE_MAX_ARGS = 4;

constexpr int HUKS_NAPI_ML_KEM_DECAPSULATE_MIN_ARGS = 3;
constexpr int HUKS_NAPI_ML_KEM_DECAPSULATE_MAX_ARGS = 5;
constexpr int HKS_MAX_DATA_LEN_ML_KEM = 0x6400000;

static NapiRes MlKemGetUint8Array(napi_env env, napi_value object, HksBlob &arrayBlob)
{
    napi_typedarray_type arrayType {};
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(env, object, &arrayType, &length,
        &rawData, &arrayBuffer, &offset);
    if (status != napi_ok) {
        HKS_LOG_E("get typedarray info failed, status = %" LOG_PUBLIC "d", status);
        return {HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "get typedarray info failed"};
    }

    if (arrayType != napi_uint8_array) {
        HKS_LOG_E("the type of data is not Uint8Array");
        return {HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the type of data is not Uint8Array"};
    }

    if (length > HKS_MAX_DATA_LEN_ML_KEM) {
        HKS_LOG_E("data len is too large, len = %" LOG_PUBLIC "zu", length);
        return {HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the length of data is too long"};
    }

    if (length == 0) {
        arrayBlob.data = static_cast<uint8_t *>(HksMalloc(1));
    } else {
        arrayBlob.data = static_cast<uint8_t *>(HksMalloc(length));
    }
    if (arrayBlob.data == nullptr) {
        HKS_LOG_E("could not alloc memory");
        return {HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "Insufficient memory."};
    }

    (void)memcpy_s(arrayBlob.data, length, rawData, length);
    arrayBlob.size = static_cast<uint32_t>(length);
    return NapiRes::Ok();
}

static NapiRes HuksParseKeyAlias(napi_env env, napi_value object, HksBlob *&alias)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        HKS_LOG_E("napi fail");
        return {HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "napi fail"};
    }

    if (valueType != napi_valuetype::napi_string) {
        HKS_LOG_E("no string type");
        return {HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the type of alias isn't string"};
    }

    size_t length = 0;
    status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);
    if (status != napi_ok) {
        HKS_LOG_E("could not get string length %" LOG_PUBLIC "d", status);
        return {HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get string length"};
    }

    constexpr int HKS_MAX_DATA_LEN = 0x6400000;
    if (length > HKS_MAX_DATA_LEN) {
        HKS_LOG_E("input key alias length %" LOG_PUBLIC "zu too large", length);
        return {HUKS_ERR_CODE_INVALID_ARGUMENT, "the length of alias is too long"};
    }

    char *data = static_cast<char *>(HksMalloc(length + 1));
    if (data == nullptr) {
        HKS_LOG_E("could not alloc memory");
        return {HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "Insufficient memory."};
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, data, length + 1, &result);
    if (status != napi_ok) {
        HKS_FREE(data);
        HKS_LOG_E("could not get string %" LOG_PUBLIC "d", status);
        return {HUKS_ERR_CODE_INVALID_ARGUMENT, "could not get string"};
    }

    alias = static_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (alias == nullptr) {
        HKS_FREE(data);
        HKS_LOG_E("could not alloc memory");
        return {HUKS_ERR_CODE_INSUFFICIENT_MEMORY, "Insufficient memory."};
    }
    alias->data = reinterpret_cast<uint8_t *>(data);
    alias->size = static_cast<uint32_t>(length & UINT32_MAX);

    return NapiRes::Ok();
}

static MlKemEncapsulateAsyncContext CreateMlKemEncapsulateAsyncContext()
{
    MlKemEncapsulateAsyncContext context =
        static_cast<MlKemEncapsulateAsyncContext>(HksMalloc(sizeof(MlKemEncapsulateAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(MlKemEncapsulateAsyncContextT), 0, sizeof(MlKemEncapsulateAsyncContextT));
    }
    return context;
}

static void DeleteMlKemEncapsulateAsyncContext(napi_env env, MlKemEncapsulateAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
    }

    if (context->keyAlias != nullptr) {
        HKS_FREE_BLOB(*context->keyAlias);
        HKS_FREE(context->keyAlias);
    }

    HksFreeParamSet(&context->paramSet);

    if (context->sharedKeyAlias != nullptr) {
        HKS_FREE_BLOB(*context->sharedKeyAlias);
        HKS_FREE(context->sharedKeyAlias);
    }

    HksFreeParamSet(&context->sharedKeyParamSet);

    if (context->encapResult != nullptr) {
        HKS_FREE_ENCAPSULATION_RESULT(context->encapResult);
        HKS_FREE(context->encapResult);
    }

    HKS_FREE(context);
    context = nullptr;
}

static napi_value ParseMlKemEncapsulateParams(napi_env env, napi_callback_info info,
    MlKemEncapsulateAsyncContext context)
{
    size_t argc = HUKS_NAPI_ML_KEM_ENCAPSULATE_MAX_ARGS;
    napi_value argv[HUKS_NAPI_ML_KEM_ENCAPSULATE_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_ML_KEM_ENCAPSULATE_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    NapiRes res = HuksParseKeyAlias(env, argv[index], context->keyAlias);
    if (res.code != HKS_SUCCESS) {
        HksNapiThrow(env, res.code, res.errMsg.data());
        HKS_LOG_E("could not get key alias");
        return nullptr;
    }

    index++;
    napi_value result = ParseHuksParams(env, argv[index], {}, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramset");
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    // Optional: sharedKeyAlias and sharedKeyParamSet
    index++;
    if (index >= argc) {
        return GetInt32(env, 0);
    }

    res = HuksParseKeyAlias(env, argv[index], context->sharedKeyAlias);
    if (res.code != HKS_SUCCESS) {
        HksNapiThrow(env, res.code, res.errMsg.data());
        HKS_LOG_E("could not get shared key alias");
        return nullptr;
    }

    index++;
    if (index < argc) {
        result = ParseHuksParams(env, argv[index], {}, context->sharedKeyParamSet);
        if (result == nullptr) {
            HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get shared key paramset");
            HKS_LOG_E("could not get shared key paramset");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value MlKemEncapsulateAsyncWork(napi_env env, MlKemEncapsulateAsyncContext &context)
{
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "mlKemEncapsulateAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    napi_status status = napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            MlKemEncapsulateAsyncContext napiContext = static_cast<MlKemEncapsulateAsyncContext>(data);
            napiContext->encapResult =
                static_cast<struct HksEncapsulationResult *>(HksMalloc(sizeof(struct HksEncapsulationResult)));
            if (napiContext->encapResult != nullptr) {
                (void)memset_s(napiContext->encapResult, sizeof(struct HksEncapsulationResult), 0,
                    sizeof(struct HksEncapsulationResult));
            }
            napiContext->result = HksEncapsulate(napiContext->keyAlias, napiContext->paramSet,
                napiContext->sharedKeyAlias, napiContext->sharedKeyParamSet, napiContext->encapResult);
        },
        [](napi_env env, napi_status status, void *data) {
            MlKemEncapsulateAsyncContext napiContext = static_cast<MlKemEncapsulateAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);

            if (napiContext->encapResult != nullptr) {
                resultData.outData = &napiContext->encapResult->encapsulatedData;
                resultData.sharedSecret = &napiContext->encapResult->sharedSecret;
            }

            if (napiContext->sharedKeyAlias != nullptr) {
                resultData.forceReturnObject = true;
            }

            napiContext->result = HksReplaceErrCodeIf401(napiContext->result);

            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteMlKemEncapsulateAsyncContext(env, napiContext);
        },
        static_cast<void *>(context), &context->asyncWork);
    if (status != napi_ok) {
        DeleteMlKemEncapsulateAsyncContext(env, context);
        HKS_LOG_E("could not create async work");
        return nullptr;
    }

    status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteMlKemEncapsulateAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value HuksNapiMlKemEncapsulate(napi_env env, napi_callback_info info)
{
    MlKemEncapsulateAsyncContext context = CreateMlKemEncapsulateAsyncContext();
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ParseMlKemEncapsulateParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteMlKemEncapsulateAsyncContext(env, context);
        return nullptr;
    }

    result = MlKemEncapsulateAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteMlKemEncapsulateAsyncContext(env, context);
        return nullptr;
    }

    return result;
}

static MlKemDecapsulateAsyncContext CreateMlKemDecapsulateAsyncContext()
{
    MlKemDecapsulateAsyncContext context =
        static_cast<MlKemDecapsulateAsyncContext>(HksMalloc(sizeof(MlKemDecapsulateAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(MlKemDecapsulateAsyncContextT), 0, sizeof(MlKemDecapsulateAsyncContextT));
    }
    return context;
}

static void DeleteMlKemDecapsulateAsyncContext(napi_env env, MlKemDecapsulateAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
    }

    if (context->keyAlias != nullptr) {
        HKS_FREE_BLOB(*context->keyAlias);
        HKS_FREE(context->keyAlias);
    }

    HksFreeParamSet(&context->paramSet);

    if (context->encapOrsharedSecret != nullptr) {
        HKS_MEMSET_FREE_BLOB(*context->encapOrsharedSecret);
        HKS_FREE(context->encapOrsharedSecret);
    }

    if (context->sharedKeyAlias != nullptr) {
        HKS_FREE_BLOB(*context->sharedKeyAlias);
        HKS_FREE(context->sharedKeyAlias);
    }

    HksFreeParamSet(&context->sharedKeyParamSet);

    HKS_FREE(context);
    context = nullptr;
}

static napi_value ParseOptionalSharedKeyParams(napi_env env, size_t argc, napi_value argv[],
    size_t index, MlKemDecapsulateAsyncContext context)
{
    if (index >= argc) {
        return GetInt32(env, 0);
    }

    NapiRes res = HuksParseKeyAlias(env, argv[index], context->sharedKeyAlias);
    if (res.code != HKS_SUCCESS) {
        HksNapiThrow(env, res.code, res.errMsg.data());
        HKS_LOG_E("could not get shared key alias");
        return nullptr;
    }

    index++;
    if (index < argc) {
        napi_value result = ParseHuksParams(env, argv[index], {}, context->sharedKeyParamSet);
        if (result == nullptr) {
            HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get shared key paramset");
            HKS_LOG_E("could not get shared key paramset");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value ParseMlKemDecapsulateParams(napi_env env, napi_callback_info info,
    MlKemDecapsulateAsyncContext context)
{
    size_t argc = HUKS_NAPI_ML_KEM_DECAPSULATE_MAX_ARGS;
    napi_value argv[HUKS_NAPI_ML_KEM_DECAPSULATE_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_ML_KEM_DECAPSULATE_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    NapiRes res = HuksParseKeyAlias(env, argv[index], context->keyAlias);
    if (res.code != HKS_SUCCESS) {
        HksNapiThrow(env, res.code, res.errMsg.data());
        HKS_LOG_E("could not get key alias");
        return nullptr;
    }

    index++;
    napi_value result = ParseHuksParams(env, argv[index], {}, context->paramSet);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get paramset");
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    index++;
    context->encapOrsharedSecret = static_cast<struct HksBlob *>(HksMalloc(sizeof(struct HksBlob)));
    if (context->encapOrsharedSecret == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not alloc encapOrsharedSecret blob");
        return nullptr;
    }
    NapiRes resArray = MlKemGetUint8Array(env, argv[index], *context->encapOrsharedSecret);
    if (resArray.code != HKS_SUCCESS) {
        HksNapiThrow(env, resArray.code, resArray.errMsg.data());
        HKS_LOG_E("could not get encapsulatedData");
        return nullptr;
    }

    return ParseOptionalSharedKeyParams(env, argc, argv, ++index, context);
}

static napi_value MlKemDecapsulateAsyncWork(napi_env env, MlKemDecapsulateAsyncContext &context)
{
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "mlKemDecapsulateAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    napi_status status = napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            MlKemDecapsulateAsyncContext napiContext = static_cast<MlKemDecapsulateAsyncContext>(data);
            // encapOrsharedSecret: 输入是密文，HUKS 会分配输出内存（如果 sharedKeyAlias == NULL）
            napiContext->result = HksDecapsulate(napiContext->keyAlias, napiContext->paramSet,
                napiContext->sharedKeyAlias, napiContext->sharedKeyParamSet,
                napiContext->encapOrsharedSecret);
        },
        [](napi_env env, napi_status status, void *data) {
            MlKemDecapsulateAsyncContext napiContext = static_cast<MlKemDecapsulateAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);

            if (napiContext->sharedKeyAlias == nullptr && napiContext->encapOrsharedSecret != nullptr) {
                resultData.sharedSecret = napiContext->encapOrsharedSecret;
            }

            if (napiContext->sharedKeyAlias != nullptr) {
                resultData.forceReturnObject = true;
            }

            napiContext->result = HksReplaceErrCodeIf401(napiContext->result);
            
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteMlKemDecapsulateAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);
    if (status != napi_ok) {
        DeleteMlKemDecapsulateAsyncContext(env, context);
        HKS_LOG_E("could not create async work");
        return nullptr;
    }

    status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteMlKemDecapsulateAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value HuksNapiMlKemDecapsulate(napi_env env, napi_callback_info info)
{
    MlKemDecapsulateAsyncContext context = CreateMlKemDecapsulateAsyncContext();
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ParseMlKemDecapsulateParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteMlKemDecapsulateAsyncContext(env, context);
        return nullptr;
    }

    result = MlKemDecapsulateAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteMlKemDecapsulateAsyncContext(env, context);
        return nullptr;
    }

    return result;
}
}  // namespace HuksNapiItem