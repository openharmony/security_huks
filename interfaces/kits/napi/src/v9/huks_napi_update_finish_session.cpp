/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "huks_napi_update_finish_session.h"

#include <vector>

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_napi_common_item.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_UPDATE_MIN_ARGS = 2;
constexpr int HUKS_NAPI_UPDATE_MAX_ARGS = 4;

UpdateAsyncContext CreateUpdateAsyncContext()
{
    UpdateAsyncContext context = static_cast<UpdateAsyncContext>(HksMalloc(sizeof(UpdateAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(UpdateAsyncContextT), 0, sizeof(UpdateAsyncContextT));
    }
    return context;
}

void DeleteUpdateAsyncContext(napi_env env, UpdateAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteCommonAsyncContext(env, context->asyncWork, context->callback, context->handle, context->paramSet);

    if (context->inData != nullptr) {
        if (context->inData->data != nullptr && context->inData->size != 0) {
            (void)memset_s(context->inData->data, context->inData->size, 0, context->inData->size);
        }
        FreeHksBlob(context->inData);
    }

    if (context->outData != nullptr) {
        if (context->outData->data != nullptr && context->outData->size != 0) {
            (void)memset_s(context->outData->data, context->outData->size, 0, context->outData->size);
        }
        FreeHksBlob(context->outData);
    }

    if (context->token != nullptr) {
        FreeHksBlob(context->token);
    }

    HKS_FREE(context);
    context = nullptr;
}

static int32_t FillContextInDataAndOutData(napi_env env, napi_value *argv, UpdateAsyncContext context, size_t index)
{
    napi_value inData = nullptr;
    bool hasInData = false;
    napi_has_named_property(env, argv[index], HKS_OPTIONS_PROPERTY_INDATA.c_str(), &hasInData);
    napi_status status = napi_get_named_property(env, argv[index], HKS_OPTIONS_PROPERTY_INDATA.c_str(), &inData);
    if (status == napi_ok && inData != nullptr && hasInData) {
        napi_value result = GetUint8Array(env, inData, *context->inData);
        if (result == nullptr) {
            HKS_LOG_E("could not get inData");
            return HKS_ERROR_BAD_STATE;
        }
    } else {
        context->inData->size = 0;
        context->inData->data = nullptr;
    }

    context->outData->size = context->inData->size + DATA_SIZE_64KB;
    context->outData->data = static_cast<uint8_t *>(HksMalloc(context->outData->size));
    if (context->outData->data == nullptr) {
        HKS_LOG_E("malloc memory failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

    return HKS_SUCCESS;
}

int32_t FillContextInDataAndOutBlob(napi_env env, napi_value *argv, UpdateAsyncContext context, size_t index)
{
    context->outData = static_cast<struct HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->outData == nullptr) {
        HKS_LOG_E("could not alloc out blob memory");
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->outData, sizeof(HksBlob), 0, sizeof(HksBlob));

    context->inData = static_cast<struct HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->inData == nullptr) {
        HKS_LOG_E("could not alloc in blob memory");
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->inData, sizeof(HksBlob), 0, sizeof(HksBlob));

    int32_t ret = FillContextInDataAndOutData(env, argv, context, index);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("fill data failed");
    }
    return ret;
}

static int32_t GetCallBackFunction(napi_env env, napi_value object, UpdateAsyncContext context)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        HKS_LOG_E("could not get object type");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (valueType != napi_valuetype::napi_function) {
        HKS_LOG_I("no callback fun, process as promise func");
        return HKS_SUCCESS;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, object, 1, &ref);
    if (status != napi_ok) {
        HKS_LOG_E("could not create reference");
        return HKS_ERROR_BAD_STATE;
    }
    context->callback = ref;
    return HKS_SUCCESS;
}

static int32_t GetToken(napi_env env, napi_value object, UpdateAsyncContext context)
{
    context->token = static_cast<struct HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (context->token == nullptr) {
        HKS_LOG_E("could not alloc token blob memory");
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->token, sizeof(HksBlob), 0, sizeof(HksBlob));

    napi_value result = GetUint8Array(env, object, *(context->token));
    if (result == nullptr) {
        HKS_LOG_E("could not get token data");
        return HKS_ERROR_BAD_STATE;
    }

    return HKS_SUCCESS;
}

int32_t GetTokenOrCallback(napi_env env, napi_value *argv, UpdateAsyncContext context,
    size_t index, size_t maxIndex)
{
    if (index >= maxIndex) { /* only 2 input params */
        return HKS_SUCCESS;
    }

    /*
     * check wether arg 3 is callback: if true, get callback function and return;
     * else get token, then check wether has arg 4: if true, get arg 4 as callback function
     */
    int32_t ret;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, argv[index], &valueType);
    if (status != napi_ok) {
        HKS_LOG_E("could not get object type");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (valueType) {
        case napi_valuetype::napi_function:
            return GetCallBackFunction(env, argv[index], context); /* return if arg 3 is callback */
        case napi_valuetype::napi_object: {
            ret = GetToken(env, argv[index], context);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("could not get token value");
                return ret;
            }

            index++;
            if (index < maxIndex) { /* has arg 4: can only be callback */
                return GetCallBackFunction(env, argv[index], context);
            }
            return HKS_SUCCESS;
        }
        case napi_valuetype::napi_undefined: {
            HKS_LOG_I("param %" LOG_PUBLIC "zu is undefined", index);
            // if param 3 is undefined, ignore this and try to get param 4 as callback func
            index++;
            if (index < maxIndex) { /* has arg 4: can only be callback */
                return GetCallBackFunction(env, argv[index], context);
            }
            return HKS_SUCCESS;
        }
        default:
            HKS_LOG_I("param %" LOG_PUBLIC "zu is invalid type", index);
            // if param 3 is invalid type, process as redundant params
            return HKS_SUCCESS;
    }

    return HKS_ERROR_BAD_STATE;
}

static napi_value ParseUpdateParams(napi_env env, napi_callback_info info, UpdateAsyncContext context)
{
    size_t argc = HUKS_NAPI_UPDATE_MAX_ARGS;
    napi_value argv[HUKS_NAPI_UPDATE_MAX_ARGS] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < HUKS_NAPI_UPDATE_MIN_ARGS) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "no enough params input");
        HKS_LOG_E("no enough params");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = GetHandleValue(env, argv[index], context->handle);
    if (result == nullptr) {
        HKS_LOG_E("update could not get handle value");
        return nullptr;
    }

    index++;
    napi_value properties = GetPropertyFromOptions(env, argv[index], HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (properties == nullptr) {
        HKS_LOG_E("get properties failed");
        return nullptr;
    }

    if (FillContextInDataAndOutBlob(env, argv, context, index) != HKS_SUCCESS) {
        HKS_LOG_E("fill in or out blob failed");
        return nullptr;
    }

    index++;
    if (GetTokenOrCallback(env, argv, context, index, argc) != HKS_SUCCESS) {
        HKS_LOG_E("get token or callback failed");
        return nullptr;
    }

    if (ParseHksParamSetWithToken(env, context->token, properties, context->paramSet) == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value UpdateFinishAsyncWork(napi_env env, UpdateAsyncContext context)
{
    napi_value promise = nullptr;
    if (context->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    }

    napi_value resourceName;
    napi_create_string_latin1(env, "UpdateAsyncWork", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            UpdateAsyncContext napiContext = static_cast<UpdateAsyncContext>(data);
            if (napiContext->isUpdate) {
                napiContext->result = HksUpdate(napiContext->handle,
                    napiContext->paramSet, napiContext->inData, napiContext->outData);
            } else {
                napiContext->result = HksFinish(napiContext->handle,
                    napiContext->paramSet, napiContext->inData, napiContext->outData);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            UpdateAsyncContext napiContext = static_cast<UpdateAsyncContext>(data);
            HksSuccessReturnResult resultData;
            SuccessReturnResultInit(resultData);
            resultData.outData = napiContext->outData;
            HksReturnNapiResult(env, napiContext->callback, napiContext->deferred, napiContext->result, resultData);
            DeleteUpdateAsyncContext(env, napiContext);
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        DeleteUpdateAsyncContext(env, context);
        HKS_LOG_E("could not queue async work");
        return nullptr;
    }

    if (context->callback == nullptr) {
        return promise;
    } else {
        return GetNull(env);
    }
}

napi_value HuksNapiUpdateSession(napi_env env, napi_callback_info info)
{
    UpdateAsyncContext context = CreateUpdateAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("update: could not create context");
        return nullptr;
    }

    context->isUpdate = true;
    napi_value result = ParseUpdateParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("update: could not parse params");
        DeleteUpdateAsyncContext(env, context);
        return nullptr;
    }

    result = UpdateFinishAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("update: could not start async work");
        DeleteUpdateAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value HuksNapiFinishSession(napi_env env, napi_callback_info info)
{
    UpdateAsyncContext context = CreateUpdateAsyncContext();
    if (context == nullptr) {
        HKS_LOG_E("finish: could not create context");
        return nullptr;
    }

    context->isUpdate = false;
    napi_value result = ParseUpdateParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("finish: could not parse params");
        DeleteUpdateAsyncContext(env, context);
        return nullptr;
    }

    result = UpdateFinishAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("finish: could not start async work");
        DeleteUpdateAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
