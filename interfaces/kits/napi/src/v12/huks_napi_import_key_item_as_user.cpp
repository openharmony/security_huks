/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "huks_napi_import_key_item_as_user.h"
#include "huks_napi_import_key_item.h"
#include "huks_napi_common_item.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

namespace HuksNapiItem {
constexpr int HUKS_NAPI_IMPORT_KEY_AS_USER_ARGS_COUNT = 3;

static napi_value ImportKeyAsUserParseParams(napi_env env, napi_callback_info info, ImportKeyAsyncContext context)
{
    size_t argc = HUKS_NAPI_IMPORT_KEY_AS_USER_ARGS_COUNT;
    napi_value argv[HUKS_NAPI_IMPORT_KEY_AS_USER_ARGS_COUNT] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != HUKS_NAPI_IMPORT_KEY_AS_USER_ARGS_COUNT) {
        HksNapiThrowInvalidParamCount(env);
        HKS_LOG_E("invalid params count %" LOG_PUBLIC "zu", argc);
        return nullptr;
    }

    int userId = 0;
    size_t index = 0;
    napi_value result = GetUserIdValue(env, argv[index], userId);
    if (result == nullptr) {
        HksNapiThrowGetUserIdFail(env);
        HKS_LOG_E("ImportKeyAsUserParseParams could not get user id value");
        return nullptr;
    }
    index++;
    result = ParseKeyAliasAndHksParamSetAsUser(env, userId, argv, index, {context->keyAlias, context->paramSet});
    if (result == nullptr) {
        HKS_LOG_E("importKey parse keyAlias or paramSet failed");
        return nullptr;
    }

    result = ParseKeyData(env, argv[index], context->key);
    if (result == nullptr) {
        HKS_LOG_E("importKey parse keyData failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value HuksNapiImportKeyItemAsUser(napi_env env, napi_callback_info info)
{
    ImportKeyAsyncContext context = CreateImportKeyAsyncContext();
    if (context == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ImportKeyAsUserParseParams(env, info, context);
    if (result == nullptr) {
        HKS_LOG_E("could not parse params");
        DeleteImportKeyAsyncContext(env, context);
        return nullptr;
    }

    result = ImportKeyAsyncWork(env, context);
    if (result == nullptr) {
        HKS_LOG_E("could not start async work");
        DeleteImportKeyAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace HuksNapiItem
