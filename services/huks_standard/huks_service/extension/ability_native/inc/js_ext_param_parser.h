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

#ifndef JS_EXT_PARAM_PARSER_H
#define JS_EXT_PARAM_PARSER_H

#include "js_hks_crypto_ext_ability.h"

namespace OHOS {
namespace Security {
namespace Huks {

int32_t GetOpenRemoteHandleParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetResourceIdParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetAuthUkeyPinParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetUkeyPinAuthStateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetExportCertificateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetSessionParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetExportPublicKeyParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t GetGetPropertyParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
int32_t ConvertFunctionResult(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);
void GetErrorInfoParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams);

} // namespace Huks
} // namespace Security
} // namespace OHOS

#endif // JS_EXT_PARAM_PARSER_H
