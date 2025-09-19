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

#ifndef JS_HKS_CRYPTO_EXT_ABILITY_H
#define JS_HKS_CRYPTO_EXT_ABILITY_H

#include "hks_crypto_ext_ability.h"
#include "js_runtime.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace Huks {

using InputArgsParser = std::function<bool(napi_env&, napi_value*, size_t&)>;
using ResultValueParser = std::function<bool(napi_env&, napi_value)>;

struct CallJsParam {
    std::mutex CryptoOperateMutex;
    std::condition_variable CryptoOperateCondition;
    bool isReady = false;
    std::string funcName;
    AbilityRuntime::JsRuntime *jsRuntime;
    NativeReference *jsObj;
    InputArgsParser argParser;
    ResultValueParser retParser;

    CallJsParam(const std::string &funcNameIn, AbilityRuntime::JsRuntime *jsRuntimeIn, NativeReference *jsObjIn,
        InputArgsParser &argParserIn, ResultValueParser &retParserIn)
        : funcName(funcNameIn), jsRuntime(jsRuntimeIn), jsObj(jsObjIn), argParser(argParserIn), retParser(retParserIn)
    {}
};

class JsHksCryptoExtAbility : public HksCryptoExtAbility {
public:
    JsHksCryptoExtAbility(AbilityRuntime::JsRuntime &jsRuntime);
    virtual ~JsHksCryptoExtAbility() override;

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    static JsHksCryptoExtAbility* Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);
    void OnStart(const AAFwk::Want &want) override;
    sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;
    int test(const std::string &testIn, std::vector<std::string> &testOut) override;
    int OnCreateRemoteIndex(const std::string& abilityName, std::string& index) override;
private:
    template <typename T>
    struct Value {
        T data;
        int code {ERR_OK};
    };
    napi_value CallObjectMethod(const char *name, napi_value const *argv = nullptr, size_t argc = 0);
    napi_status GetStringValue(napi_env env, napi_value value, std::string &result);
    int CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime, NativeReference *jsObj,
        InputArgsParser argParser, ResultValueParser retParser);
    void GetSrcPath(std::string &srcPath);
    bool ParserVectorStringJsResult(napi_env &env, napi_value nativeValue, Value<std::vector<std::string>> &results);
    AbilityRuntime::JsRuntime &jsRuntime_;
    std::shared_ptr<NativeReference> jsObj_;
};
} // HUKS
} // namespace Security
} // namespace OHOS
#endif // JS_HKS_CRYPTO_EXT_ABILITY_H
