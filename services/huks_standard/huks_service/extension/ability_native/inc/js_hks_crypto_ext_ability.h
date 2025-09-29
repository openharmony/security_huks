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

typedef enum {
    OPEN_REMOTE_HANDLE = 0,
    CLOSE_REMOTE_HANDLE,
    AUTH_UKEY_PIN,
    GET_UKEY_PIN_AUTH_STATE,
    EXPORT_CERTIFICATE,
    EXPORT_PROVIDER_CERTIFICATES
} CryptoResultParamType;

typedef struct HksCertInfo {
    int32_t purpose {};
    std::string index {};
    struct HksBlob certsArray {};
} HksCertInfo;

typedef struct CryptoResultParam {
    int32_t errCode {};
    int32_t authState {};
    uint32_t retryCnt {};
    std::string handle {};
    std::string index {};
    std::vector<HksCertInfo> certs {};

    CryptoResultParamType paramType {};
    std::condition_variable callJsCon;
    std::atomic<bool> callJsExMethodDone {false};
    std::mutex callJsMutex;
} CryptoResultParam; 

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
    int OpenRemoteHandle(const std::string& index, const CppParamSet& params, std::string& handle,
        int32_t& errcode) override;
    int CloseRemoteHandle(const std::string& handle, const CppParamSet& params, int32_t& errcode) override;
    int AuthUkeyPin(const std::string& handle, const CppParamSet& params, int32_t& errcode,
        int32_t& authState, uint32_t& retryCnt) override;
    int GetUkeyPinAuthState(const std::string& handle, const CppParamSet& params,
        int32_t& authState, int32_t& errcode) override;
    int ExportCertificate(const std::string& index, const CppParamSet& params,
        std::string& certJsonArr, int32_t& errcode) override;
    int ExportProviderCertificates( const CppParamSet& params, std::string& certJsonArr,
        int32_t& errcode) override;
private:
    template <typename T>
    struct Value {
        T data;
        int code {ERR_OK};
    };
    napi_value CallObjectMethod(const char *name, napi_value const *argv = nullptr, size_t argc = 0);
    static napi_status GetStringValue(napi_env env, napi_value value, std::string &result);
    static napi_status GetHksCertInfoValue(napi_env env, napi_value value, HksCertInfo &certInfo);
    static napi_status GetUint8ArrayValue(napi_env env, napi_value value, HksBlob &result);
    static void HksCertInfoToString(std::vector<HksCertInfo> &certInfoVec, std::string &jsonStr);
    int CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime, NativeReference *jsObj,
        InputArgsParser argParser, ResultValueParser retParser);
    void GetSrcPath(std::string &srcPath);
    bool ParserVectorStringJsResult(napi_env &env, napi_value nativeValue, Value<std::vector<std::string>> &results);
    static bool ConvertFunctionResult(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);
    static napi_value PromiseCallback(napi_env env, napi_callback_info info);
    void CallPromise(napi_env &env, napi_value funcResult, std::shared_ptr<CryptoResultParam> dataParam);
    static void GetOpenRemoteHandleParams(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);
    static void GetAuthUkeyPin(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);
    static void GetUkeyPinAuthStateParams(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);
    static void GetExportCertificateParams(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);
    // static void GetUkeyPinAuthStateParams(napi_env env, napi_value funcResult, CryptoResultParam &resultParams);

    AbilityRuntime::JsRuntime &jsRuntime_;
    std::shared_ptr<NativeReference> jsObj_;
};

class PromiseCallbackInfo {
public:
    static PromiseCallbackInfo* Create(std::shared_ptr<CryptoResultParam> cryptoResultParam);
 
    static void Destroy(PromiseCallbackInfo* callbackInfo);
 
    std::shared_ptr<CryptoResultParam> GetJsCallBackParam();
private:
    explicit PromiseCallbackInfo(std::shared_ptr<CryptoResultParam> cryptoResultParam);
 
    ~PromiseCallbackInfo();
 
    std::shared_ptr<CryptoResultParam> cryptoResultParam_;
};
} // HUKS
} // namespace Security
} // namespace OHOS
#endif // JS_HKS_CRYPTO_EXT_ABILITY_H
