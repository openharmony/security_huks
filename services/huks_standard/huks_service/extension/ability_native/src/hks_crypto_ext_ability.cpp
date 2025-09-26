/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_crypto_ext_ability.h"
#include "extension_context.h"
#include "if_system_ability_manager.h"
#include "js_hks_crypto_ext_ability.h"
#include "runtime.h"
#include "refbase.h"
// #include "hks_log.h"
#include "log_utils.h"

namespace OHOS {
namespace Security {
namespace Huks {

CreatorFunc HksCryptoExtAbility::creator_ = nullptr;
void HksCryptoExtAbility::SetCreator(const CreatorFunc &creator)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO SetCreator HksCryptoExtAbility(BASE)");
    creator_ = creator;
}

HksCryptoExtAbility* HksCryptoExtAbility::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtAbility Create start");
    if (runtime == nullptr) {
        return new HksCryptoExtAbility();
    }

    if (creator_) {
        return creator_(runtime);
    }

    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO create CryptoExtJSAbility(JS)");
            return JsHksCryptoExtAbility::Create(runtime);
        default:
            LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO create CryptoExtJSAbility(BASE)");
            return new HksCryptoExtAbility();
    }
}

void HksCryptoExtAbility::Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
    std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO Init CryptoExtJSAbility(BASE)");
    ExtensionBase<>::Init(record, application, handler, token);
}

int HksCryptoExtAbility::test(const std::string& testIn, std::vector<std::string>& testOut)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO test(BASE)");
    return true;
}

int HksCryptoExtAbility::OnCreateRemoteIndex(const std::string& abilityName, std::string& index)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO OnCreateRemoteIndex(BASE)");
    return true;
}

int HksCryptoExtAbility::OnGetRemoteHandle(const std::string& index, std::string& handle)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO OnGetRemoteHandle(BASE)");
    return true;
}

int HksCryptoExtAbility::OnOpenRemoteHandle(const std::string& handle)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO OnOpenRemoteHandle(BASE)");
    return true;
}

int HksCryptoExtAbility::OpenRemoteHandle(const std::string& index, const CppParamSet& params, std::string& handle,
    int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO OpenRemoteHandle(BASE)");
    return true;
}

int HksCryptoExtAbility::CloseRemoteHandle(const std::string& handle, const CppParamSet& params, int32_t& errcode)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO CloseRemoteHandle(BASE)");
    return true;
}

int HksCryptoExtAbility::AuthUkeyPin(const std::string& handle, const CppParamSet& params, int32_t& errcode,
    int32_t& authState, uint32_t& retryCnt)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO AuthUkeyPin(BASE)");
    return true;
}
} // namespace HUKS
} // namespace Security
} // namespace OHOS