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

CreatorFunc CryptoExtAbility::creator_ = nullptr;
void CryptoExtAbility::SetCreator(const CreatorFunc &creator)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO SetCreator CryptoExtJSAbility(BASE)");
    creator_ = creator;
}

CryptoExtAbility* CryptoExtAbility::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO CryptoExtAbility Create start");
    if (runtime == nullptr) {
        return new CryptoExtAbility();
    }

    if (creator_) {
        return creator_(runtime);
    }

    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO create CryptoExtJSAbility(JS)");
            return JsCryptoExtAbility::Create(runtime);
        default:
            LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO create CryptoExtJSAbility(BASE)");
            return new CryptoExtAbility();
    }
}

void CryptoExtAbility::Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
    std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO Init CryptoExtJSAbility(BASE)");
    ExtensionBase<>::Init(record, application, handler, token);
}

int CryptoExtAbility::test(const std::string& testIn, std::vector<std::string>& testOut)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO test(BASE)");
    return true;
}
} // namespace HUKS
} // namespace Security
} // namespace OHOS