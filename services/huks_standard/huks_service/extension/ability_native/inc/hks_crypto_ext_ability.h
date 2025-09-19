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

#ifndef HUKS_CRYPTO_EXT_ABILITY_H
#define HUKS_CRYPTO_EXT_ABILITY_H

#include "extension_base.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
class Runtime;
}
namespace Security {
namespace Huks {

class HksCryptoExtAbility;
using CreatorFunc = std::function<HksCryptoExtAbility* (const std::unique_ptr<AbilityRuntime::Runtime>& runtime)>;
class HksCryptoExtAbility : public AbilityRuntime::ExtensionBase<> {
public:
    HksCryptoExtAbility() = default;
    virtual ~HksCryptoExtAbility() = default;

    virtual void Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
        const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
        std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    static HksCryptoExtAbility* Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime);
    static void SetCreator(const CreatorFunc& creator);
    
    virtual int test(const std::string& testIn, std::vector<std::string>& testOut);
private:
    static CreatorFunc creator_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // HUKS_CRYPTO_EXT_ABILITY_H