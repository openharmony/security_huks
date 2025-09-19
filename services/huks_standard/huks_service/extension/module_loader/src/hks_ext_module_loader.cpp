/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_ext_module_loader.h"

#include <string>
#include <utility>
#include "hks_crypto_ext_ability.h"

namespace OHOS {
namespace Security {
namespace Huks {

HksCryptoExtAbilityModuleLoader::HksCryptoExtAbilityModuleLoader() = default;
HksCryptoExtAbilityModuleLoader::~HksCryptoExtAbilityModuleLoader() = default;

Extension *HksCryptoExtAbilityModuleLoader::Create(const std::unique_ptr<Runtime>& runtime) const
{
    return HksCryptoExtAbility::Create(runtime);
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &HksCryptoExtAbilityModuleLoader::GetInstance();
}

extern "C" __attribute__((visibility("default"))) void SetCreator(const CreatorFunc& creator)
{
    return HksCryptoExtAbility::SetCreator(creator);
}

std::map<std::string, std::string> HksCryptoExtAbilityModuleLoader::GetParams()
{
    std::map<std::string, std::string> params;
    // TODO 根据BMS最终代码，要更换 35的具体值
    const std::string CRYPTO_ACCESS_TYPE = "35";
    params.insert(std::pair<std::string, std::string>("type", CRYPTO_ACCESS_TYPE));
    params.insert(std::pair<std::string, std::string>("name", "CryptoExtensionAbility"));
    return params;
}
} // Huks
} // namespace Security
} // namespace OHOS