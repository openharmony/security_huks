/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef FILE_ACCESS_EXT_STUB_IMPL_H
#define FILE_ACCESS_EXT_STUB_IMPL_H

#include <memory>
#include <vector>

#include "extension_stub.h"
#include "hks_crypto_ext_ability.h"

namespace OHOS {
namespace Security {
namespace Huks {
class HksCryptoExtStubImpl : public ExtensionStub {
public:
    explicit HksCryptoExtStubImpl(const std::shared_ptr<HksCryptoExtAbility>& extension, napi_env env)
        : extension_(extension) {}

    virtual ~HksCryptoExtStubImpl() {}

    // bool CheckCallingPermission(const std::string &permission);
    ErrCode test(const std::string& testIn, std::vector<std::string> &testOut) override;
private:
    std::shared_ptr<HksCryptoExtAbility> extension_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // FILE_ACCESS_EXT_STUB_IMPL_H
