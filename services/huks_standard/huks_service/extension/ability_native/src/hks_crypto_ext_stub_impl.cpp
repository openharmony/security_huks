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

#include "hks_crypto_ext_stub_impl.h"
// #include "hks_log.h"
#include "log_utils.h"
namespace OHOS {
namespace Security {
namespace Huks {
ErrCode HksCryptoExtStubImpl::test(const std::string& testIn, std::vector<std::string>& testOut)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl test");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    extension_->test(testIn, testOut);
    return ERR_OK;
}

ErrCode HksCryptoExtStubImpl::OnCreateRemoteIndex(const std::string& abilityName, std::string& index)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO HksCryptoExtStubImpl OnCreateRemoteIndex");
    if (extension_ == nullptr) {
        LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO extension_ nullptr");
        return ERR_OK;
    }
    extension_->OnCreateRemoteIndex(abilityName, index);
    return ERR_OK;
}
} // namespace Huks
} // namespace Security
} // namespace OHOS