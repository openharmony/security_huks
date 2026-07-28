/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_ERR_CODE_MAPPER_H
#define HKS_UKEY_ERR_CODE_MAPPER_H

#include <map>
#include <cstdint>
#include "hks_function_types.h"

namespace OHOS {
namespace Security {
namespace Huks {

class HksErrCodeMapper {
public:
    void Register(PluginMethodEnum method, const std::map<int32_t, int32_t> &mapping);
    void AddEntry(PluginMethodEnum method, int32_t extErrCode, int32_t hksErrCode);
    int32_t Convert(PluginMethodEnum method, int32_t extensionErrorCode) const;
private:
    std::map<PluginMethodEnum, std::map<int32_t, int32_t>> mappings_;
};

void InitDefaultMappings(HksErrCodeMapper &mapper);

}
}
}
#endif
