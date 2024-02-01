/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_FUZZ_UTIL_H
#define HKS_FUZZ_UTIL_H

#include <vector>
#include <cstdio>

// import WrapParamSet
#include "base/security/huks/test/unittest/huks_standard_test/three_stage_test/include/hks_chipset_platform_test.h"

namespace OHOS {
namespace Security {
namespace Hks {
template<typename ReadType>
inline ReadType ReadData(uint8_t *&data, size_t &size, uint32_t readSize)
{
    ReadType read = reinterpret_cast<ReadType>(data);
    data += readSize;
    size -= readSize;
    return read;
}

[[maybe_unused]] WrapParamSet ConstructHksParamSetFromFuzz(uint8_t *&data, size_t &size);
}}}

#endif // HKS_FUZZ_UTIL_H
