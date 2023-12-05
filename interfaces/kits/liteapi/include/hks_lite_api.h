/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_LITE_API_H
#define HKS_LITE_API_H

#include "jsi.h"

namespace OHOS {
namespace ACELite {
class HksLiteModule final : public MemoryHeap {
public:
    HksLiteModule() {}
    ~HksLiteModule() {}
    static JSIValue generateKeyItem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue initSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue updateSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue finishSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue abortSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue deleteKeyItem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue isKeyItemExist(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue hasKeyItem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
};

void InitHuksModule(JSIValue exports);
} // namespace ACELite
} // namespace OHOS
#endif // HKS_LITE_API_H
