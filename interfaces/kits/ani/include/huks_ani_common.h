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

 #ifndef HKS_ANI_H
 #define HKS_ANI_H

#include "hks_mem.h"
#include "hks_type.h"
#include "securec.h"

#include <ani.h>
#include <string>
namespace HuksAni {

int32_t HksAniString2NativeStirng([[maybe_unused]] ani_env *&env, const ani_string &strObject, std::string &nativeStr);

int32_t HksGetKeyAliasFromAni([[maybe_unused]] ani_env *&env, const ani_string &strObject, HksBlob &keyAliasOut);

int32_t HksCreateAniResult(const int32_t result, const std::string errMsg, [[maybe_unused]] ani_env *&env,
    ani_object &resultObjOut);
}
#endif