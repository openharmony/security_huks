/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_MODIFY_OLD_KEY_H
#define HKS_TEST_MODIFY_OLD_KEY_H

#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksTestGenerateOldKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo);
int32_t HksTestDeleteOldKey(const struct HksBlob *keyAlias, const struct HksProcessInfo *processInfo);
int32_t HksTestOldKeyExist(const struct HksBlob *keyAlias);
int32_t HksTestInitialize(void);
void HksChangeOldKeyOwner(const char *path, uint32_t uid);

#ifdef __cplusplus
}
#endif

#endif
