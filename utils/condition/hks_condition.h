/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef HKS_CONDITION_H
#define HKS_CONDITION_H

#include <stdint.h>

// One-time condition struct, you CAN NOT reset it after notify or notify-all,
// you can only create a new one.
typedef struct HksCondition HksCondition;

#ifdef __cplusplus
extern "C" {
#endif

HksCondition *HksConditionCreate(void);

int32_t HksConditionWait(HksCondition *condition);

int32_t HksConditionNotify(HksCondition *condition);

int32_t HksConditionNotifyAll(HksCondition *condition);

void HksConditionDestroy(HksCondition* condition);

#ifdef __cplusplus
}
#endif
#endif
