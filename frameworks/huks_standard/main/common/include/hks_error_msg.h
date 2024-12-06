/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HKS_ERROR_MSG_H
#define HKS_ERROR_MSG_H

#include <stdint.h>
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksClearThreadErrorMsg(void);

void PrintErrorMsg(void);

void HksLog(uint32_t logLevel, const char *format, ...);

void HksAppendThreadErrMsg(const uint8_t *buff, uint32_t buffLen);

const char *HksGetThreadErrorMsg(void);

uint8_t *HksCopyThreadErrorMsg(void);

uint32_t HksGetThreadErrorMsgLen(void);

#ifdef __cplusplus
}
#endif

#endif /* HKS_ERROR_MSG_H */