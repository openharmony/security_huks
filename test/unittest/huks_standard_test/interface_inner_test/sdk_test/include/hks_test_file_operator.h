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

#ifndef HKS_TEST_FILE_OPERATOR_H
#define HKS_TEST_FILE_OPERATOR_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksIsFileExist(const char *path, const char *fileName);

uint32_t HksFileSize(const char *path, const char *fileName);

int32_t HksFileRead(const char *path, const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size);

int32_t HksFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* HKS_TEST_FILE_OPERATOR_H */
