/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_test_file_operator.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hks_param.h"
#include "hks_test_log.h"
#include "hks_test_mem.h"
#include "hks_type.h"

#include "securec.h"

#define HKS_MAX_FILE_NAME_LEN 512
#define REQUIRED_KEY_NOT_AVAILABLE 126

int32_t GetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen);

int32_t IsFileExist(const char *fileName);

int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size);

uint32_t FileSize(const char *fileName);

int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);
