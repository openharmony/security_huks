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

#ifndef HKS_ITERATIVE_READER_H
#define HKS_ITERATIVE_READER_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct HksReadFileInfo {
    char *path;
    char *fileName;
};

struct HksReadFileInfoList {
    struct HksReadFileInfo *infos;
    uint32_t occu;
    uint32_t cap;
};

struct HksIterativeReader {
    struct HksReadFileInfoList *fileLists;
    uint32_t curIndex;
};

int32_t HksInitFileIterativeReader(struct HksIterativeReader *reader, char *path);

int32_t HksReadFileWithIterativeReader(struct HksIterativeReader *reader, struct HksBlob *fileContent,
    struct HksBlob *alias, struct HksBlob *path);

#ifdef __cplusplus
}
#endif

#endif // HKS_ITERATIVE_READER_H