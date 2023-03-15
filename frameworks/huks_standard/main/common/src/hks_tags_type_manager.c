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

#include "hks_tags_type_manager.h"

#include "hks_log.h"
#include "hks_type_inner.h"

#undef HKS_ASSIGN_ENUM_VALUE
#define HKS_ASSIGN_ENUM_VALUE(x, y) x,

static const uint32_t HKS_ALG_PARAMS_TAG[] = { HKS_ASSIGN_PARAM_ALG_ENUM HKS_ASSIGN_INNER_PARAM_ALG_VALUE };
static const uint32_t HKS_KEY_FILE_TAGS[] = { HKS_ASSIGN_PARAM_FILE_ENUM };

void HksGetAlgTagsList(uint32_t **tagsList, uint32_t *listSize)
{
    *tagsList = (uint32_t *)HKS_ALG_PARAMS_TAG;
    *listSize = HKS_ARRAY_SIZE(HKS_ALG_PARAMS_TAG);
}

void HksGetKeyFileTagsList(uint32_t **tagsList, uint32_t *listSize)
{
    *tagsList = (uint32_t *)HKS_KEY_FILE_TAGS;
    *listSize = HKS_ARRAY_SIZE(HKS_KEY_FILE_TAGS);
}