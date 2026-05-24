/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "hks_external_error_info.h"
#include "hks_mem.h"
#include "securec.h"
#include <stdlib.h>
#include <string.h>
#include "hks_template.h"

#ifdef __cplusplus
extern "C" {
#endif

static __thread struct HksExternalErrorInfo *g_threadUkeyExtErrInfo = NULL;

void HksAppendThreadExtErrMsg(int32_t errVal, const char *errorDesc)
{
    if (g_threadUkeyExtErrInfo != NULL) {
        HksFreeExternalErrorInfo(g_threadUkeyExtErrInfo);
        g_threadUkeyExtErrInfo = NULL;
    }

    if (errorDesc == NULL || strlen(errorDesc) == 0) {
        g_threadUkeyExtErrInfo = HksCreateExternalErrorInfo(errVal, "");
        return;
    }

    g_threadUkeyExtErrInfo = HksCreateExternalErrorInfo(errVal, errorDesc);
    if (g_threadUkeyExtErrInfo == NULL) {
        HKS_LOG_E("HksAppendThreadExtErrMsg: create errInfo failed");
    }
}

const struct HksExternalErrorInfo* HksGetThreadExtErrMsg(void)
{
    return g_threadUkeyExtErrInfo;
}

struct HksExternalErrorInfo* HksGetAndClearThreadExtErrMsg(void)
{
    struct HksExternalErrorInfo *errInfo = g_threadUkeyExtErrInfo;
    g_threadUkeyExtErrInfo = NULL;
    return errInfo;
}

void HksClearThreadExtErrMsg(void)
{
    if (g_threadUkeyExtErrInfo != NULL) {
        HksFreeExternalErrorInfo(g_threadUkeyExtErrInfo);
        g_threadUkeyExtErrInfo = NULL;
    }
}

struct HksExternalErrorInfo* HksCreateExternalErrorInfo(int32_t errVal, const char *errorDesc)
{
    struct HksExternalErrorInfo *errInfo = (struct HksExternalErrorInfo*)HksMalloc(sizeof(struct HksExternalErrorInfo));
    HKS_IF_NULL_RETURN(errInfo, NULL)
    
    errInfo->errVal = errVal;
    errInfo->errorDesc = NULL;
    errInfo->errorDescLen = 0;

    if (errorDesc == NULL || strlen(errorDesc) == 0) {
        errInfo->errorDesc = (char*)HksMalloc(1);
        if (errInfo->errorDesc == NULL) {
            HKS_FREE(errInfo);
            return NULL;
        }
        errInfo->errorDesc[0] = '\0';
        return errInfo;
    }

    uint32_t descLen = strlen(errorDesc);
    HKS_IF_TRUE_EXCU(descLen > MAX_EXT_ERROR_DESC_LEN, descLen = MAX_EXT_ERROR_DESC_LEN);
    errInfo->errorDesc = (char*)HksMalloc(descLen + 1);
    if (errInfo->errorDesc == NULL) {
        HKS_FREE(errInfo);
        return NULL;
    }

    if (memcpy_s(errInfo->errorDesc, descLen + 1, errorDesc, descLen) != EOK) {
        HKS_FREE(errInfo->errorDesc);
        HKS_FREE(errInfo);
        return NULL;
    }
        
    errInfo->errorDesc[descLen] = '\0';
    errInfo->errorDescLen = descLen;
    
    return errInfo;
}

void HksFreeExternalErrorInfo(struct HksExternalErrorInfo *errInfo)
{
    HKS_IF_NULL_RETURN_VOID(errInfo)
    HKS_FREE(errInfo->errorDesc);
    HKS_FREE(errInfo);
}

#ifdef __cplusplus
}
#endif