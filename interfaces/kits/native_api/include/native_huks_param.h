/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

/**
 * @file native_huks_param.h
 *
 * @brief 提供参数集构造、使用和销毁的API。
 *
 * @since 9
 * @version 1.0
 *
 * @vee OH_Huks_InitParamSet
 * @vee OH_Huks_AddParams
 * @vee OH_Huks_BuildParamSet
 * @vee OH_Huks_FreeParamSet
 * @vee OH_Huks_CopyParamSet
 * @vee OH_Huks_GetParam
 * @vee OH_Huks_FreshParamSet
 * @vee OH_Huks_isParamSetTagValid
 * @vee OH_Huks_isParamSetValid
 * @vee OH_Huks_CheckParamMatch
 */

#ifndef NATIVE_HUKS_PARAM_H
#define NATIVE_HUKS_PARAM_H

#include "native_huks_type.h"

#define OH_HUKS_PARAM_SET_MAX_SIZE (4 * 1024 * 1024)
#define OH_HUKS_DEFAULT_PARAM_SET_SIZE 512
#define OH_HUKS_DEFAULT_PARAM_CNT ((uint32_t)(OH_HUKS_DEFAULT_PARAM_SET_SIZE / sizeof(struct OH_Huks_Param)))
#define OH_HUKS_TAG_TYPE_MASK (0xF << 28)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化参数集。
 *
 * @param paramSet 表示指向要初始化的参数集的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_InitParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 添加参数到参数集里面。
 *
 * @param paramSet 表示指向要被添加参数的参数集的指针。
 * @param params 表示指向要添加的参数的指针。
 * @param paramCnt 表示要添加参数的个数。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_AddParams(struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Param *params, uint32_t paramCnt);

/**
 * @brief 构造正式的参数集。
 *
 * @param paramSet 表示指向要被正式构造的参数集的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_BuildParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 销毁参数集。
 *
 * @param paramSet 表示指向要被销毁的参数集的指针。
 * @since 9
 * @version 1.0
 */
void OH_Huks_FreeParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 复制参数集。
 *
 * @param fromParamSet 表示指向要被复制的参数集的指针。
 * @param fromParamSetSize 表示被复制的参数集占用内存的大小。
 * @param paramSet 表示指向生成新的参数集的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_CopyParamSet(const struct OH_Huks_ParamSet *fromParamSet,
    uint32_t fromParamSetSize, struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 从参数集中获取参数。
 *
 * @param paramSet 表示指向参数集的指针。
 * @param tag 表示要获取的参数对应的特征值。
 * @param param 表示指向获取到的参数的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetParam(const struct OH_Huks_ParamSet *paramSet, uint32_t tag,
    struct OH_Huks_Param **param);

/**
 * @brief 刷新参数集。
 *
 * @param paramSet 表示指向参数集的指针。
 * @param isCopy 表示是否要刷新参数集内存中的struct HksBlob型的参数数据。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_FreshParamSet(struct OH_Huks_ParamSet *paramSet, bool isCopy);

/**
 * @brief 检查参数集中的参数是否有效、是否有重复。
 *
 * @param paramSet 表示指向参数集的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsParamSetTagValid(const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 检查参数集是否有效。
 *
 * @param paramSet 表示指向参数集的指针。
 * @param size 表示参数集占用的内存大小。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsParamSetValid(const struct OH_Huks_ParamSet *paramSet, uint32_t size);

/**
 * @brief 比较两个参数是否相同
 *
 * @param baseParam 表示指向被比较的参数的指针。
 * @param param 表示指向比较的参数的指针。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_CheckParamMatch(const struct OH_Huks_Param *baseParam, const struct OH_Huks_Param *param);

#ifdef __cplusplus
}
#endif

#endif /* NATIVE_HUKS_PARAM_H */
