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

#ifndef NATIVE_HUKS_PARAM_H
#define NATIVE_HUKS_PARAM_H

/**
 * @addtogroup HuksParamSetApi
 * @{
 *
 * @brief 描述HUKS参数集的能力，支持HUKS密钥管理接口的使用，包括初始化参数集、添加参数、构造参数集、释放参数集等HUKS参数集生命周期管理函数，
 * 还包括获取参数、复制参数集、查询参数集、检查是否有效等函数。
 *
 * @syscap SystemCapability.Security.Huks
 * @since 9
 * @version 1.0
 */

/**
 * @file native_huks_param.h
 *
 * @brief 提供参数集构造、使用和销毁的API。
 *
 * @since 9
 * @version 1.0
 */

#include "native_huks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化参数集。
 *
 * @param paramSet 指向要初始化的参数集的指针地址。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示初始化成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_InitParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 添加参数到参数集里面。
 *
 * @param paramSet 指向要被添加参数的参数集的指针。
 * @param params 指向要添加的参数数组的指针。
 * @param paramCnt 待添加参数数组的参数个数。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示添加成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_AddParams(struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Param *params, uint32_t paramCnt);

/**
 * @brief 构造正式的参数集。
 *
 * @param paramSet 指向要被正式构造的参数集的指针地址。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示构建成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_BuildParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 销毁参数集。
 *
 * @param paramSet 指向要被销毁的参数集的指针地址。
 * @since 9
 * @version 1.0
 */
void OH_Huks_FreeParamSet(struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 复制参数集（深拷贝）。
 *
 * @param fromParamSet 指向要被复制的参数集的指针。
 * @param fromParamSetSize 被复制的参数集占用内存的大小。
 * @param paramSet 指向生成新的参数集的指针地址。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示复制成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_CopyParamSet(const struct OH_Huks_ParamSet *fromParamSet,
    uint32_t fromParamSetSize, struct OH_Huks_ParamSet **paramSet);

/**
 * @brief 从参数集中获取参数。
 *
 * @param paramSet 指向参数集的指针。
 * @param tag 要获取的对应参数的值。
 * @param param 指向获取到的参数的指针地址。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示获取成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetParam(const struct OH_Huks_ParamSet *paramSet, uint32_t tag,
    struct OH_Huks_Param **param);

/**
 * @brief 刷新（复制）参数集内Blob类型的数据到参数集内。
 *
 * @param paramSet 指向参数集的指针。
 * @param isCopy 是否要刷新参数集内存中的struct HksBlob型的参数数据。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_FreshParamSet(struct OH_Huks_ParamSet *paramSet, bool isCopy);

/**
 * @brief 检查参数集中的参数是否有效、是否有重复。
 *
 * @param paramSet 指向参数集的指针。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示有效，其他时为无效或者错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsParamSetTagValid(const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 检查参数集大小是否有效。
 *
 * @param paramSet 指向参数集的指针。
 * @param size 参数集占用的内存大小。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示有效，其他时为无效或者错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsParamSetValid(const struct OH_Huks_ParamSet *paramSet, uint32_t size);

/**
 * @brief 比较两个参数是否相同
 *
 * @param baseParam 指向被比较的参数的指针。
 * @param param 指向比较的参数的指针。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时表示相同，其他时为不同或者错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_CheckParamMatch(const struct OH_Huks_Param *baseParam, const struct OH_Huks_Param *param);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HUKS_PARAM_H */
