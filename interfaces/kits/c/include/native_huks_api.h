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

#ifndef NATIVE_HUKS_API_H
#define NATIVE_HUKS_API_H

/**
 * @addtogroup HuksKeyApi
 * @{
 *
 * @brief 描述HUKS向应用提供密钥库能力，包括密钥管理及密钥的密码学操作等功能。
 * 管理的密钥可以由应用导入或者由应用调用HUKS接口生成。
 *
 * @syscap SystemCapability.Security.Huks
 * @since 9
 * @version 1.0
 */

/**
 * @file native_huks_api.h
 *
 * @brief 声明用于访问HUKS的API。
 *
 * @since 9
 * @version 1.0
 */

#include "native_huks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 获取当前Huks sdk版本号。
 *
 * @param sdkVersion 用于存放获取到的版本信息（字符串格式）。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetSdkVersion(struct OH_Huks_Blob *sdkVersion);

/**
 * @brief 生成密钥。
 *
 * @param keyAlias 给要生成的密钥的别名，需要保证业务所在进程内唯一，否则会发生覆盖。
 * @param paramSetIn 生成密钥的属性信息的参数集。
 * @param paramSetOut 生成密钥为临时类型时，存放着密钥数据；非临时类型可为空。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GenerateKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut);

/**
 * @brief 导入明文密钥。
 *
 * @param keyAlias 待导入密钥的别名，需要保证业务所在进程内唯一，否则会发生覆盖。
 * @param paramSet 待导入密钥的属性参数。
 * @param key 待导入密钥数据，需符合Huks的格式要求，具体见{@link HuksTypeApi}。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ImportKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *key);

/**
 * @brief 导入密文密钥。
 *
 * @param keyAlias 待导入密钥的别名，需要保证业务所在进程内唯一，否则会发生覆盖。
 * @param wrappingKeyAlias 密钥别名，该对应密钥用于密钥协商出密钥解密待导入密钥。
 * @param paramSet 待导入加密密钥的属性参数。
 * @param wrappedKeyData 需要导入的加密的密钥数据，需要符合Huks定义的格式，具体见{@link OH_Huks_AlgSuite}
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ImportWrappedKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_Blob *wrappingKeyAlias, const struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Blob *wrappedKeyData);

/**
 * @brief 导出公钥。
 *
 * @param keyAlias 待导出公钥的密钥别名，应与所用密钥生成时使用的别名相同。
 * @param paramSet 导出公钥需要的属性参数。
 * @param key 存放导出的公钥。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ExportPublicKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *key);

/**
 * @brief 删除密钥。
 *
 * @param keyAlias 待删除密钥的别名，应与密钥生成时使用的别名相同。
 * @param paramSet 删除密钥需要属性参数（默认传空）。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DeleteKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 获取密钥的属性集。
 *
 * @param keyAlias 要获取参数集的密钥别名。
 * @param paramSetIn 要获取参数集需要的属性TAG（默认传空）。
 * @param paramSetOut 获取到的输出参数集。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时获取成功，其他时为失败。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetKeyItemParamSet(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut);

/**
 * @brief 判断密钥是否存在。
 *
 * @param keyAlias 要查找的密钥的别名。
 * @param paramSet 查询密钥需要的属性TAG（默认传空）。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时密钥存在，
 *         返回{@link OH_Huks_ErrCode#OH_HUKS_ERR_CODE_ITEM_NOT_EXIST}不存在，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsKeyItemExist(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 获取密钥证书链。
 *
 * @param keyAlias 要获取证书的密钥的别名。
 * @param paramSet 获取密钥证书需要的参数。
 * @param certChain 存放输出的密钥证书链。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时获取成功，其他时为错误。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_AttestKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_CertChain *certChain);

/**
 * @brief 初始化密钥会话接口，并获取一个句柄（必选）和挑战值（可选）。
 *
 * @param keyAlias 操作的密钥的别名。
 * @param paramSet 初始化操作的密钥参数集合。
 * @param handle 密钥会话的句柄，后续其他操作时传入该句柄，包括{@link OH_Huks_UpdateSession},
 *               {@link OH_Huks_FinishSession}, {@link OH_Huks_AbortSession}。
 * @param challenge 存放安全访问控制时传回的challenge
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 * @see OH_Huks_UpdateSession
 * @see OH_Huks_FinishSession
 * @see OH_Huks_AbortSession
 */
struct OH_Huks_Result OH_Huks_InitSession(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *handle, struct OH_Huks_Blob *challenge);

/**
 * @brief 分段添加密钥操作的数据并进行相应的密钥操作，输出处理数据。
 *
 * @param handle 密钥会话句柄，通过{@link OH_Huks_InitSession}接口生成的。
 * @param paramSet 密钥操作对应的输入参数集。
 * @param inData 要处理的输入数据，如果数据过大，可分片多次调用。
 * @param outData 经过对应的密钥操作后输出的数据。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 * @see OH_Huks_InitSession
 * @see OH_Huks_FinishSession
 * @see OH_Huks_AbortSession
 */
struct OH_Huks_Result OH_Huks_UpdateSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData);

/**
 * @brief 结束密钥会话并进行相应的密钥操作，输出处理数据。
 *
 * @param handle 密钥会话句柄，通过{@link OH_Huks_InitSession}接口生成的。
 * @param paramSet 密钥操作对应的输入参数集。
 * @param inData 要处理的输入数据。
 * @param outData 经过对应的密钥操作后输出的数据。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 * @see OH_Huks_InitSession
 * @see OH_Huks_UpdateSession
 * @see OH_Huks_AbortSession
 */
struct OH_Huks_Result OH_Huks_FinishSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData);

/**
 * @brief 取消密钥会话。
 *
 * @param handle 密钥会话句柄，通过{@link OH_Huks_InitSession}接口生成的。
 * @param paramSet 取消密钥会话需要的输入参数集（默认传空）。
 * @return 返回{@link OH_Huks_ErrCode#OH_HUKS_SUCCESS}时接口使用成功，其他时为错误。
 * @since 9
 * @version 1.0
 * @see OH_Huks_InitSession
 * @see OH_Huks_UpdateSession
 * @see OH_Huks_FinishSession
 */
struct OH_Huks_Result OH_Huks_AbortSession(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_HUKS_API_H */
