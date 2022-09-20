/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 * @addtogroup huks
 * @{
 *
 * @brief 描述huks向应用提供密钥库能力，包括密钥管理及密钥的密码学操作等功能。
 * 管理的密钥可以由应用导入或者由应用调用HUKS接口生成。
 *
 * @since 9
 * @version 1.0
 */

/**
 * @file native_huks_api.h
 *
 * @brief 声明用于访问huks的API。
 *
 * @since 9
 * @version 1.0
 *
 * @vee OH_Huks_GetSdkVersion
 * @vee OH_Huks_GenerateKey
 * @vee OH_Huks_ImportKey
 * @vee OH_Huks_ImportWrappedKey
 * @vee OH_Huks_ExportPublicKey
 * @vee OH_Huks_DeleteKey
 * @vee OH_Huks_GetKeyParamSet
 * @vee OH_Huks_isKeyExist
 * @vee OH_Huks_Init
 * @vee OH_Huks_Update
 * @vee OH_Huks_Abort
 */

#ifndef _NATIVE_HUKS_API_H_
#define _NATIVE_HUKS_API_H_

#include "native_huks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 获取当前系统sdk版本。
 *
 * @param sdkVersion 用于存储获取到的版本信息。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetSdkVersion(struct OH_Huks_Blob *sdkVersion);

/**
 * @brief 生成密钥。
 *
 * @param keyAlias 表示给要生成的密钥的别名。
 * @param paramSetIn 表示生成密钥需要的TAG。
 * @param paramSetOut 生成密钥为临时类型时存放着密钥数据；非临时类型可为空。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GenerateKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut);

/**
 * @brief 导入明文密钥。
 *
 * @param keyAlias 密钥别名，存放待导入密钥的别名。
 * @param paramSet 导入时所需TAG。
 * @param key 需要导入的加密的密钥数据。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ImportKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *key);

/**
 * @brief 导入加密密钥。
 *
 * @param keyAlias 密钥别名，存放待导入密钥的别名。
 * @param wrappingKeyAlias 密钥别名，对应密钥用于解密加密的密钥数据。
 * @param paramSet 导入时所需TAG。
 * @param key 需要导入的加密的密钥数据。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ImportWrappedKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_Blob *wrappingKeyAlias, const struct OH_Huks_ParamSet *paramSet,
    const struct OH_Huks_Blob *wrappedKeyData);

/**
 * @brief 导出公钥。
 *
 * @param keyAlias 表示要导出公钥对应的密钥别名，应与所用密钥生成时使用的别名相同。
 * @param paramSet 导出公钥需要的TAG。
 * @param key 存放导出的公钥。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_ExportPublicKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *key);

/**
 * @brief 删除密钥。
 *
 * @param keyAlias 表示要删除密钥的别名，应与密钥生成时使用的别名相同。
 * @param paramSet 删除密钥需要的TAG（此处传空）。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DeleteKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 获取密钥的参数集。
 *
 * @param keyAlias 表示要获取参数集的密钥别名
 * @param paramSetIn 表示要获取参数集需要的TAG（此处传空）。
 * @param paramSetOut 表示获取到的输出参数集。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_GetKeyItemParamSet(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSetIn, struct OH_Huks_ParamSet *paramSetOut);

/**
 * @brief 判断密钥是否存在。
 *
 * @param keyAlias 表示要查找的密钥的别名。
 * @param paramSet 表示查询密钥需要的TAG（此处传空）。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_IsKeyItemExist(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet);

/**
 * @brief 获取密钥证书。
 *
 * @param keyAlias 表示要获取证书的密钥的别名。
 * @param paramSet 表示获取密钥证书需要的参数（此处传空）。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_AttestKeyItem(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_CertChain *certChain);

/**
 * @brief init操作密钥接口。
 *
 * @param keyAlias 表示init操作的密钥的别名。
 * @param paramSet 表示init操作的参数集合。
 * @param handle 表示使init、update、finish和abort联系起来的输出特征值。
 * @param token 存放安全访问控制时传回的challenge
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DoInit(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, struct OH_Huks_Blob *handle, struct OH_Huks_Blob *token);

/**
 * @brief update操作密钥接口。
 *
 * @param handle 表示使init、update、finish和abort联系起来的输入特征值。
 * @param paramSet 表示update需要的输入参数集。
 * @param inData 表示要处理的输入数据，如果数据过大，可分片多次调用update。
 * @param outData 表示经过update操作后的输出数据。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DoUpdate(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData);

/**
 * @brief finish操作密钥接口。
 *
 * @param handle 表示使init、update、finish和abort联系起来的输入特征值。
 * @param paramSet 表示finish需要的输入参数集。
 * @param inData 表示要处理的输入数据。
 * @param outData 表示经过finish操作处理后的输出数据。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DoFinish(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *outData);

/**
 * @brief abort操作密钥接口。
 *
 * @param handle 表示使init、update、finish和abort联系起来的输入特征值。
 * @param paramSet 表示abort需要的输入参数集。
 * @return 返回执行的状态代码。
 * @since 9
 * @version 1.0
 */
struct OH_Huks_Result OH_Huks_DoAbort(const struct OH_Huks_Blob *handle,
    const struct OH_Huks_ParamSet *paramSet);

#ifdef __cplusplus
}
#endif

#endif /* NATIVE_HUKS_API_H */
