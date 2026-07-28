/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_JSON_WRAPPER_H
#define HKS_JSON_WRAPPER_H

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <functional>

#include "hks_error_code.h"

struct cJSON;
namespace OHOS {
namespace Security {
namespace Huks {
constexpr int32_t INVALID_ARRAY_SIZE = -1;
constexpr int32_t JSON_MAX_SIZE = 1024 * 1024;
constexpr int32_t JSON_MAX_NESTING_DEPTH = 50;
constexpr int32_t JSON_MAX_OBJECT_COUNT = 1000;
using Var = std::variant<bool, uint8_t, int32_t, uint32_t, int64_t, double, std::string>;

class CommJsonObject {
public:
    CommJsonObject();
    explicit CommJsonObject(cJSON *json, int32_t err = HKS_SUCCESS,
        std::string parentKeyName = "", bool takeOwnership = true);
    CommJsonObject(CommJsonObject &&other) noexcept;
    CommJsonObject(const CommJsonObject &) = delete;
    CommJsonObject &operator = (const CommJsonObject &) = delete;

    static CommJsonObject CreateObject();
    static CommJsonObject CreateArray();
    static CommJsonObject CreateString(const std::string &value);
    static CommJsonObject CreateNumber(double value);
    static CommJsonObject CreateBool(bool value);
    static CommJsonObject CreateNull(int32_t err, std::string errMsg = "");
    
    [[nodiscard]] bool IsNull() const;
    [[nodiscard]] bool IsBool() const;
    [[nodiscard]] bool IsNumber() const;
    [[nodiscard]] bool IsString() const;
    [[nodiscard]] bool IsArray() const;
    [[nodiscard]] bool IsObject() const;
    
    [[nodiscard]] std::pair<int32_t, std::string> ToString() const;
    [[nodiscard]] std::pair<int32_t, double> ToDouble() const;
    [[nodiscard]] std::pair<int32_t, bool> ToBool() const;
    template<typename Type>
    [[nodiscard]] std::pair<int32_t, Type> ToNumber() const
    {
        std::pair<int32_t, double> ret = ToDouble();
        return {ret.first, static_cast<Type>(ret.second)};
    }

    [[nodiscard]] bool HasKey(const std::string &key) const;
    [[nodiscard]] CommJsonObject GetValue(const std::string &key) const;

    [[nodiscard]] bool SetValue(const std::string &key, CommJsonObject &&value);
    [[nodiscard]] bool SetValue(const std::string &key, CommJsonObject &value);

    template <typename T, std::enable_if_t<
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, uint8_t> ||
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, int32_t> ||
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, uint32_t> ||
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, int64_t> ||
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, size_t> ||
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, double>, int> = 0>
    [[nodiscard]] bool SetValue(const std::string &key, T &&value)
    {
        return SetValue(key, CreateNumber(std::forward<T>(value)));
    }

    template <typename T, std::enable_if_t<
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, std::string>, int> = 0>
    [[nodiscard]] bool SetValue(const std::string &key, T &&value)
    {
        return SetValue(key, CreateString(std::forward<T>(value)));
    }

    template <typename T, std::enable_if_t<
        std::is_same_v<std::remove_const_t<std::remove_reference_t<T>>, bool>, int> = 0>
    [[nodiscard]] bool SetValue(const std::string &key, T &&value)
    {
        return SetValue(key, CreateBool(std::forward<T>(value)));
    }

    void RemoveKey(const std::string &key);
    [[nodiscard]] std::vector<std::string> GetKeys() const;

    [[nodiscard]] int32_t ArraySize() const;
    [[nodiscard]] CommJsonObject GetElement(int32_t index) const;
    [[nodiscard]] bool SetElement(int32_t index, const CommJsonObject &value);
    [[nodiscard]] bool AppendElement(const CommJsonObject &value);
    [[nodiscard]] bool AppendElement(CommJsonObject &&value);
    void RemoveElement(int32_t index);

    [[nodiscard]] std::string Serialize(bool formatted = false) const;
    static CommJsonObject Parse(const std::string &jsonString);
    
    CommJsonObject &operator = (CommJsonObject &&other) noexcept;
    CommJsonObject operator[](const std::string &key) const;
    CommJsonObject operator[](int32_t index) const;

    [[nodiscard]] CommJsonObject Clone() const;

    [[nodiscard]] std::vector<uint8_t> SerializeToBytes() const;
    static CommJsonObject DeserializeFromBytes(const std::vector<uint8_t> &bytes);

    [[nodiscard]] static bool AddKeyValueToArray(CommJsonObject &array, const std::string &key, const Var &value);
    [[nodiscard]] static std::pair<int32_t, std::string> MapToJson(const std::map<std::string, Var> &map);
    [[nodiscard]] static std::pair<int32_t, std::map<std::string, Var>> JsonToMap(const std::string &str);
private:
    std::unique_ptr<cJSON, void (*)(cJSON *)> mJson_;
    int32_t err_{};
    const std::string parentKeyName_{};

    [[nodiscard]] bool CheckIsValid() const;
    [[nodiscard]] bool CheckIsObject() const;
    [[nodiscard]] bool CheckIsArray() const;
};

std::pair<int32_t, std::string> U8Vec2Base64Str(const std::vector<uint8_t> &srcBuffer);

std::pair<int32_t, std::vector<uint8_t>> Base64Str2U8Vec(const std::string &base64Str);

constexpr uint8_t MASK_6BIT = 0x3F;
constexpr uint8_t MASK_4BIT = 0x0F;
constexpr uint8_t MASK_2BIT = 0x03;
constexpr uint8_t OFFSET_6BIT = 6;
constexpr uint8_t OFFSET_4BIT = 4;
constexpr uint8_t OFFSET_2BIT = 2;
constexpr uint8_t BASE64_BLOCK_SIZE = 4;
constexpr uint8_t PADDING_MAX_NUM = 2;
constexpr uint8_t NUM2 = 2;
constexpr uint8_t NUM3 = 3;
constexpr uint8_t NUM4 = 4;
const std::string Base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Check JSON structure constraints before parsing.
 *
 * This function performs a lightweight pre-check to validate JSON structure constraints
 * without full syntax parsing. It is designed to quickly reject inputs that would
 * cause issues during parsing, such as:
 * - Excessive size (> 1MB)
 * - Excessive nesting depth (> 50)
 * - Excessive object/array count (> 1000)
 * - Mismatched brackets or unclosed strings
 *
 * Note: This does NOT perform full JSON syntax validation. Complete syntax
 * validation is performed by cJSON_Parse in Parse function.
 *
 * @param jsonString The JSON string to check
 * @return true if all structure constraints are satisfied, false otherwise
 */
bool CheckJsonStructureConstraints(const std::string &jsonString);
}
}
}

#endif