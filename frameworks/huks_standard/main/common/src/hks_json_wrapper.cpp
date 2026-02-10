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

#include <iostream>
#include <cmath>
#include <utility>
#include <hks_log.h>
#include <hks_template.h>
#include "hks_json_wrapper.h"
#include <cJSON.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace OHOS {
namespace Security {
namespace Huks {

CommJsonObject::CommJsonObject() : mJson_(nullptr, [](cJSON *) {}) {}

CommJsonObject::CommJsonObject(cJSON *json, int32_t err, std::string parentKeyName, bool takeOwnership)
    : mJson_(nullptr, cJSON_Delete), err_(err), parentKeyName_(std::move(parentKeyName))
{
    if (takeOwnership) {
        mJson_.reset(json);
    } else {
        mJson_.reset(cJSON_Duplicate(json, true));
    }
}

CommJsonObject::CommJsonObject(CommJsonObject &&other) noexcept
    : mJson_(std::move(other.mJson_)), err_(other.err_), parentKeyName_(std::move(other.parentKeyName_)) {}

CommJsonObject &CommJsonObject::operator = (CommJsonObject &&other) noexcept
{
    if (this != &other) {
        mJson_ = std::move(other.mJson_);
    }
    return *this;
}

CommJsonObject CommJsonObject::CreateObject()
{
    return CommJsonObject(cJSON_CreateObject());
}

CommJsonObject CommJsonObject::CreateArray()
{
    return CommJsonObject(cJSON_CreateArray());
}

CommJsonObject CommJsonObject::CreateString(const std::string &value)
{
    return CommJsonObject(cJSON_CreateString(value.c_str()));
}

CommJsonObject CommJsonObject::CreateNumber(double value)
{
    return CommJsonObject(cJSON_CreateNumber(value));
}

CommJsonObject CommJsonObject::CreateBool(bool value)
{
    return CommJsonObject(cJSON_CreateBool(static_cast<cJSON_bool>(value)));
}

CommJsonObject CommJsonObject::CreateNull(int32_t err, std::string errMsg)
{
    return CommJsonObject(cJSON_CreateNull(), err, std::move(errMsg));
}

bool CommJsonObject::IsNull() const
{
    return mJson_ == nullptr || cJSON_IsNull(mJson_.get());
}

bool CommJsonObject::IsBool() const
{
    return mJson_ != nullptr && cJSON_IsBool(mJson_.get());
}

bool CommJsonObject::IsNumber() const
{
    return mJson_ != nullptr && cJSON_IsNumber(mJson_.get());
}

bool CommJsonObject::IsString() const
{
    return mJson_ != nullptr && cJSON_IsString(mJson_.get());
}

bool CommJsonObject::IsArray() const
{
    return mJson_ != nullptr && cJSON_IsArray(mJson_.get());
}

bool CommJsonObject::IsObject() const
{
    return mJson_ != nullptr && cJSON_IsObject(mJson_.get());
}

std::pair<int32_t, std::string> CommJsonObject::ToString() const
{
    if (err_ != HKS_SUCCESS) {
        HKS_LOG_E("operate an error json object %" LOG_PUBLIC "d %" LOG_PUBLIC "s", err_, parentKeyName_.c_str());
        return {err_, ""};
    }
    if (!CheckIsValid()) {
        return {HKS_ERROR_NULL_JSON, ""};
    }
    if (!IsString()) {
        HKS_LOG_E("JSON value of %" LOG_PUBLIC "s is not a string", parentKeyName_.c_str());
        return {HKS_ERROR_JSON_NOT_STRING, ""};
    }
    return {HKS_SUCCESS, mJson_->valuestring};
}

std::pair<int32_t, double> CommJsonObject::ToDouble() const
{
    if (err_ != HKS_SUCCESS) {
        HKS_LOG_E("operate an error json object %" LOG_PUBLIC "d %" LOG_PUBLIC "s", err_, parentKeyName_.c_str());
        return {err_, HUGE_VAL};
    }
    if (!CheckIsValid()) {
        return {HKS_ERROR_NULL_JSON, HUGE_VAL};
    }
    if (!IsNumber()) {
        HKS_LOG_E("JSON value of %" LOG_PUBLIC "s is not a number", parentKeyName_.c_str());
        return {HKS_ERROR_JSON_NOT_NUMBER, HUGE_VAL};
    }
    return {HKS_SUCCESS, mJson_->valuedouble};
}

std::pair<int32_t, bool> CommJsonObject::ToBool() const
{
    if (err_ != HKS_SUCCESS) {
        HKS_LOG_E("operate an error json object %" LOG_PUBLIC "d %" LOG_PUBLIC "s", err_, parentKeyName_.c_str());
        return {err_, false};
    }
    if (!CheckIsValid()) {
        return {HKS_ERROR_NULL_JSON, false};
    }
    if (!IsBool()) {
        HKS_LOG_E("JSON value of %" LOG_PUBLIC "s is not a boolean", parentKeyName_.c_str());
        return {HKS_ERROR_JSON_NOT_BOOL, false};
    }
    return {HKS_SUCCESS, cJSON_IsTrue(mJson_.get())};
}

bool CommJsonObject::HasKey(const std::string &key) const
{
    return CheckIsValid() && CheckIsObject() && cJSON_HasObjectItem(mJson_.get(), key.c_str());
}

CommJsonObject CommJsonObject::GetValue(const std::string &key) const
{
    if (!CheckIsValid()) {
        return CreateNull(HKS_ERROR_NULL_JSON);
    }
    if (!CheckIsObject()) {
        return CreateNull(HKS_ERROR_JSON_NOT_OBJECT);
    }
    
    cJSON *item = cJSON_GetObjectItem(mJson_.get(), key.c_str());
    if (item == nullptr) {
        std::string errMsg = "Key not found: " + key;
        HKS_LOG_E("%" LOG_PUBLIC "s", errMsg.c_str());
        return CreateNull(HKS_ERROR_JSON_KEY_NOT_FOUND,  errMsg);
    }
    
    return CommJsonObject(item, HKS_SUCCESS, key, false);
}

bool CommJsonObject::SetValue(const std::string &key, CommJsonObject &&value)
{
    if (!CheckIsValid() || !CheckIsObject()) {
        return false;
    }
    if (value.mJson_) {
        cJSON *item = value.mJson_.release();
        if (!static_cast<bool>(cJSON_AddItemToObject(mJson_.get(), key.c_str(), item))) {
            value.mJson_.reset(item);
            return false;
        }
        value.mJson_.reset(cJSON_CreateNull());
        return true;
    }
    return false;
}

bool CommJsonObject::SetValue(const std::string &key, CommJsonObject &value)
{
    if (!CheckIsValid() || !CheckIsObject()) {
        return false;
    }
    return cJSON_AddItemToObject(mJson_.get(), key.c_str(), cJSON_Duplicate(value.mJson_.get(), true)) != 0;
}

void CommJsonObject::RemoveKey(const std::string &key)
{
    if (CheckIsValid() && CheckIsObject()) {
        cJSON_DeleteItemFromObject(mJson_.get(), key.c_str());
    }
}

std::vector<std::string> CommJsonObject::GetKeys() const
{
    std::vector<std::string> keys;
    if (!CheckIsValid() || !CheckIsObject()) {
        return keys;
    }
    
    cJSON *item = mJson_->child;
    while (item != nullptr) {
        keys.emplace_back(item->string);
        item = item->next;
    }
    
    return keys;
}

int32_t CommJsonObject::ArraySize() const
{
    if (!CheckIsArray()) {
        return INVALID_ARRAY_SIZE;
    }
    return cJSON_GetArraySize(mJson_.get());
}

CommJsonObject CommJsonObject::GetElement(int32_t index) const
{
    if (!CheckIsValid()) {
        return CommJsonObject::CreateNull(HKS_ERROR_NULL_JSON);
    }
    if (!CheckIsArray()) {
        return CommJsonObject::CreateNull(HKS_ERROR_JSON_NOT_ARRAY);
    }
    cJSON *item = cJSON_GetArrayItem(mJson_.get(), index);
    HKS_IF_TRUE_LOGE_RETURN(item == nullptr, CommJsonObject::CreateNull(HKS_ERROR_JSON_ARRAY_INDEX_OUT_OF_BOUNDS,
        std::to_string(index)), "Array index out of bounds")
    return CommJsonObject(item, HKS_SUCCESS, "|array index|" + std::to_string(index) + "|", false);
}

bool CommJsonObject::SetElement(int32_t index, const CommJsonObject &value)
{
    HKS_IF_TRUE_RETURN(!CheckIsValid() || !CheckIsArray(), false)
    return cJSON_ReplaceItemInArray(mJson_.get(), index, cJSON_Duplicate(value.mJson_.get(), true)) != 0;
}

bool CommJsonObject::AppendElement(const CommJsonObject &value)
{
    HKS_IF_TRUE_RETURN(!CheckIsValid() || !CheckIsArray(), false)
    return cJSON_AddItemToArray(mJson_.get(), cJSON_Duplicate(value.mJson_.get(), true)) != 0;
}

bool CommJsonObject::AppendElement(CommJsonObject &&value)
{
    HKS_IF_TRUE_RETURN(!CheckIsValid() || !CheckIsArray(), false)
    cJSON *item = value.mJson_.release();
    if (!static_cast<bool>(cJSON_AddItemToArray(mJson_.get(), item))) {
        value.mJson_.reset(item);
        return false;
    }
    value.mJson_.reset(cJSON_CreateNull());
    return true;
}

void CommJsonObject::RemoveElement(int32_t index)
{
    HKS_IF_TRUE_RETURN_VOID(!CheckIsValid() || !CheckIsArray())
    cJSON_DeleteItemFromArray(mJson_.get(), index);
}

std::string CommJsonObject::Serialize(bool formatted) const
{
    std::string ret = "";
    HKS_IF_TRUE_RETURN(!CheckIsValid(), ret)
    char *jsonStr = formatted ? cJSON_Print(mJson_.get()) : cJSON_PrintUnformatted(mJson_.get());
    HKS_IF_NULL_LOGE_RETURN(jsonStr, ret, "Failed to serialize JSON")
    std::string result(jsonStr);
    free(jsonStr);
    return result;
}

CommJsonObject CommJsonObject::Parse(const std::string &jsonString)
{
    cJSON *json = cJSON_Parse(jsonString.c_str());
    if (json == nullptr) {
        const char *errorPtr = cJSON_GetErrorPtr();
        std::string error = (errorPtr != nullptr) ? std::string(errorPtr) : "Unknown error";
        HKS_LOG_E("cJSON parse error: %" LOG_PUBLIC "s", error.c_str());
        return CreateNull(HKS_ERROR_JSON_PARSE_ERROR, error);
    }
    
    return CommJsonObject(json);
}

CommJsonObject CommJsonObject::operator[](const std::string &key) const
{
    return GetValue(key);
}

CommJsonObject CommJsonObject::operator[](int32_t index) const
{
    return GetElement(index);
}

CommJsonObject CommJsonObject::Clone() const
{
    return CommJsonObject(mJson_ ? cJSON_Duplicate(mJson_.get(), true) : nullptr, err_, parentKeyName_, true);
}

std::vector<uint8_t> CommJsonObject::SerializeToBytes() const
{
    std::string jsonStr = Serialize(false);
    return { jsonStr.begin(), jsonStr.end() };
}

CommJsonObject CommJsonObject::DeserializeFromBytes(const std::vector<uint8_t> &bytes)
{
    std::string jsonStr(bytes.begin(), bytes.end());
    return Parse(jsonStr);
}

bool CommJsonObject::AddKeyValueToArray(CommJsonObject &array, const std::string &key, const Var &value)
{
    CommJsonObject item = CommJsonObject::CreateObject();
    HKS_IF_NOT_TRUE_RETURN(item.SetValue("Key", key), false);
    bool setRet = true;
    std::visit([&](auto&& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, int32_t>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("int32")), setRet = false);
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("uint32")), setRet = false);
        } else if constexpr (std::is_same_v<T, int64_t>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("int64")), setRet = false);
        } else if constexpr (std::is_same_v<T, bool>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("bool")), setRet = false);
        } else if constexpr (std::is_same_v<T, uint8_t>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("uint8")), setRet = false);
        } else if constexpr (std::is_same_v<T, double>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("double")), setRet = false);
        } else if constexpr (std::is_same_v<T, std::string>) {
            HKS_IF_NOT_TRUE_EXCU(item.SetValue("Type", std::string("string")), setRet = false);
        }
        HKS_IF_NOT_TRUE_EXCU(item.SetValue("Value", val), setRet = false);
    },
        value);
    HKS_IF_TRUE_LOGE_RETURN(!setRet, false, "AddKeyValueToArray, but setValue fail")
    return array.AppendElement(item);
}

std::pair<int32_t, std::string> CommJsonObject::MapToJson(const std::map<std::string, Var> &map)
{
    CommJsonObject array = CommJsonObject::CreateArray();
    bool jsonRet = false;
    for (const auto& [k, v] : map) {
        jsonRet = AddKeyValueToArray(array, k, v);
        HKS_IF_TRUE_LOGE_RETURN(!jsonRet, std::make_pair(HKS_JSON_INVAILD, ""),
            "AddKeyValueToArray failed. now key = %" LOG_PUBLIC "s", k.c_str())
    }
    
    return {HKS_SUCCESS, array.Serialize()};
}

std::pair<int32_t, std::map<std::string, Var>> CommJsonObject::JsonToMap(const std::string &str)
{
    std::map<std::string, Var> map {};
    CommJsonObject root = CommJsonObject::Parse(str);
    std::pair<int32_t, std::map<std::string, Var>> invaildRet{HKS_JSON_INVAILD, {}};
    HKS_IF_TRUE_LOGE_RETURN(!root.IsArray(), invaildRet, "Parse the input, but not a array")
    int32_t arrSize = root.ArraySize();
    for (int i = 0; i < arrSize; ++i) {
        CommJsonObject jKey = root.GetElement(i).GetValue("Key");
        CommJsonObject jType = root.GetElement(i).GetValue("Type");
        CommJsonObject jValue = root.GetElement(i).GetValue("Value");
        auto keyRet = jKey.ToString();
        HKS_IF_TRUE_LOGE_BREAK(keyRet.first != HKS_SUCCESS, "get key failed. ret = %" LOG_PUBLIC "d", keyRet.first)
        auto typeRet = jType.ToString();
        HKS_IF_TRUE_LOGE_BREAK(typeRet.first != HKS_SUCCESS, "get key failed. ret = %" LOG_PUBLIC "d", typeRet.first)
        if (typeRet.second == "int32") {
            auto i32number = jValue.ToNumber<int32_t>();
            HKS_IF_TRUE_LOGE_RETURN(i32number.first != HKS_SUCCESS, invaildRet, "value to int32_t fail")
            map[keyRet.second] = i32number.second;
        } else if (typeRet.second == "uint32") {
            auto ui32number = jValue.ToNumber<uint32_t>();
            HKS_IF_TRUE_LOGE_RETURN(ui32number.first != HKS_SUCCESS, invaildRet, "value to uint32_t fail")
            map[keyRet.second] = ui32number.second;
        } else if (typeRet.second == "int64") {
            auto i64number = jValue.ToNumber<int64_t>();
            HKS_IF_TRUE_LOGE_RETURN(i64number.first != HKS_SUCCESS, invaildRet, "value to int64_t fail")
            map[keyRet.second] = i64number.second;
        } else if (typeRet.second == "bool") {
            auto boolRet = jValue.ToBool();
            HKS_IF_TRUE_LOGE_RETURN(boolRet.first != HKS_SUCCESS, invaildRet, "value to bool fail")
            map[keyRet.second] = boolRet.second;
        } else if (typeRet.second == "uint8") {
            auto uint8number = jValue.ToNumber<uint8_t>();
            HKS_IF_TRUE_LOGE_RETURN(uint8number.first != HKS_SUCCESS, invaildRet, "value to uint8_t fail")
            map[keyRet.second] = uint8number.second;
        } else if (typeRet.second == "double") {
            auto doubleRet = jValue.ToDouble();
            HKS_IF_TRUE_LOGE_RETURN(doubleRet.first != HKS_SUCCESS, invaildRet, "value to double fail")
            map[keyRet.second] = doubleRet.second;
        } else if (typeRet.second == "string") {
            auto stringRet = jValue.ToString();
            HKS_IF_TRUE_LOGE_RETURN(stringRet.first != HKS_SUCCESS, invaildRet, "value to string fail")
            map[keyRet.second] = stringRet.second;
        } else {
            return invaildRet;
        }
    }
    return { HKS_SUCCESS, map };
}

bool CommJsonObject::CheckIsValid() const
{
    if (mJson_ == nullptr) {
        HKS_LOG_E("Invaild JSON value");
        return false;
    }
    return true;
}

bool CommJsonObject::CheckIsObject() const
{
    if (!IsObject()) {
        HKS_LOG_E("Invaild value is not an object");
        return false;
    }
    return true;
}

bool CommJsonObject::CheckIsArray() const
{
    if (!IsArray()) {
        HKS_LOG_E("Invaild value is not an array");
        return false;
    }
    return true;
}

std::pair<int32_t, std::string> U8Vec2Base64Str(const std::vector<uint8_t> &srcBuffer)
{
    std::string base64Str;
    if (srcBuffer.empty()) {
        return {HKS_SUCCESS, base64Str};
    }

    const char *base64Table = Base64Table.c_str();
    size_t strLen = srcBuffer.size();
    HKS_IF_TRUE_LOGE_RETURN(strLen > UINT32_MAX || (strLen + NUM2) / NUM3 > UINT32_MAX / NUM4,
        std::make_pair(HKS_ERROR_INVALID_ARGUMENT, ""), "U8Vec2Base64Str: Input too large.")
    uint32_t outputLength = ((strLen + NUM2) / NUM3) * NUM4;
    base64Str.resize(outputLength);
    
    uint32_t strPos = 0;
    uint32_t i = 0;
    for (; i < strLen; i += NUM3) {
        uint8_t byte1 = srcBuffer[i];
        uint8_t byte2 = (i + 1 < strLen) ? srcBuffer[i + 1] : 0;
        uint8_t byte3 = (i + NUM2 < strLen) ? srcBuffer[i + NUM2] : 0;
        
        base64Str[strPos++] = base64Table[(byte1 >> NUM2) & MASK_6BIT];
        base64Str[strPos++] = base64Table[((byte1 & MASK_2BIT) << OFFSET_4BIT) | ((byte2 >> OFFSET_4BIT) & MASK_4BIT)];
        base64Str[strPos++] = base64Table[((byte2 & MASK_4BIT) << OFFSET_2BIT) | ((byte3 >> OFFSET_6BIT) & MASK_2BIT)];
        base64Str[strPos++] = base64Table[(byte3 & MASK_6BIT)];
    }

    if (i - NUM3 + 1 >= strLen) {
        base64Str[strPos - PADDING_MAX_NUM] = '=';
        base64Str[strPos - 1] = '=';
    } else if (i - NUM3 + PADDING_MAX_NUM >= strLen) {
        base64Str[strPos - 1] = '=';
    }
    
    return {HKS_SUCCESS, base64Str};
}

std::pair<int32_t, std::vector<uint8_t>> CheckAndGetInitBuffer(const std::string &base64Str)
{
    std::vector<uint8_t> outBuffer;
    if (base64Str.empty()) {
        outBuffer.clear();
        return {HKS_SUCCESS, outBuffer };
    }
    
    uint32_t strLen = base64Str.size();
    if (strLen % BASE64_BLOCK_SIZE != 0) {
        return {HKS_COMM_BASE64_SIZE_ERROR, outBuffer };
    }
    for (uint32_t i = 0;i < strLen; ++i) {
        char tempChar = base64Str[i];
        if (tempChar != '=' && Base64Table.find(tempChar) == std::string::npos) {
            return {HKS_COMM_BASE64_CHAR_INVAILD, outBuffer };
        }

        if (tempChar == '=' && i != strLen - 1 && i != strLen -NUM2) {
            return {HKS_COMM_BASE64_PADDING_INVAILD, outBuffer };
        }
    }

    uint32_t padding = static_cast<uint32_t>(std::count(base64Str.begin(), base64Str.end(), '='));
    if (padding > PADDING_MAX_NUM) {
        return { HKS_COMM_BASE64_PADDING_INVAILD, outBuffer };
    }
    
    if ((strLen / NUM4) * NUM3 < padding) {
        return { HKS_COMM_BASE64_PADDING_INVAILD, outBuffer };
    }
    outBuffer.resize(static_cast<uint32_t>((strLen / NUM4) * NUM3 -padding));
     
    return {HKS_SUCCESS, outBuffer};
}

std::pair<int32_t, std::vector<uint8_t>> Base64Str2U8Vec(const std::string &base64Str)
{
    auto checkRet = CheckAndGetInitBuffer(base64Str);
    if (checkRet.first != HKS_SUCCESS) {
        return checkRet;
    }
    uint32_t strLen = base64Str.size();
    uint32_t curPos = 0;
    for (uint32_t i = 0; i < strLen; i += NUM4) {
        char char1 = base64Str[i];
        char char2 = base64Str[i + 1];
        char char3 = base64Str[i + NUM2];
        char char4 = base64Str[i + NUM3];

        uint8_t value1 = Base64Table.find(char1);
        uint8_t value2 = Base64Table.find(char2);
        uint8_t value3 = (char3 == '=') ? 0 : Base64Table.find(char3);
        uint8_t value4 = (char4 == '=') ? 0 : Base64Table.find(char4);

        uint8_t byte1 = (value1 << OFFSET_2BIT) | (value2 >> OFFSET_4BIT);
        uint8_t byte2 = ((value2 & MASK_4BIT) << OFFSET_4BIT) | (value3 >> OFFSET_2BIT);
        uint8_t byte3 = ((value3 & MASK_2BIT) << OFFSET_6BIT) | value4;
        if (curPos < checkRet.second.size()) {
            checkRet.second[curPos] = byte1;
            curPos++;
        }
        if (curPos < checkRet.second.size()) {
            checkRet.second[curPos] = byte2;
            curPos++;
        }
        if (curPos < checkRet.second.size()) {
            checkRet.second[curPos] = byte3;
            curPos++;
        }
    }
     
    return {HKS_SUCCESS, checkRet.second};
}

}  // namespace Huks
}  // namespace Security
}  // namespace OHOS