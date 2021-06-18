/*
*  Copyright 2021 Matthew Nelson
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
* */
package io.matthewnelson.crypto_common.clazzes

import io.matthewnelson.crypto_common.annotations.RawPasswordAccess

@Suppress("NOTHING_TO_INLINE")
@OptIn(RawPasswordAccess::class)
inline fun Password.clear(char: Char = '0') {
    value.fill(char)
}

@Suppress("NOTHING_TO_INLINE")
@OptIn(RawPasswordAccess::class)
inline fun Password.compare(password: Password): Boolean {
    if (value.hashCode() == password.value.hashCode()) {
        return true
    }

    if (value.size != password.value.size) {
        return false
    }

    try {
        for (i in value.indices) {
            if (password.value[i] != value[i]) {
                return false
            }
        }
    } catch (e: Exception) {
        return false
    }

    return true
}

@JvmInline
value class Password(@property: RawPasswordAccess val value: CharArray) {

    @Throws(IllegalAccessException::class)
    override fun toString(): String {
        throw IllegalAccessException(
            "Strings are unable to be modified prior to being garbage collected"
        )
    }
}
