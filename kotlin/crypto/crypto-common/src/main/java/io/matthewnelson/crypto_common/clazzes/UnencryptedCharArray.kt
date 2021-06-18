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

import io.matthewnelson.crypto_common.annotations.UnencryptedDataAccess
import io.matthewnelson.crypto_common.extensions.toByteArray

@Suppress("NOTHING_TO_INLINE")
@OptIn(UnencryptedDataAccess::class)
inline fun UnencryptedCharArray.clear(char: Char = '0') {
    value.fill(char)
}

@Suppress("NOTHING_TO_INLINE")
@OptIn(UnencryptedDataAccess::class)
inline fun UnencryptedCharArray.toUnencryptedByteArray(): UnencryptedByteArray =
    UnencryptedByteArray(value.toByteArray())

@Suppress("NOTHING_TO_INLINE")
@OptIn(UnencryptedDataAccess::class)
inline fun UnencryptedCharArray.toUnencryptedString(): UnencryptedString =
    UnencryptedString(value.joinToString(""))

@JvmInline
value class UnencryptedCharArray(@property: UnencryptedDataAccess val value: CharArray) {

    @Throws(IllegalAccessException::class)
    override fun toString(): String {
        throw IllegalAccessException("toUnencryptedString must be used.")
    }
}
