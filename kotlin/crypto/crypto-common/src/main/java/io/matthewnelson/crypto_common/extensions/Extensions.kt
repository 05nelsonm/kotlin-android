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
package io.matthewnelson.crypto_common.extensions

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.Charset

/** securely converts a ByteArray to a CharArray */
@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.toCharArray(fill: Char = '0'): CharArray =
    copyOf().let { copyByteArray ->
        ByteBuffer.wrap(copyByteArray).let { byteBuffer ->
            charset("UTF-8").newDecoder().decode(byteBuffer).let { charBuffer ->
                charBuffer.array().copyOf(charBuffer.limit()).let { charArray ->
                    byteBuffer.array().fill(fill.code.toByte())
                    charBuffer.array().fill(fill)
                    charArray
                }
            }
        }
    }

inline val ByteArray.isValidUTF8: Boolean
    get() = try {
        charset("UTF-8").newDecoder().decode(ByteBuffer.wrap(this))
        true
    } catch (e: CharacterCodingException) {
        false
    }

/** securely converts a CharArray to a ByteArray */
@Suppress("NOTHING_TO_INLINE")
inline fun CharArray.toByteArray(fill: Char = '0'): ByteArray =
    copyOf().let { copyCharArray ->
        CharBuffer.wrap(copyCharArray).let { charBuffer ->
            charset("UTF-8").newEncoder().encode(charBuffer).let { byteBuffer ->
                byteBuffer.array().copyOf(byteBuffer.limit()).let { byteArray ->
                    charBuffer.array().fill(fill)
                    byteBuffer.array().fill(fill.code.toByte())
                    byteArray
                }
            }
        }
    }

@Suppress("NOTHING_TO_INLINE")
inline fun String.encodeToByteArray(charset: Charset = charset("UTF-8")): ByteArray =
    toByteArray(charset)

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.decodeToString(charset: Charset = charset("UTF-8")): String =
    toString(charset)

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.toHex(): String =
    StringBuilder(size * 2).let { hex ->
        for (b in this) {
            hex.append(String.format("%02x", b, 0xFF))
        }
        hex.toString()
    }
