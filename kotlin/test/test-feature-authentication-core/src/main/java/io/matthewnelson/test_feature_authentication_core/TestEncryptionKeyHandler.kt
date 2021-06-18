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
package io.matthewnelson.test_feature_authentication_core

import io.matthewnelson.concept_encryption_key.EncryptionKey
import io.matthewnelson.concept_encryption_key.EncryptionKeyException
import io.matthewnelson.concept_encryption_key.EncryptionKeyHandler
import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.clazzes.HashIterations
import io.matthewnelson.crypto_common.clazzes.Password

/**
 * Extend and implement your own overrides if desired.
 * */
open class TestEncryptionKeyHandler: EncryptionKeyHandler() {

    companion object {
        const val TEST_ENCRYPTION_KEY_STRING = "TEST_ENCRYPTION_KEY_STRING"

        /**
         * The default number of [HashIterations] used to encrypt/decrypt
         * the test string value
         * */
        val DEFAULT_TEST_STRING_ENCRYPT_HASH_ITERATIONS: HashIterations
            get() = HashIterations(1)
    }

    var keysToRestore: RestoreKeyHolder? = null

    class RestoreKeyHolder(val privateKey: Password, val publicKey: Password)

    @OptIn(RawPasswordAccess::class)
    override suspend fun generateEncryptionKey(): EncryptionKey {
        return keysToRestore?.let { keys ->
            copyAndStoreKey(keys.privateKey.value, keys.publicKey.value)
        } ?: copyAndStoreKey(TEST_ENCRYPTION_KEY_STRING.toCharArray(), CharArray(0))
    }

    override fun validateEncryptionKey(privateKey: CharArray, publicKey: CharArray): EncryptionKey {
        val keyString = privateKey.joinToString("")
        if (keysToRestore == null && keyString != TEST_ENCRYPTION_KEY_STRING) {
            throw EncryptionKeyException("EncryptionKey: $keyString != $TEST_ENCRYPTION_KEY_STRING")
        }

        return copyAndStoreKey(privateKey, publicKey)
    }

    override fun getTestStringEncryptHashIterations(privateKey: Password): HashIterations {
        return DEFAULT_TEST_STRING_ENCRYPT_HASH_ITERATIONS
    }
}