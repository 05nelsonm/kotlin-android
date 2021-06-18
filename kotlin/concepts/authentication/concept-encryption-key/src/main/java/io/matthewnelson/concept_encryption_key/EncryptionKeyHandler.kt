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
package io.matthewnelson.concept_encryption_key

import io.matthewnelson.crypto_common.clazzes.HashIterations
import io.matthewnelson.crypto_common.clazzes.Password

abstract class EncryptionKeyHandler {

    /**
     * Work occurs on Dispatchers.Default when this method is called.
     * */
    abstract suspend fun generateEncryptionKey(): EncryptionKey

    @Throws(EncryptionKeyException::class)
    fun storeCopyOfEncryptionKey(privateKey: CharArray, publicKey: CharArray): EncryptionKey {
        return validateEncryptionKey(privateKey, publicKey)
    }

    /**
     * After validation of the key for correctness of your specified parameters,
     * returning [copyAndStoreKey] allows you the ability to clear the character
     * array to mitigate heap dump analysis.
     * */
    @Throws(EncryptionKeyException::class)
    protected abstract fun validateEncryptionKey(privateKey: CharArray, publicKey: CharArray): EncryptionKey

    /**
     * Call from [validateEncryptionKey] if everything checks out.
     * */
    protected fun copyAndStoreKey(privateKey: CharArray, publicKey: CharArray): EncryptionKey =
        EncryptionKey.instantiate(Password(privateKey.copyOf()), Password(publicKey.copyOf()))

    /**
     * The [HashIterations] used to encrypt/decrypt things using the
     * [EncryptionKey] (a strong "password" not requiring a high number of iterations),
     *
     * This return value is *not* the [HashIterations] used to encrypt/decrypt the
     * [EncryptionKey] with the user's password which is then persisted to disk.
     * */
    abstract fun getTestStringEncryptHashIterations(privateKey: Password): HashIterations
}
