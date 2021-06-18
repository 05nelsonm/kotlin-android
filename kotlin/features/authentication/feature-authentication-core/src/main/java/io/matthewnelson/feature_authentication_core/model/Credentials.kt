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
package io.matthewnelson.feature_authentication_core.model

import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_encryption_key.EncryptionKeyHandler
import io.matthewnelson.k_openssl.KOpenSSL
import io.matthewnelson.k_openssl.isSalted
import io.matthewnelson.crypto_common.annotations.UnencryptedDataAccess
import io.matthewnelson.crypto_common.clazzes.*

/**
 * [encryptedPrivateKey] is encrypted with the User's PIN + application specified [HashIterations]
 * [encryptedPublicKey] is encrypted with the decrypted [encryptedPrivateKey]
 * [encryptedTestString] is encrypted with the decrypted [encryptedPrivateKey]
 * */
internal class Credentials private constructor(
    private val encryptedPrivateKey: EncryptedString,
    private val encryptedPublicKey: EncryptedString,
    private val encryptedTestString: EncryptedString
) {

    companion object {
        const val ENCRYPTION_KEY_TEST_STRING_VALUE = "There will only ever be 21 million..."
        const val DELIMITER = "|-SAFU-|"
        const val EMPTY = "EMPTY"

        @JvmSynthetic
        fun instantiate(
            encryptedPrivateKey: EncryptedString,
            encryptedPublicKey: EncryptedString,
            encryptionKeyTestString: EncryptedString
        ): Credentials =
            Credentials(
                encryptedPrivateKey,
                encryptedPublicKey,
                encryptionKeyTestString
            )

        @JvmSynthetic
        @Throws(IllegalArgumentException::class)
        fun fromString(string: String): Credentials =
            string.split(DELIMITER).let { list ->
                if (
                    list.size != 3 ||
                    !list[0].isSalted ||
                    !list[1].isSalted ||
                    !list[2].isSalted
                ) {
                    throw IllegalArgumentException(
                        "String value did not meet requirements for creating Credentials"
                    )
                }

                return Credentials(
                    EncryptedString(list[0]),
                    EncryptedString(list[1]),
                    EncryptedString(list[2]),
                )
            }
    }

    @JvmSynthetic
    @Throws(AuthenticationException::class)
    @Suppress("BlockingMethodInNonBlockingContext")
    suspend fun decryptPrivateKey(
        dispatchers: CoroutineDispatchers,
        encryptionKeyHashIterations: HashIterations,
        kOpenSSL: KOpenSSL,
        userInput: UserInputWriter
    ): Password {
        val password = Password(userInput.toCharArray())
        return try {
            val unencryptedByteArray = kOpenSSL.decrypt(
                encryptionKeyHashIterations,
                password,
                encryptedPrivateKey,
                dispatchers.default
            )

            val unencryptedCharArray = unencryptedByteArray.toUnencryptedCharArray()
            unencryptedByteArray.clear()

            @OptIn(UnencryptedDataAccess::class)
            Password(unencryptedCharArray.value)
        } catch (e: Exception) {
            throw AuthenticationException(
                AuthenticateFlowResponse.Error.FailedToDecryptEncryptionKey
            )
        } finally {
            password.clear()
        }
    }



    @JvmSynthetic
    @OptIn(UnencryptedDataAccess::class)
    @Throws(AuthenticationException::class)
    @Suppress("BlockingMethodInNonBlockingContext")
    suspend fun decryptPublicKey(
        dispatchers: CoroutineDispatchers,
        privateKey: Password,
        encryptionKeyHandler: EncryptionKeyHandler,
        kOpenSSL: KOpenSSL
    ): Password {
        return try {
            val unencryptedByteArray = kOpenSSL.decrypt(
                encryptionKeyHandler.getTestStringEncryptHashIterations(privateKey),
                privateKey,
                encryptedPublicKey,
                dispatchers.default
            )

            val unencryptedCharArray = unencryptedByteArray.toUnencryptedCharArray()
            unencryptedByteArray.clear()

            if (unencryptedCharArray.value.size >= EMPTY.length) {
                // check empty
                if (unencryptedCharArray.value.copyOfRange(0, EMPTY.length).joinToString("") == EMPTY) {
                    Password(CharArray(0))
                } else {
                    Password(unencryptedCharArray.value)
                }

            } else {
                Password(unencryptedCharArray.value)
            }
        } catch (e: Exception) {
            throw AuthenticationException(
                AuthenticateFlowResponse.Error.FailedToDecryptEncryptionKey
            )
        }
    }

    @JvmSynthetic
    override fun toString(): String {
        StringBuilder().let { sb ->
            sb.append(encryptedPrivateKey.value)
            sb.append(DELIMITER)
            sb.append(encryptedPublicKey.value)
            sb.append(DELIMITER)
            sb.append(encryptedTestString.value)
            return sb.toString()
        }
    }

    @JvmSynthetic
    @OptIn(UnencryptedDataAccess::class)
    @Suppress("BlockingMethodInNonBlockingContext")
    suspend fun validateTestString(
        dispatchers: CoroutineDispatchers,
        privateKey: Password,
        encryptionKeyHandler: EncryptionKeyHandler,
        kOpenSSL: KOpenSSL
    ): Boolean {
        return try {
            kOpenSSL.decrypt(
                privateKey,
                encryptionKeyHandler.getTestStringEncryptHashIterations(privateKey),
                encryptedTestString,
                dispatchers.default
            ).let { result ->
                result.value == ENCRYPTION_KEY_TEST_STRING_VALUE
            }
        } catch (e: Exception) {
            false
        }
    }
}
