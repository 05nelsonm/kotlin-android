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
package io.matthewnelson.k_openssl.algos

import io.matthewnelson.crypto_common.annotations.UnencryptedDataAccess
import io.matthewnelson.k_openssl.KOpenSSL
import io.matthewnelson.crypto_common.clazzes.*
import io.matthewnelson.crypto_common.extensions.isValidUTF8
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import javax.crypto.*

/**
 * Methods for encrypting/decrypting data in a manner compliant with OpenSSL such that
 * they can be used interchangeably.
 *
 * OpenSSL Encryption from command line:
 *
 *   echo "Hello World!" | openssl aes-256-cbc -e -a -p -salt -pbkdf2 -iter 25000 -k password
 *
 * Terminal output (-p shows the following):
 *   salt=F71F01EC4171ACDF
 *   key=AF9344D72520323D210C440BA015526DABA0D22AD6247DFACF7D3F5B0F724A23
 *   iv =1125D64C744EDE615CE3B8AD55C1581C
 *   U2FsdGVkX1/3HwHsQXGs37PixswoJihPWATaxph4OVQ=
 *
 * OpenSSL Decryption from command line:
 *
 *   echo "U2FsdGVkX1/3HwHsQXGs37PixswoJihPWATaxph4OVQ=" | openssl aes-256-cbc -d -a -p -salt -pbkdf2 -iter 25000 -k password
 * */
@Suppress("ClassName", "SpellCheckingInspection")
class AES256CBC_PBKDF2_HMAC_SHA256: KOpenSSL() {

    /**
     * Decrypts an [EncryptedString] value.
     *
     * @return [UnencryptedString]
     * */
    @Throws(
        ArrayIndexOutOfBoundsException::class,
        BadPaddingException::class,
        CancellationException::class,
        CharacterCodingException::class,
        IllegalArgumentException::class,
        IllegalBlockSizeException::class,
        IllegalStateException::class, // bouncy castle DecoderException wrapper
        IndexOutOfBoundsException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class
    )
    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun decrypt(
        password: Password,
        hashIterations: HashIterations,
        encryptedString: EncryptedString,
        dispatcher: CoroutineDispatcher
    ): UnencryptedString =
        decrypt(
            hashIterations,
            password,
            encryptedString,
            dispatcher
        ).let { unencryptedByteArray ->
            @OptIn(UnencryptedDataAccess::class)
            unencryptedByteArray.toUnencryptedString()
                .also {
                    unencryptedByteArray.clear()
                }
        }

    /**
     * Decrypts an [EncryptedString] value.
     *
     * @return [UnencryptedByteArray]
     * */
    @Throws(
        ArrayIndexOutOfBoundsException::class,
        BadPaddingException::class,
        CancellationException::class,
        CharacterCodingException::class,
        IllegalArgumentException::class,
        IllegalBlockSizeException::class,
        IllegalStateException::class, // bouncy castle DecoderException wrapper
        IndexOutOfBoundsException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class
    )
    override suspend fun decrypt(
        hashIterations: HashIterations,
        password: Password,
        encryptedString: EncryptedString,
        dispatcher: CoroutineDispatcher
    ): UnencryptedByteArray =
        withContext(dispatcher) {
            val encryptedBytes = decodeEncryptedString(encryptedString)

            // Salt is bytes 8 - 15
            val salt = encryptedBytes.copyOfRange(8, 16)

            val components = getSecretKeyComponents(password, salt, hashIterations)

            // Cipher Text is bytes 16 - end of the encrypted bytes
            val cipherText = encryptedBytes.copyOfRange(16, encryptedBytes.size)

            // Decrypt the Cipher Text and manually remove padding after
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                components.getSecretKeySpec(),
                components.getIvParameterSpec()
            )
            val decrypted = try {
                cipher.doFinal(cipherText)
            } finally {
                components.clearValues()
            }

            if (!decrypted.isValidUTF8) {
                decrypted.fill('*'.code.toByte())
                throw CharacterCodingException()
            }

            // Last byte of the decrypted text is the number of padding bytes needed to remove
            UnencryptedByteArray(
                decrypted.copyOfRange(0, decrypted.size - decrypted.last().toInt())
            ).also {
                decrypted.fill('*'.code.toByte())
            }
        }

    /**
     * Encrypts an [UnencryptedString] value.
     *
     * @return [EncryptedString]
     * */
    @Throws(
        ArrayIndexOutOfBoundsException::class,
        AssertionError::class,
        BadPaddingException::class,
        CancellationException::class,
        IllegalArgumentException::class,
        IllegalBlockSizeException::class,
        IllegalStateException::class, // bouncy castle EncoderException wrapper
        IndexOutOfBoundsException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class
    )
    @OptIn(UnencryptedDataAccess::class)
    override suspend fun encrypt(
        password: Password,
        hashIterations: HashIterations,
        unencryptedString: UnencryptedString,
        dispatcher: CoroutineDispatcher
    ): EncryptedString =
        unencryptedString.toUnencryptedByteArray().let { unencryptedByteArray ->
            encrypt(
                password,
                hashIterations,
                unencryptedByteArray,
                dispatcher
            ).also {
                unencryptedByteArray.clear()
            }
        }

    /**
     * Encrypts an [UnencryptedByteArray] value.
     *
     * @return [EncryptedString]
     * */
    @Throws(
        ArrayIndexOutOfBoundsException::class,
        AssertionError::class,
        BadPaddingException::class,
        CancellationException::class,
        IllegalArgumentException::class,
        IllegalBlockSizeException::class,
        IllegalStateException::class, // bouncy castle EncoderException wrapper
        IndexOutOfBoundsException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        InvalidKeySpecException::class,
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class
    )
    @OptIn(UnencryptedDataAccess::class)
    override suspend fun encrypt(
        password: Password,
        hashIterations: HashIterations,
        unencryptedByteArray: UnencryptedByteArray,
        dispatcher: CoroutineDispatcher
    ): EncryptedString =
        withContext(dispatcher) {
            val salt = SecureRandom().generateSeed(8)

            val components = getSecretKeyComponents(password, salt, hashIterations)

            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                components.getSecretKeySpec(),
                components.getIvParameterSpec()
            )
            val cipherText = try {
                cipher.doFinal(unencryptedByteArray.value)
            } finally {
                components.clearValues()
            }

            EncryptedString(encodeCipherText(salt, cipherText))
        }
}
