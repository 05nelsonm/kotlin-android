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
package io.matthewnelson.k_openssl

import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.clazzes.*
import io.matthewnelson.crypto_common.extensions.encodeToByteArray
import io.matthewnelson.crypto_common.extensions.toByteArray
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import okio.base64.decodeBase64ToArray
import okio.base64.encodeBase64
import org.bouncycastle_ktx.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle_ktx.crypto.params.KeyParameter
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

inline val CharSequence.isSalted: Boolean
    get() = try {
        lines().joinToString("")
            .decodeBase64ToArray()
            ?.copyOfRange(0, 8)
            ?.contentEquals(KOpenSSL.SALTED.encodeToByteArray())
            ?: false
    } catch (e: Exception) {
        false
    }

abstract class KOpenSSL {

    companion object {
        const val SALTED = "Salted__"
    }

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
    abstract suspend fun decrypt(
        password: Password,
        hashIterations: HashIterations,
        encryptedString: EncryptedString,
        dispatcher: CoroutineDispatcher = Dispatchers.Default
    ): UnencryptedString

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
    abstract suspend fun decrypt(
        hashIterations: HashIterations,
        password: Password,
        encryptedString: EncryptedString,
        dispatcher: CoroutineDispatcher = Dispatchers.Default
    ): UnencryptedByteArray

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
    abstract suspend fun encrypt(
        password: Password,
        hashIterations: HashIterations,
        unencryptedString: UnencryptedString,
        dispatcher: CoroutineDispatcher = Dispatchers.Default
    ): EncryptedString

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
    abstract suspend fun encrypt(
        password: Password,
        hashIterations: HashIterations,
        unencryptedByteArray: UnencryptedByteArray,
        dispatcher: CoroutineDispatcher = Dispatchers.Default
    ): EncryptedString

    @Throws(IllegalStateException::class)
    protected open fun decodeEncryptedString(encryptedString: EncryptedString): ByteArray =
        encryptedString.value.lines().joinToString("")
            .decodeBase64ToArray()
            ?: throw IllegalStateException("Could not decode the provided string")

    @Throws(IllegalStateException::class)
    protected open fun encodeCipherText(salt: ByteArray, cipherText: ByteArray): String =
        (SALTED.encodeToByteArray() + salt + cipherText)
            .encodeBase64()
            .replace("(.{64})".toRegex(), "$1\n")

    /**
     * By default uses PKCS5S2 (PBKDF2 HMac Sha256)
     * */
    @Throws(CancellationException::class)
    @OptIn(RawPasswordAccess::class)
    protected open suspend fun getSecretKeyComponents(
        password: Password,
        salt: ByteArray,
        hashIterations: HashIterations
    ): SecretKeyComponents =
        PKCS5S2ParametersGenerator().let { generator ->
            generator.init(password.value.toByteArray(), salt, hashIterations.value)
            try {
                (generator.generateDerivedMacParameters(48 * 8) as KeyParameter).key.let { secretKey ->

                    SecretKeyComponents(
                        // Decryption Key is bytes 0 - 31 of the derived secret key
                        key = secretKey.copyOfRange(0, 32),

                        // Input Vector is bytes 32 - 47 of the derived secret key
                        iv = secretKey.copyOfRange(32, secretKey.size)
                    ).also {
                        secretKey.fill('*'.code.toByte())
                    }

                }
            } finally {
                generator.password?.fill('*'.code.toByte())
            }
        }

    protected open class SecretKeyComponents(
        private val key: ByteArray,
        private val iv: ByteArray
    ) {
        fun getSecretKeySpec(algorithm: String = "AES"): SecretKeySpec =
            SecretKeySpec(key, algorithm)

        fun getIvParameterSpec(): IvParameterSpec =
            IvParameterSpec(iv)

        fun clearValues() {
            key.fill('*'.code.toByte())
            iv.fill('*'.code.toByte())
        }
    }
}
