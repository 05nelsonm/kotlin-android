package org.bouncycastle_ktx.crypto

import org.bouncycastle_ktx.util.Strings

/**
 * super class for all Password Based Encryption (PBE) parameter generator classes.
 */
@Suppress("FunctionName")
abstract class PBEParametersGenerator
/**
 * base constructor.
 */
protected constructor() {
    /**
     * return the password byte array.
     *
     * @return the password byte array.
     */
    var password: ByteArray? = null
        protected set

    /**
     * return the salt byte array.
     *
     * @return the salt byte array.
     */
    var salt: ByteArray ? = null
        protected set

    /**
     * return the iteration count.
     *
     * @return the iteration count.
     */
    protected var iterationCount = 0

    /**
     * initialise the PBE generator.
     *
     * @param password the password converted into bytes (see below).
     * @param salt the salt to be mixed with the password.
     * @param iterationCount the number of iterations the "mixing" function
     * is to be applied for.
     */
    fun init(
        password: ByteArray,
        salt: ByteArray,
        iterationCount: Int
    ) {
        this.password = password
        this.salt = salt
        this.iterationCount = iterationCount
    }

    /**
     * generate derived parameters for a key of length keySize.
     *
     * @param keySize the length, in bits, of the key required.
     * @return a parameters object representing a key.
     */
    abstract suspend fun generateDerivedParameters(keySize: Int): CipherParameters

    /**
     * generate derived parameters for a key of length keySize, and
     * an initialisation vector (IV) of length ivSize.
     *
     * @param keySize the length, in bits, of the key required.
     * @param ivSize the length, in bits, of the iv required.
     * @return a parameters object representing a key and an IV.
     */
    abstract suspend fun generateDerivedParameters(keySize: Int, ivSize: Int): CipherParameters?

    /**
     * generate derived parameters for a key of length keySize, specifically
     * for use with a MAC.
     *
     * @param keySize the length, in bits, of the key required.
     * @return a parameters object representing a key.
     */
    abstract suspend fun generateDerivedMacParameters(keySize: Int): CipherParameters?

    companion object {
        /**
         * converts a password to a byte array according to the scheme in
         * PKCS5 (ascii, no padding)
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        fun PKCS5PasswordToBytes(
            password: CharArray?
        ): ByteArray {
            return if (password != null) {
                val bytes = ByteArray(password.size)
                for (i in bytes.indices) {
                    bytes[i] = password[i].code.toByte()
                }
                bytes
            } else {
                ByteArray(0)
            }
        }

        /**
         * converts a password to a byte array according to the scheme in
         * PKCS5 (UTF-8, no padding)
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        fun PKCS5PasswordToUTF8Bytes(
            password: CharArray?
        ): ByteArray {
            return if (password != null) {
                Strings.toUTF8ByteArray(password)
            } else {
                ByteArray(0)
            }
        }

        /**
         * converts a password to a byte array according to the scheme in
         * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        fun PKCS12PasswordToBytes(password: CharArray?): ByteArray {
            return if (password != null && password.isNotEmpty()) {
                // +1 for extra 2 pad bytes.
                val bytes = ByteArray((password.size + 1) * 2)
                for (i in password.indices) {
                    bytes[i * 2] = (password[i].code ushr 8).toByte()
                    bytes[i * 2 + 1] = password[i].code.toByte()
                }
                bytes
            } else {
                ByteArray(0)
            }
        }
    }
}
