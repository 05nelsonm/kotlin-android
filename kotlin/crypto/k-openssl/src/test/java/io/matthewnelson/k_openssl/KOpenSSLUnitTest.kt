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

import io.matthewnelson.crypto_common.annotations.UnencryptedDataAccess
import io.matthewnelson.k_openssl.algos.AES256CBC_PBKDF2_HMAC_SHA256
import io.matthewnelson.crypto_common.clazzes.EncryptedString
import io.matthewnelson.crypto_common.clazzes.HashIterations
import io.matthewnelson.crypto_common.clazzes.Password
import io.matthewnelson.crypto_common.clazzes.UnencryptedString
import io.matthewnelson.test_k_openssl.OpenSSLTestHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runBlockingTest
import kotlinx.coroutines.test.setMain
import okio.base64.encodeBase64
import org.junit.*

///**
// * See [OpenSSLTestHelper]
// * */
//@OptIn(UnencryptedDataAccess::class)
//@Suppress("BlockingMethodInNonBlockingContext")
//class KOpenSSLUnitTest: OpenSSLTestHelper() {
//
//    private companion object {
//        const val PASSWORD = "qk4aX-EfMUa-g4HdF-fjfkU-bbLNx-25739"
//        const val HASH_ITERATIONS = 25739
//        const val UNENCRYPTED_STRING = "Hello World!"
//        const val UNENCRYPTED_MULTI_LINE_STRING = "Hello\nWorld!"
//        const val UNENCRYPTED_VERY_LONG_STRING = "very long string to test formatting because " +
//                "OpenSSL makes a line break every 64 characters"
//    }
//
//    private val aes256cbc: AES256CBC_PBKDF2_HMAC_SHA256 by lazy { AES256CBC_PBKDF2_HMAC_SHA256() }
//
//    @Before
//    fun setup() {
//        Dispatchers.setMain(testDispatcher)
//    }
//
//    @After
//    fun tearDown() {
//        Dispatchers.resetMain()
//        testDispatcher.cleanupTestCoroutines()
//    }
//
//    @Test
//    fun `encrypt with Kotlin is compat with OpenSSL decrypt`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val encryptedResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_STRING),
//                    testDispatcher
//                )
//                val decryptedResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = true,
//                    stringToEcho = encryptedResultFromKotlin.value,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                Assert.assertEquals(UNENCRYPTED_STRING, decryptedResultFromOpenSSL!!)
//
//                val encryptedMultiLineResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_MULTI_LINE_STRING),
//                    testDispatcher
//                )
//                val decryptedMultiLineResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = true,
//                    stringToEcho = encryptedMultiLineResultFromKotlin.value,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_MULTI_LINE_STRING,
//                    decryptedMultiLineResultFromOpenSSL!!
//                )
//
//                val encryptedVeryLongStringResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_VERY_LONG_STRING),
//                    testDispatcher
//                )
//                val decryptedVeryLongStringResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = true,
//                    stringToEcho = encryptedVeryLongStringResultFromKotlin.value,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_VERY_LONG_STRING,
//                    decryptedVeryLongStringResultFromOpenSSL!!
//                )
//            }
//        }
//
//    @Test
//    fun `encrypt with OpenSSL is compat with Kotlin decrypt`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val encryptedResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                val decryptedResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    EncryptedString(encryptedResultFromOpenSSL!!),
//                    testDispatcher
//                )
//                Assert.assertEquals(UNENCRYPTED_STRING, decryptedResultFromKotlin.value)
//
//                val encryptedMultiLineResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_MULTI_LINE_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                val decryptedMultiLineResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    EncryptedString(encryptedMultiLineResultFromOpenSSL!!),
//                    testDispatcher
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_MULTI_LINE_STRING,
//                    decryptedMultiLineResultFromKotlin.value
//                )
//
//                val encryptedVeryLongStringResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_VERY_LONG_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                val decryptedVeryLongStringResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    EncryptedString(encryptedVeryLongStringResultFromOpenSSL!!),
//                    testDispatcher
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_VERY_LONG_STRING,
//                    decryptedVeryLongStringResultFromKotlin.value
//                )
//            }
//        }
//
//    @Test
//    fun `Kotlin encryption and decryption compat`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val encryptedResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_STRING),
//                    testDispatcher
//                )
//                val decryptedResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    encryptedResultFromKotlin,
//                    testDispatcher
//                )
//                Assert.assertEquals(UNENCRYPTED_STRING, decryptedResultFromKotlin.value)
//
//                val encryptedMultiLineResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_MULTI_LINE_STRING),
//                    testDispatcher
//                )
//                val decryptedMultiLineResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    encryptedMultiLineResultFromKotlin,
//                    testDispatcher
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_MULTI_LINE_STRING,
//                    decryptedMultiLineResultFromKotlin.value
//                )
//
//                val encryptedVeryLongStringResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_VERY_LONG_STRING),
//                    testDispatcher
//                )
//                val decryptedVeryLongStringResultFromKotlin = aes256cbc.decrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    encryptedVeryLongStringResultFromKotlin,
//                    testDispatcher
//                )
//                Assert.assertEquals(
//                    UNENCRYPTED_VERY_LONG_STRING,
//                    decryptedVeryLongStringResultFromKotlin.value
//                )
//            }
//        }
//
//    @Test
//    fun `incorrect password throws character coding exception on decrypt`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val failMsg = "CharacterCodingException was not thrown on wrong password decrypt"
//                val encryptedResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_STRING),
//                    testDispatcher
//                )
//
//                try {
//                    aes256cbc.decrypt(
//                        Password((PASSWORD + "7").toCharArray()),
//                        HashIterations(HASH_ITERATIONS),
//                        encryptedResultFromKotlin,
//                        testDispatcher
//                    )
//                    Assert.fail("$failMsg for Kotlin encrypted data")
//                } catch (e: CharacterCodingException) {
//                }
//
//                val encryptedResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                try {
//                    aes256cbc.decrypt(
//                        Password((PASSWORD + "7").toCharArray()),
//                        HashIterations(HASH_ITERATIONS),
//                        EncryptedString(encryptedResultFromOpenSSL!!),
//                        testDispatcher
//                    )
//                    Assert.fail("$failMsg for OpenSSL encrypted data")
//                } catch (e: CharacterCodingException) {}
//            }
//        }
//
//    @Test
//    fun `incorrect hash iterations throws character encoding exception on decrypt`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val failMsg =
//                    "CharacterCodingException was not thrown on wrong hash iteration decrypt"
//                val encryptedResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_STRING),
//                    testDispatcher
//                )
//                try {
//                    aes256cbc.decrypt(
//                        Password(PASSWORD.toCharArray()),
//                        HashIterations(HASH_ITERATIONS - 1),
//                        encryptedResultFromKotlin,
//                        testDispatcher
//                    )
//                    Assert.fail("$failMsg for Kotlin encrypted data")
//                } catch (e: CharacterCodingException) {
//                }
//
//                val encryptedResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                try {
//                    aes256cbc.decrypt(
//                        Password(PASSWORD.toCharArray()),
//                        HashIterations(HASH_ITERATIONS - 1),
//                        EncryptedString(encryptedResultFromOpenSSL!!),
//                        testDispatcher
//                    )
//                    Assert.fail("$failMsg for OpenSSL encrypted data")
//                } catch (e: CharacterCodingException) {
//                }
//            }
//        }
//
//    @Test
//    fun `isSalted method properly detects a salted, encrypted string`() =
//        testDispatcher.runBlockingTest {
//            script?.let {
//                val encryptedResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_STRING),
//                    testDispatcher
//                )
//                val encryptedResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                Assert.assertTrue(encryptedResultFromKotlin.value.isSalted)
//                Assert.assertTrue(encryptedResultFromOpenSSL!!.isSalted)
//                Assert.assertTrue(KOpenSSL.SALTED.toByteArray().encodeBase64().isSalted)
//                Assert.assertFalse(
//                    KOpenSSL.SALTED.dropLast(1).toByteArray().encodeBase64().isSalted
//                )
//                Assert.assertFalse(KOpenSSL.SALTED.isSalted)
//
//                val encryptedMultiLineResultFromKotlin = aes256cbc.encrypt(
//                    Password(PASSWORD.toCharArray()),
//                    HashIterations(HASH_ITERATIONS),
//                    UnencryptedString(UNENCRYPTED_MULTI_LINE_STRING),
//                    testDispatcher
//                )
//                val encryptedMultiLineResultFromOpenSSL = openSSLExecute(
//                    printOutput = false,
//                    decrypt = false,
//                    stringToEcho = UNENCRYPTED_MULTI_LINE_STRING,
//                    iterations = HASH_ITERATIONS,
//                    password = PASSWORD
//                )
//                Assert.assertTrue(encryptedMultiLineResultFromKotlin.value.isSalted)
//                Assert.assertTrue(encryptedMultiLineResultFromOpenSSL!!.isSalted)
//                Assert.assertTrue(KOpenSSL.SALTED.toByteArray().encodeBase64().isSalted)
//                Assert.assertFalse(
//                    KOpenSSL.SALTED.dropLast(1).toByteArray().encodeBase64().isSalted
//                )
//                Assert.assertFalse(KOpenSSL.SALTED.isSalted)
//            }
//        }
//}
