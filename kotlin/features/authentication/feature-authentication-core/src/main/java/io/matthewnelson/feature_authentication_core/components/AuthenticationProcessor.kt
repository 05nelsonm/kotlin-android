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
package io.matthewnelson.feature_authentication_core.components

import app.cash.exhaustive.Exhaustive
import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.feature_authentication_core.data.AuthenticationCoreStorage
import io.matthewnelson.concept_authentication.state.AuthenticationState
import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_encryption_key.EncryptionKey
import io.matthewnelson.concept_encryption_key.EncryptionKeyException
import io.matthewnelson.concept_encryption_key.EncryptionKeyHandler
import io.matthewnelson.feature_authentication_core.AuthenticationCoreManager
import io.matthewnelson.feature_authentication_core.model.*
import io.matthewnelson.feature_authentication_core.model.AuthenticationException
import io.matthewnelson.feature_authentication_core.model.Credentials
import io.matthewnelson.feature_authentication_core.model.UserInputWriter
import io.matthewnelson.k_openssl.KOpenSSL
import io.matthewnelson.k_openssl.algos.AES256CBC_PBKDF2_HMAC_SHA256
import io.matthewnelson.crypto_common.annotations.RawPasswordAccess
import io.matthewnelson.crypto_common.clazzes.*
import io.matthewnelson.crypto_common.extensions.toByteArray
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.withContext

/**
 * TODO: Really need to implement a "login with encryption key" response to better handle
 *  errors.
 * */
internal class AuthenticationProcessor private constructor(
    private val authenticationCoreManager: AuthenticationCoreManager,
    private val dispatchers: CoroutineDispatchers,
    private val encryptionKeyHashIterations: HashIterations,
    val encryptionKeyHandler: EncryptionKeyHandler,
    private val authenticationCoreStorage: AuthenticationCoreStorage,
    private val authenticationManagerInitializer: AuthenticationManagerInitializer
    // TODO: WrongPinLockout
) {

    companion object {
        @JvmSynthetic
        fun instantiate(
            authenticationCoreManager: AuthenticationCoreManager,
            dispatchers: CoroutineDispatchers,
            encryptionKeyHashIterations: HashIterations,
            encryptionKeyHandler: EncryptionKeyHandler,
            authenticationCoreStorage: AuthenticationCoreStorage,
            authenticationManagerInitializer: AuthenticationManagerInitializer
        ): AuthenticationProcessor =
            AuthenticationProcessor(
                authenticationCoreManager,
                dispatchers,
                encryptionKeyHashIterations,
                encryptionKeyHandler,
                authenticationCoreStorage,
                authenticationManagerInitializer
            )
    }

    @JvmSynthetic
    suspend fun isAnEncryptionKeySet(): Boolean =
        authenticationCoreStorage.retrieveCredentials() != null

    ////////////////////
    /// Authenticate ///
    ////////////////////
    @JvmSynthetic
    @OptIn(RawPasswordAccess::class)
    fun authenticate(
        privateKey: Password,
        request: AuthenticationRequest.LogIn
    ): Flow<AuthenticationResponse> = flow {

        authenticationCoreStorage.retrieveCredentials()?.let { credsString ->

            val creds: Credentials? = try {
                Credentials.fromString(credsString)
            } catch (e: IllegalArgumentException) {
                null
            }

            creds?.let { nnCreds ->

                val kOpenssl = AES256CBC_PBKDF2_HMAC_SHA256()

                val validation = nnCreds.validateTestString(
                    dispatchers,
                    privateKey,
                    encryptionKeyHandler,
                    kOpenssl
                )

                if (validation) {

                    try {
                        val publicKey = nnCreds.decryptPublicKey(
                            dispatchers,
                            privateKey,
                            encryptionKeyHandler,
                            kOpenssl
                        )

                        val key = encryptionKeyHandler.storeCopyOfEncryptionKey(
                            privateKey.value,
                            publicKey.value
                        )

//                        authenticationCoreManager.setEncryptionKey(key)
                        authenticationCoreManager.updateAuthenticationState(
                            AuthenticationState.NotRequired,
                            key
                        )

                        flowOf(AuthenticationResponse.Success.Key(request, key))

                    } catch (e: AuthenticationException) {
                        flowOf(AuthenticationResponse.Failure(request))
                    } catch (e: EncryptionKeyException) {
                        flowOf(AuthenticationResponse.Failure(request))
                    }

                } else {

                    flowOf(AuthenticationResponse.Failure(request))

                }

            } ?: flowOf(AuthenticationResponse.Failure(request))

        } ?: flowOf(AuthenticationResponse.Failure(request))

    }

    @JvmSynthetic
    fun authenticate(
        pinEntry: UserInputWriter,
        requests: List<AuthenticationRequest>
    ): Flow<AuthenticateFlowResponse> = flow {
        emit(AuthenticateFlowResponse.Notify.DecryptingEncryptionKey)
        validatePinEntry(AES256CBC_PBKDF2_HMAC_SHA256(), pinEntry).let { response ->
            @Exhaustive
            when (response) {

                is PinValidationResponse.PinEntryIsValid -> {
                    // TODO: Clear WrongPinLockout
                    emitAll(
                        processValidPinEntryResponse(
                            response.encryptionKey,
                            pinEntry,
                            requests
                        )
                    )
                }

                is PinValidationResponse.PinEntryIsNotValid -> {
                    // TODO: WrongPinLockout
                    emit(AuthenticateFlowResponse.WrongPin.instantiate(2))
                }

                is PinValidationResponse.NoCredentials -> {
                    emit(
                        AuthenticateFlowResponse.ConfirmInputToSetForFirstTime
                            .instantiate(pinEntry.clone())
                    )
                }

                is PinValidationResponse.CredentialsFromStringError -> {
//                    response.credentialsString
                    // TODO: Persisted String value was malformed. Add logic to
                    //  handle it.
                }
            }
        }
    }

    @OptIn(RawPasswordAccess::class)
    private suspend fun validatePinEntry(
        kOpenSSL: KOpenSSL,
        pinEntry: UserInputWriter
    ): PinValidationResponse =
        authenticationCoreStorage.retrieveCredentials()?.let { credsString ->
            val creds = try {
                Credentials.fromString(credsString)
            } catch (e: IllegalArgumentException) {
                return PinValidationResponse.CredentialsFromStringError(credsString)
            }

            return try {
                val privateKey = creds.decryptPrivateKey(
                    dispatchers,
                    encryptionKeyHashIterations,
                    kOpenSSL,
                    pinEntry
                )

                val validation = creds.validateTestString(
                    dispatchers,
                    privateKey,
                    encryptionKeyHandler,
                    kOpenSSL
                )

                if (!validation) {
                    privateKey.clear()
                    return PinValidationResponse.PinEntryIsNotValid
                }

                val publicKey = try {
                    creds.decryptPublicKey(
                        dispatchers,
                        privateKey,
                        encryptionKeyHandler,
                        kOpenSSL
                    )
                } catch (e: AuthenticationException) {
                    privateKey.clear()
                    throw e
                }

                val encryptionKey = try {
                    encryptionKeyHandler.storeCopyOfEncryptionKey(
                        privateKey.value,
                        publicKey.value
                    )
                } finally {
                    privateKey.clear()
                    publicKey.clear()
                }

                PinValidationResponse.PinEntryIsValid(encryptionKey)
            } catch (e: AuthenticationException) {
                PinValidationResponse.PinEntryIsNotValid
            } catch (e: EncryptionKeyException) {
                PinValidationResponse.PinEntryIsNotValid
            }

        } ?: PinValidationResponse.NoCredentials

    private sealed class PinValidationResponse {
        class PinEntryIsValid(val encryptionKey: EncryptionKey): PinValidationResponse()
        object PinEntryIsNotValid: PinValidationResponse()
        object NoCredentials: PinValidationResponse()
        class CredentialsFromStringError(val credentialsString: String): PinValidationResponse()
    }

    /////////////////
    /// Reset Pin ///
    /////////////////
    @JvmSynthetic
    @OptIn(RawPasswordAccess::class)
    fun resetPassword(
        resetPasswordResponse: AuthenticateFlowResponse.PasswordConfirmedForReset,
        requests: List<AuthenticationRequest>
    ): Flow<AuthenticateFlowResponse> = flow {
        emit(AuthenticateFlowResponse.Notify.EncryptingEncryptionKeyWithNewPin)

        try {
            val kOpenSSL = AES256CBC_PBKDF2_HMAC_SHA256()

            val key: EncryptionKey = authenticationCoreManager
                .getEncryptionKeyCopy()
                ?: authenticationCoreStorage
                    .retrieveCredentials()
                    ?.let { credsString ->
                        val creds = try {
                            Credentials.fromString(credsString)
                        } catch (e: IllegalArgumentException) {
                            // TODO: Persisted String value was malformed. Add logic to
                            //  handle it.
                            throw AuthenticationException(
                                AuthenticateFlowResponse.Error.FailedToDecryptEncryptionKey
                            )
                        }

                        val privateKey = creds.decryptPrivateKey(
                            dispatchers,
                            encryptionKeyHashIterations,
                            kOpenSSL,
                            resetPasswordResponse.getOriginalValidatedPassword()
                        )

                        val publicKey = try {
                            creds.decryptPublicKey(
                                dispatchers,
                                privateKey,
                                encryptionKeyHandler,
                                kOpenSSL
                            )
                        } catch (e: AuthenticationException) {
                            privateKey.clear()
                            throw e
                        }

                        try {
                            encryptionKeyHandler.storeCopyOfEncryptionKey(
                                privateKey.value,
                                publicKey.value
                            )
                        } catch (e: EncryptionKeyException) {
                            throw AuthenticationException(
                                AuthenticateFlowResponse.Error.FailedToDecryptEncryptionKey
                            )
                        } finally {
                            privateKey.clear()
                            publicKey.clear()
                        }

                    } ?: throw AuthenticationException(
                    AuthenticateFlowResponse.Error.ResetPassword.CredentialsFromPrefsReturnedNull
                )

            val encryptedPrivateKey = encryptPrivateKey(
                key.privateKey,
                resetPasswordResponse.getNewPasswordToBeSet() ?: let {
                    key.privateKey.clear()
                    throw AuthenticationException(
                        AuthenticateFlowResponse.Error.ResetPassword.NewPasswordEntryWasNull
                    )
                },
                kOpenSSL
            )

            val encryptedPublicKey = encryptPublicKey(
                key.privateKey,
                key.publicKey,
                kOpenSSL
            )

            val encryptedTestString = encryptTestString(key.privateKey, kOpenSSL)

            val creds = Credentials.instantiate(
                encryptedPrivateKey,
                encryptedPublicKey,
                encryptedTestString
            )

            if (resetPasswordResponse.newPasswordHasBeenCleared) {
                throw AuthenticationException(
                    AuthenticateFlowResponse.Error.ResetPassword.NewPasswordEntryWasCleared
                )
            }

            authenticationCoreStorage.saveCredentials(creds)

            resetPasswordResponse.onPasswordResetCompletion()

            emitAll(
                processValidPinEntryResponse(
                    key,
                    resetPasswordResponse.getNewPasswordToBeSet() ?: throw AuthenticationException(
                        AuthenticateFlowResponse.Error.ResetPassword.NewPasswordEntryWasNull
                    ),
                    requests
                )
            )
        } catch (e: AuthenticationException) {
            emit(e.flowResponseError)
        } catch (e: Exception) {
            emit(AuthenticateFlowResponse.Error.Unclassified(e))
        }
    }

    //////////////////////////
    /// Set Pin First Time ///
    //////////////////////////
    @JvmSynthetic
    fun setPasswordFirstTime(
        setPasswordFirstTimeResponse: AuthenticateFlowResponse.ConfirmInputToSetForFirstTime,
        requests: List<AuthenticationRequest>
    ): Flow<AuthenticateFlowResponse> = flow {
        try {
            emit(AuthenticateFlowResponse.Notify.GeneratingAndEncryptingEncryptionKey)

            val newKey: EncryptionKey = withContext(dispatchers.default) {
                encryptionKeyHandler.generateEncryptionKey()
            }

            val kOpenssl = AES256CBC_PBKDF2_HMAC_SHA256()

            val initialInput = setPasswordFirstTimeResponse.getInitialUserInput()
            val encryptedEncryptionKey = encryptPrivateKey(
                newKey.privateKey,
                initialInput,
                kOpenssl
            )

            val encryptedPublicKey = encryptPublicKey(
                newKey.privateKey,
                newKey.publicKey,
                kOpenssl
            )

            val encryptedTestString = encryptTestString(newKey.privateKey, kOpenssl)

            if (setPasswordFirstTimeResponse.initialUserInputHasBeenCleared) {
                throw AuthenticationException(AuthenticateFlowResponse.Error.SetPasswordFirstTime.NewPasswordEntryWasCleared)
            }

            val creds = Credentials.instantiate(
                encryptedEncryptionKey,
                encryptedPublicKey,
                encryptedTestString
            )

            authenticationCoreStorage.saveCredentials(creds)

            emitAll(
                processValidPinEntryResponse(newKey, setPasswordFirstTimeResponse.getInitialUserInput(), requests)
            )
        } catch (e: AuthenticationException) {
            emit(e.flowResponseError)
        } catch (e: Exception) {
            emit(AuthenticateFlowResponse.Error.Unclassified(e))
        }
    }

    private suspend fun encryptPrivateKey(
        privateKey: Password,
        userInput: UserInputWriter,
        kOpenSSL: KOpenSSL
    ): EncryptedString {
        Password(userInput.toCharArray()).let { password ->

            @OptIn(RawPasswordAccess::class)
            UnencryptedByteArray(privateKey.value.toByteArray()).let { unencryptedByteArray ->

                return try {
                    kOpenSSL.encrypt(
                        password,
                        encryptionKeyHashIterations,
                        unencryptedByteArray,
                        dispatchers.default
                    )
                } catch (e: Exception) {
                    privateKey.clear()
                    throw AuthenticationException(
                        AuthenticateFlowResponse.Error.FailedToEncryptEncryptionKey
                    )
                } finally {
                    password.clear()
                    unencryptedByteArray.clear()
                }
            }
        }
    }

    @OptIn(RawPasswordAccess::class)
    private suspend fun encryptPublicKey(
        privateKey: Password,
        publicKey: Password,
        kOpenSSL: KOpenSSL
    ): EncryptedString {
        // If public key is empty, replace with "EMPTY" char array.
        val rawPubKey = if (publicKey.value.isEmpty()) {
            Credentials.EMPTY.toCharArray()
        } else {
            publicKey.value
        }

        UnencryptedByteArray(rawPubKey.toByteArray()).let { unencryptedByteArray ->
            return try {
                kOpenSSL.encrypt(
                    privateKey,
                    encryptionKeyHandler.getTestStringEncryptHashIterations(privateKey),
                    unencryptedByteArray,
                    dispatchers.default
                )
            } catch (e: Exception) {
                privateKey.clear()
                publicKey.clear()
                throw AuthenticationException(
                    AuthenticateFlowResponse.Error.FailedToEncryptEncryptionKey
                )
            } finally {
                unencryptedByteArray.clear()
            }
        }
    }

    private suspend fun encryptTestString(
        privateKey: Password,
        kOpenSSL: KOpenSSL
    ): EncryptedString {
        return try {
            kOpenSSL.encrypt(
                privateKey,
                encryptionKeyHandler.getTestStringEncryptHashIterations(privateKey),
                UnencryptedString(Credentials.ENCRYPTION_KEY_TEST_STRING_VALUE),
                dispatchers.default
            )
        } catch (e: Exception) {
            privateKey.clear()
            throw AuthenticationException(
                AuthenticateFlowResponse.Error.SetPasswordFirstTime.FailedToEncryptTestString
            )
        }
    }

    /////////////////
    /// Responses ///
    /////////////////
    private suspend fun processValidPinEntryResponse(
        encryptionKey: EncryptionKey,
        userInput: UserInputWriter,
        requests: List<AuthenticationRequest>
    ): Flow<AuthenticateFlowResponse> = flow {
        ArrayList<AuthenticationResponse>(requests.size).let { responses ->

            var stopProcessing: Boolean = false
            for (request in requests.sortedBy { it.priority }) {
                if (stopProcessing) {
                    break
                }

                @Exhaustive
                when (request) {
                    is AuthenticationRequest.LogIn -> {

//                        authenticationCoreManager.getEncryptionKey() ?: let {
//                            authenticationCoreManager.setEncryptionKey(encryptionKey)
//                        }

                        authenticationCoreManager.updateAuthenticationState(
                            AuthenticationState.NotRequired, encryptionKey
                        )
                        responses.add(
                            AuthenticationResponse.Success.Authenticated(request)
                        )
                    }
                    is AuthenticationRequest.ResetPassword -> {

                        AuthenticateFlowResponse
                            .PasswordConfirmedForReset
                            .generate(userInput, request)
                            ?.let { confirmNewPinEntryToReset ->
                                stopProcessing = true
                                emit(confirmNewPinEntryToReset)
                            } ?: responses.add(
                                    AuthenticationResponse.Success.Authenticated(request)
                                )
                    }
                    is AuthenticationRequest.ConfirmPin -> {
                        try {
                            request
                                .listener
                                ?.doWithConfirmedPassword(Password(userInput.toCharArray()))
                        } catch (e: Exception) {}

                        responses.add(
                            AuthenticationResponse.Success.Authenticated(request)
                        )
                    }
                    is AuthenticationRequest.GetEncryptionKey -> {

//                        authenticationCoreManager.getEncryptionKey() ?: let {
//                            authenticationCoreManager.setEncryptionKey(encryptionKey)
//                        }
                        authenticationCoreManager.updateAuthenticationState(
                            AuthenticationState.NotRequired, encryptionKey
                        )

                        responses.add(
                            AuthenticationResponse.Success.Key(request, encryptionKey)
                        )
                    }
                }
            }

            if (!stopProcessing) {
                emit(AuthenticateFlowResponse.Success.instantiate(responses))
            }
        }
    }.flowOn(dispatchers.default)
}
