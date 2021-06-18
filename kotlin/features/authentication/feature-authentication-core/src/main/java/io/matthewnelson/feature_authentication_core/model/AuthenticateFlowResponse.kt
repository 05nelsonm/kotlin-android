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

import io.matthewnelson.concept_authentication.coordinator.AuthenticationRequest
import io.matthewnelson.concept_authentication.coordinator.AuthenticationResponse
import io.matthewnelson.concept_authentication_core.model.ConfirmUserInputToReset
import io.matthewnelson.concept_authentication_core.model.ConfirmUserInputToSetForFirstTime
import io.matthewnelson.concept_authentication_core.model.UserInput
import io.matthewnelson.concept_authentication_core.AuthenticationManager

sealed class AuthenticateFlowResponse {

    /**
     * Is issued after processing a [AuthenticationRequest.ResetPassword] for the first time via
     * [AuthenticationManager.authenticate] where the user's input was validated against
     * their currently set password.
     *
     * Password reset process:
     *   1          - Confirm current password via [AuthenticationManager.authenticate]
     *   1 response - [PasswordConfirmedForReset] to "fill out"
     *   2          - Input new password and store in [newPasswordToBeSet]
     *   3          - Confirm new password matches [newPasswordToBeSet]
     *   .            via [AuthenticationManager.resetPassword]
     *
     * @param [originalValidatedUserInput] The original, validated [UserInput] (their current password)
     * @param [originalRequest] The original [AuthenticationRequest] being fulfilled.
     * */
    class PasswordConfirmedForReset private constructor(
        private val originalValidatedUserInput: UserInputWriter,
        private val originalRequest: AuthenticationRequest.ResetPassword
    ): AuthenticateFlowResponse(), ConfirmUserInputToReset {

        companion object {
            private val trackerLock = Object()
            private val resetCompletionTracker: Array<Int?> by lazy {
                arrayOfNulls(2)
            }

            /**
             * Will issue a request if it has not been fulfilled yet, otherwise returns null.
             * */
            @JvmSynthetic
            internal fun generate(
                validUserInput: UserInputWriter,
                request: AuthenticationRequest.ResetPassword
            ): PasswordConfirmedForReset? =
                synchronized(trackerLock) {
                    if (resetCompletionTracker.contains(request.hashCode())) {
                        null
                    } else {
                        PasswordConfirmedForReset(validUserInput.clone(), request)
                    }
                }
        }

        /**
         * Call after completion of saving new credentials to inhibit re-issuance when
         * processing request responses.
         * */
        @JvmSynthetic
        internal fun onPasswordResetCompletion() {
            synchronized(trackerLock) {
                for (i in 0 until resetCompletionTracker.lastIndex) {
                    resetCompletionTracker[i] = resetCompletionTracker[i + 1]
                }
                resetCompletionTracker[resetCompletionTracker.lastIndex] = originalRequest.hashCode()
            }
        }

        private var newPasswordToBeSet: UserInputWriter? = null

        @Volatile
        internal var originalValidatedUserInputHasBeenCleared: Boolean = false
            private set

        @Synchronized
        override fun clearOriginalValidatedPassword() {
            originalValidatedUserInputHasBeenCleared = true
            originalValidatedUserInput.clearInput()
        }

        @Volatile
        internal var newPasswordHasBeenCleared: Boolean = false
            private set

        @Synchronized
        override fun clearNewPassword() {
            newPasswordToBeSet?.let { pe ->
                newPasswordHasBeenCleared = true
                pe.clearInput()
            }
        }

        /**
         * Checks the value set for [newPasswordToBeSet] with the final confirmation [UserInput]
         * to ensure it is correct, before actually setting the new password.
         * */
        @JvmSynthetic
        @Synchronized
        internal fun compareNewPasswordWithConfirmationInput(
            confirmationInput: UserInput
        ): Boolean? =
            newPasswordToBeSet?.compare(confirmationInput)

        @JvmSynthetic
        @Synchronized
        internal fun getOriginalValidatedPassword(): UserInputWriter =
            originalValidatedUserInput

        @JvmSynthetic
        @Synchronized
        internal fun getNewPasswordToBeSet(): UserInputWriter? =
            newPasswordToBeSet

        @Synchronized
        @Throws(ClassCastException::class)
        override fun storeNewPasswordToBeSet(newUserInput: UserInput?) {
            this.newPasswordToBeSet?.clearInput()
            this.newPasswordToBeSet = (newUserInput as? UserInputWriter)?.clone()
        }
    }

    /**
     * Issued after processing [AuthenticationRequest.LogIn] where by there is no persisted
     * credentials. User's original input is stored here in [initialUserInput] so they can
     * confirm it once more for correctness.
     *
     * Setting a password for the first time process:
     *   1          - Enter password and try to authenticate via [AuthenticationManager.authenticate]
     *   1 response - No credentials persisted, [ConfirmInputToSetForFirstTime] is issued to "fill out"
     *   2          - Confirm new password matches [initialUserInput] via
     *   .            [AuthenticationManager.setPasswordFirstTime]
     *
     * @param [initialUserInput] original user input before being issued [ConfirmInputToSetForFirstTime]
     * */
    class ConfirmInputToSetForFirstTime private constructor(
        private val initialUserInput: UserInputWriter
    ): AuthenticateFlowResponse(), ConfirmUserInputToSetForFirstTime {

        companion object {
            @JvmSynthetic
            internal fun instantiate(initialUserInput: UserInputWriter): ConfirmInputToSetForFirstTime =
                ConfirmInputToSetForFirstTime(initialUserInput)
        }

        @Volatile
        internal var initialUserInputHasBeenCleared: Boolean = false
            private set

        @Synchronized
        override fun clearInitialUserInput() {
            initialUserInputHasBeenCleared = true
            initialUserInput.clearInput()
        }

        @JvmSynthetic
        @Synchronized
        internal fun compareInitialInputWithConfirmedInput(confirmedUserInput: UserInput): Boolean =
            initialUserInput.compare(confirmedUserInput)

        /**
         * Used within the flow's context under caller's coroutine scope.
         * */
        @JvmSynthetic
        @Synchronized
        internal fun getInitialUserInput(): UserInputWriter =
            initialUserInput
    }

    sealed class Notify: AuthenticateFlowResponse() {
        object DecryptingEncryptionKey: Notify()
        object EncryptingEncryptionKeyWithNewPin: Notify()
        object GeneratingAndEncryptingEncryptionKey: Notify()
    }

    /**
     * Issued after all requests have been fulfilled via user producing a valid password.
     * */
    class Success private constructor(
        val requests: List<AuthenticationResponse>
    ): AuthenticateFlowResponse() {
        companion object {
            @JvmSynthetic
            internal fun instantiate(responses: List<AuthenticationResponse>): Success =
                Success(responses)
        }
    }

    /**
     * Issued after a password input fails to decrypt the encryption key.
     * */
    class WrongPin private constructor(
        val attemptsLeftUntilLockout: Int
    ): AuthenticateFlowResponse() {
        companion object {
            @JvmSynthetic
            internal fun instantiate(attemptsLeftUntilLockout: Int): WrongPin =
                WrongPin(attemptsLeftUntilLockout)
        }
    }

    /**
     * TODO: Must rework the entire error response scructure.
     * */
    sealed class Error: AuthenticateFlowResponse() {

        object RequestListEmpty: Error()
        object FailedToEncryptEncryptionKey: Error()
        object FailedToDecryptEncryptionKey: Error()
        class Unclassified(val e: Exception): Error()

        sealed class Authenticate: Error() {
            object InvalidPasswordEntrySize: Authenticate()
        }

        sealed class ResetPassword: Error() {
            object NewPasswordEntryWasNull: ResetPassword()
            object InvalidNewPasswordEntrySize: ResetPassword()
            object InvalidConfirmedPasswordEntrySize: ResetPassword()
            object NewPinDoesNotMatchConfirmedPassword: ResetPassword()
            object CurrentPasswordEntryIsNotValid: ResetPassword()
            object CredentialsFromPrefsReturnedNull: ResetPassword()
            object CurrentPasswordEntryWasCleared: ResetPassword()
            object NewPasswordEntryWasCleared: ResetPassword()
        }

        sealed class SetPasswordFirstTime: Error() {
            object InvalidNewPasswordEntrySize: SetPasswordFirstTime()
            object NewPasswordDoesNotMatchConfirmedPassword: SetPasswordFirstTime()
            object CredentialsFromPrefsReturnedNull: SetPasswordFirstTime()
            object FailedToStartService: SetPasswordFirstTime()
            object NewPasswordEntryWasCleared: SetPasswordFirstTime()
            object FailedToEncryptTestString: SetPasswordFirstTime()
        }
    }
}
