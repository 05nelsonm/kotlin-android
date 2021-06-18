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

import io.matthewnelson.concept_foreground_state.ForegroundState
import io.matthewnelson.feature_authentication_core.AuthenticationCoreManager
import io.matthewnelson.feature_authentication_core.components.AuthenticationManagerInitializer
import io.matthewnelson.crypto_common.clazzes.HashIterations
import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Extend and implement your own overrides if desired.
 * */
open class TestAuthenticationCoreManager<
        S: TestEncryptionKeyHandler,
        V: TestAuthenticationCoreStorage
        >(
    testCoroutineDispatchers: CoroutineTestHelper.TestCoroutineDispatchers,
    testEncryptionKeyHandler: S,
    testAuthenticationCoreStorage: V,
    authenticationManagerInitializer: AuthenticationManagerInitializer,
    encryptionKeyHashIterations: HashIterations = DEFAULT_ENCRYPTION_KEY_HASH_ITERATIONS
): AuthenticationCoreManager(
    testCoroutineDispatchers,
    encryptionKeyHashIterations,
    testEncryptionKeyHandler,
    testAuthenticationCoreStorage,
    authenticationManagerInitializer
) {

    companion object {
        /**
         * The default number of [HashIterations] used to encrypt/decrypt the
         * raw Encryption Key with the user's password
         * */
        val DEFAULT_ENCRYPTION_KEY_HASH_ITERATIONS: HashIterations
            get() = HashIterations(2)
    }

    @Suppress("RemoveExplicitTypeArguments", "PropertyName")
    val _foregroundStateFlow: MutableStateFlow<ForegroundState> by lazy {
        // Is typically initialized in the Foreground.
        MutableStateFlow<ForegroundState>(ForegroundState.Foreground)
    }

    override val foregroundStateFlow: StateFlow<ForegroundState>
        get() = _foregroundStateFlow.asStateFlow()
}