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

import io.matthewnelson.concept_authentication.data.AuthenticationStorage.Companion.CREDENTIALS
import io.matthewnelson.feature_authentication_core.data.AuthenticationCoreStorage

/**
 * Extend and implement your own overrides if desired.
 * */
open class TestAuthenticationCoreStorage: AuthenticationCoreStorage() {
    val storage = mutableMapOf<String, String?>()

    @Synchronized
    override suspend fun saveCredentialString(credentialString: CredentialString) {
        storage[CREDENTIALS] = credentialString.value
    }

    @Synchronized
    override suspend fun retrieveCredentialString(): CredentialString? {
        return storage[CREDENTIALS]?.let { string ->
            CredentialString(string)
        }
    }

    @Synchronized
    override suspend fun getString(key: String, defaultValue: String?): String? {
        return storage[key] ?: defaultValue
    }

    @Synchronized
    override suspend fun putString(key: String, value: String?) {
        if (key == CREDENTIALS) {
            throw IllegalArgumentException(
                "value stored for key: $CREDENTIALS cannot be overwritten from this method"
            )
        }

        storage[key] = value
    }

    override suspend fun removeString(key: String) {
        if (key == CREDENTIALS) {
            throw IllegalArgumentException(
                "value stored for key: $CREDENTIALS cannot be removed from this method"
            )
        }

        storage.remove(key)
    }
}