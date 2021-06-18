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
package io.matthewnelson.android_feature_authentication_core.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.matthewnelson.concept_authentication.data.AuthenticationStorage.Companion.CREDENTIALS
import io.matthewnelson.feature_authentication_core.data.AuthenticationCoreStorage
import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

open class AuthenticationCoreStorageAndroid(
    context: Context,
    masterKeyAlias: MasterKeyAlias,
    authenticationSharedPrefsName: AuthenticationSharedPrefsName,
    protected val dispatchers: CoroutineDispatchers
): AuthenticationCoreStorage() {

    protected open val authenticationPrefs: SharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            context.applicationContext,
            authenticationSharedPrefsName.value,
            MasterKey.Builder(context, masterKeyAlias.value)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setUserAuthenticationRequired(false)
                .setRequestStrongBoxBacked(false)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    override suspend fun saveCredentialString(credentialString: CredentialString) {
        withContext(dispatchers.io) {
            authenticationPrefs.edit().putString(CREDENTIALS, credentialString.value)
                .let { editor ->
                    if (!editor.commit()) {
                        editor.apply()
                        delay(100L)
                    }
                }
        }
    }

    override suspend fun retrieveCredentialString(): CredentialString? {
        return withContext(dispatchers.io) {
            authenticationPrefs.getString(CREDENTIALS, null)
        }?.let { string ->
            CredentialString(string)
        }
    }

    override suspend fun getString(key: String, defaultValue: String?): String? {
        return withContext(dispatchers.io) {
            authenticationPrefs.getString(key, defaultValue)
        }
    }

    override suspend fun putString(key: String, value: String?) {
        if (key == CREDENTIALS) {
            throw IllegalArgumentException(
                "The value for key $CREDENTIALS cannot be overwritten from this method"
            )
        }
        withContext(dispatchers.io) {
            authenticationPrefs.edit().putString(key, value)
                .let { editor ->
                    if (!editor.commit()) {
                        editor.apply()
                        delay(100L)
                    }
                }
        }
    }

    override suspend fun removeString(key: String) {
        if (key == CREDENTIALS) {
            throw IllegalArgumentException(
                "The value for key $CREDENTIALS cannot be removed from this method"
            )
        }
        withContext(dispatchers.io) {
            authenticationPrefs.edit().remove(key)
                .let { editor ->
                    if (!editor.commit()) {
                        editor.apply()
                        delay(100L)
                    }
                }
        }
    }
}
