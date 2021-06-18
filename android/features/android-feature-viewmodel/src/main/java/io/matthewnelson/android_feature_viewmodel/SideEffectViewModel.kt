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
package io.matthewnelson.android_feature_viewmodel

import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_views.sideeffect.SideEffect
import io.matthewnelson.concept_views.sideeffect.SideEffectContainer
import io.matthewnelson.concept_views.sideeffect.collect
import io.matthewnelson.concept_views.viewstate.ViewState

suspend inline fun <T, SE: SideEffect<T>, VS: ViewState<VS>> SideEffectViewModel<T, SE, VS>.collectSideEffects(
    crossinline action: suspend (value: SE) -> Unit
): Unit =
    this.sideEffectContainer.collect { action(it) }

suspend inline fun <T, SE: SideEffect<T>, VS: ViewState<VS>> SideEffectViewModel<T, SE, VS>.submitSideEffect(
    sideEffect: SE
) =
    this.sideEffectContainer.submitSideEffect(sideEffect)

/**
 * Adds [SideEffect]s to the [BaseViewModel]
 *
 * @see [SideEffect]
 * @see [SideEffectContainer]
 * */
abstract class SideEffectViewModel<
        T,
        SE: SideEffect<T>,
        VS: ViewState<VS>
        >(dispatchers: CoroutineDispatchers, initialViewState: VS): BaseViewModel<
        VS
        >(dispatchers, initialViewState)
{
    @Suppress("RemoveExplicitTypeArguments")
    open val sideEffectContainer: SideEffectContainer<T, SE> by lazy {
        SideEffectContainer<T, SE>()
    }
}
