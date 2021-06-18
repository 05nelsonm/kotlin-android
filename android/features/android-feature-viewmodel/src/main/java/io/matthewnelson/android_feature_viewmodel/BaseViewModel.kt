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

import androidx.lifecycle.ViewModel
import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import io.matthewnelson.concept_views.viewstate.ViewState
import io.matthewnelson.concept_views.viewstate.ViewStateContainer
import io.matthewnelson.concept_views.viewstate.collect
import io.matthewnelson.concept_views.viewstate.value

suspend inline fun <VS: ViewState<VS>> BaseViewModel<VS>.collectViewState(
    crossinline action: suspend (value: VS) -> Unit
): Unit =
    this.viewStateContainer.collect { action(it) }

inline val <VS: ViewState<VS>>BaseViewModel<VS>.currentViewState: VS
    get() = this.viewStateContainer.value

@Suppress("NOTHING_TO_INLINE")
inline fun <VS: ViewState<VS>> BaseViewModel<VS>.updateViewState(viewState: VS) =
    this.viewStateContainer.updateViewState(viewState)

/**
 * Encapsulates a [ViewStateContainer] with a [ViewModel]
 * */
abstract class BaseViewModel<
        VS: ViewState<VS>
        >(val dispatchers: CoroutineDispatchers, initialViewState: VS)
    : ViewModel(), CoroutineDispatchers by dispatchers
{
    @Suppress("RemoveExplicitTypeArguments")
    open val viewStateContainer: ViewStateContainer<VS> by lazy {
        ViewStateContainer<VS>(initialViewState)
    }
}
