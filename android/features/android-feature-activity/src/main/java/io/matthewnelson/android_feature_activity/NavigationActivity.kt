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
package io.matthewnelson.android_feature_activity

import android.os.Bundle
import androidx.annotation.LayoutRes
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.navigation.NavController
import androidx.viewbinding.ViewBinding
import io.matthewnelson.android_feature_viewmodel.util.OnStopSupervisor
import io.matthewnelson.concept_navigation.NavigationRequest
import io.matthewnelson.feature_navigation.NavigationDriver
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

/**
 * Note, [VM] and [NVM] must be the same class (the [ViewModel]), otherwise a
 * RuntimeException will be thrown. This is to enforce that the lifecycle of the
 * [io.matthewnelson.feature_navigation.NavigationDriver] is retained through
 * configuration changes.
 * */
abstract class NavigationActivity<
        VM: ViewModel,
        D: NavigationDriver<NavController>,
        NVM: NavigationViewModel<D>,
        VB: ViewBinding
        >(@LayoutRes layoutId: Int): AppCompatActivity(layoutId)
{
    protected abstract val binding: VB
    protected abstract val navController: NavController
    protected abstract val viewModel: VM

    /**
     * A necessary evil... simply assign `get() = viewModel`
     * */
    protected abstract val navigationViewModel: NVM

    protected val onStopSupervisor: OnStopSupervisor = OnStopSupervisor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        require(viewModel.javaClass.simpleName == navigationViewModel.javaClass.simpleName) {
            "'viewModel' variable is not the same class as 'navigationActivityViewModel'"
        }

        onStopSupervisor.observe(this)
    }

    override fun onStart() {
        super.onStart()
        onStopSupervisor.scope.launch(navigationViewModel.dispatchers.mainImmediate) {
            navigationViewModel
                .navigationDriver
                .navigationRequestSharedFlow
                .collect { request ->
                    if (
                        navigationViewModel
                            .navigationDriver
                            .executeNavigationRequest(navController, request)
                    ) {
                        onPostNavigationRequestExecution(request.first)
                    }
                }
        }
    }

    /**
     * If the request was executed, do something with it before processing the
     * next one. This is helpful if you need something custom, such as starting a
     * new activity with intent extras.
     * */
    protected open suspend fun onPostNavigationRequestExecution(
        request: NavigationRequest<NavController>
    ) {}
}
