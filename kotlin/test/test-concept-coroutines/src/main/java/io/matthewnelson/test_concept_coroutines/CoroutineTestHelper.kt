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
package io.matthewnelson.test_concept_coroutines

import io.matthewnelson.concept_coroutines.CoroutineDispatchers
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.TestCoroutineDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain

abstract class CoroutineTestHelper {

    protected val testDispatcher = TestCoroutineDispatcher()

    class TestCoroutineDispatchers(
        override val default: CoroutineDispatcher,
        override val io: CoroutineDispatcher,
        override val main: CoroutineDispatcher,
        override val mainImmediate: CoroutineDispatcher,
        override val unconfined: CoroutineDispatcher
    ): CoroutineDispatchers

    protected val dispatchers: CoroutineDispatchers by lazy {
        TestCoroutineDispatchers(
            testDispatcher,
            testDispatcher,
            testDispatcher,
            testDispatcher,
            testDispatcher
        )
    }

    /**
     * Call from @Before to set application wide dispatchers to that of your test
     * */
    protected fun setupCoroutineTestHelper() {
        Dispatchers.setMain(testDispatcher)
    }

    /**
     * Call from @After if using the [testDispatcher]
     * */
    protected fun tearDownCoroutineTestHelper() {
        Dispatchers.resetMain()
        testDispatcher.cleanupTestCoroutines()
    }
}
