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
package io.matthewnelson.concept_views.sideeffect

import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runBlockingTest
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class SideEffectContainerUnitTest: CoroutineTestHelper() {

    object TestSideEffect: SideEffect<String>() {
        var executedString: String? = null
        override suspend fun execute(value: String) {
            executedString = value
        }
    }

    class TestSideEffectContainer: SideEffectContainer<String, TestSideEffect>(
        submissionSuspendTimeOut = 300L
    )

    private val container = TestSideEffectContainer()

    @Before
    fun setUp() {
        setupCoroutineTestHelper()
    }

    @After
    fun tearDown() {
        tearDownCoroutineTestHelper()
    }

    @Test
    fun `sideEffect submission suspends until subscriber is had within registered timeout period`() =
        testDispatcher.runBlockingTest {
            val toCheck= "test1"

            // submit a side effect to test suspension
            val submissionJob = launch {
                container.submitSideEffect(TestSideEffect)
            }

            // delay for less than the timeout
            delay(container.submissionSuspendTimeOut - 50L)

            // ensure collection/execution is had once a subscriber is registered
            var collectionCounter = 0
            val collectionJob = launch {
                container.collect { _ ->
                    TestSideEffect.execute(toCheck)
                    Assert.assertEquals(toCheck, TestSideEffect.executedString)
                    collectionCounter++
                }
            }
            delay(10L)

            // ensure collection/execution was had
            Assert.assertTrue(collectionCounter > 0)

            collectionJob.cancel()
            submissionJob.cancel()
        }

    @Test
    fun `sideEffect submission times out if subscriber is _not_ had within registered timeout period`() =
        testDispatcher.runBlockingTest {
            val toCheck= "test1"

            // submit a side effect to test suspension
            val submissionJob = launch {
                container.submitSideEffect(TestSideEffect)
            }

            // delay for greater than the timeout
            delay(container.submissionSuspendTimeOut + 50L)

            // ensure collection/execution is had once a subscriber is registered
            var collectionCounter = 0
            val collectionJob = launch {
                container.collect { _ ->
                    TestSideEffect.execute(toCheck)
                    Assert.assertEquals(toCheck, TestSideEffect.executedString)
                    collectionCounter++
                }
            }
            delay(10L)

            // ensure collection/execution was _not_ had
            Assert.assertTrue(collectionCounter == 0)
            Assert.assertTrue(submissionJob.isCompleted)

            collectionJob.cancel()
            submissionJob.cancel()
        }
}
