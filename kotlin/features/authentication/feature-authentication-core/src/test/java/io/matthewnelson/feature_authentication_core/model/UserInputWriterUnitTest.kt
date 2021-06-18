package io.matthewnelson.feature_authentication_core.model

import io.matthewnelson.concept_authentication_core.model.UserInput
import io.matthewnelson.feature_authentication_core.AuthenticationCoreManager
import io.matthewnelson.test_feature_authentication_core.AuthenticationCoreDefaultsTestHelper
import io.matthewnelson.test_feature_authentication_core.TestAuthenticationManagerInitializer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.junit.Assert
import org.junit.Test
import java.io.CharArrayWriter

/**
 * See [AuthenticationCoreDefaultsTestHelper]
 * */
class UserInputWriterUnitTest: AuthenticationCoreDefaultsTestHelper() {

    override val testInitializer: TestAuthenticationManagerInitializer =
        TestAuthenticationManagerInitializer(minimumUserInputLength = 4, maximumUserInputLength = 4)

    // Have to call testCoreManager here to initialize it such that the input lengths are
    // set, just like we would if in production.
    private val input: UserInputWriter = testCoreManager.getNewUserInput() as UserInputWriter

    @Test
    fun `input length state flow updates properly when adding and removing characters`() {
        Assert.assertEquals(0, input.inputLengthStateFlow.value)
        input.addCharacter('d') // 1
        Assert.assertEquals(1, input.inputLengthStateFlow.value)
        input.addCharacter('d') // 2
        input.addCharacter('d') // 3
        input.addCharacter('d') // 4
        Assert.assertEquals(4, input.inputLengthStateFlow.value)

        // exceeding the max character length set during initialization throws exception
        // and shouldn't update the state flow
        try {
            input.addCharacter('d') // 4
            Assert.fail()
        } catch (e: IllegalArgumentException) {
            Assert.assertEquals(4, input.inputLengthStateFlow.value)
        }

        input.dropLastCharacter() // 3
        input.dropLastCharacter() // 2
        input.dropLastCharacter() // 1
        input.dropLastCharacter() // 0
        Assert.assertEquals(0, input.inputLengthStateFlow.value)

        // dropping a character should not move state flow below 0
        try {
            input.dropLastCharacter()
            Assert.fail()
        } catch (e: IllegalArgumentException) {
            Assert.assertEquals(0, input.inputLengthStateFlow.value)
        }
    }

    @Test
    fun `compare returns true if hashcode is the same`() {
        Assert.assertTrue(input.compare(input))
    }

    private class NotUserInputWriter: CharArrayWriter(
        AuthenticationCoreManager.maxUserInputLength
    ), UserInput {
        private val _notUserInputWriterStateFlow =
            MutableStateFlow(0)
        override val inputLengthStateFlow: StateFlow<Int>
            get() = _notUserInputWriterStateFlow
        override fun addCharacter(c: Char) {
            append(c)
        }
        override fun clearInput() {
            reset()
            _notUserInputWriterStateFlow.value = 0
        }
        override fun compare(userInput: UserInput): Boolean {
            // not needed
            return false
        }
        override fun dropLastCharacter() {
            if (count > 0) {
                count -= 1
            }
        }
    }

    @Test
    fun `compare returns false if ClassCastException is thrown` () {
        val notUserInputWriter = NotUserInputWriter()

        // both started at 0
        Assert.assertEquals(0, notUserInputWriter.size())
        Assert.assertEquals(0, input.size())

        // both contain same characters & length
        input.addCharacter('d')
        notUserInputWriter.addCharacter('d')
        Assert.assertEquals(input.size(), notUserInputWriter.size())

        // If the exception is not thrown, comparing character for character would
        // go off and return true. This should return false due to throwing of a
        // class cast exception, meaning the UserInput class sent did not originate
        // from AuthenticationCoreManager's getUserInput method.
        Assert.assertFalse(input.compare(notUserInputWriter))
    }

    @Test
    fun `compare returns true if different writer containing same characters is passed`() {
        val newWriter = UserInputWriter.instantiate()

        input.addCharacter('d')
        input.addCharacter('e')
        newWriter.addCharacter('d')
        newWriter.addCharacter('e')
        Assert.assertTrue(input.compare(newWriter))
    }

    @Test
    fun `clear input overwrites the array and resets everything properly`() {
        input.addCharacter('d')
        input.addCharacter('d')
        input.addCharacter('d')
        input.addCharacter('d')
        Assert.assertEquals("dddd", input.toCharArray().joinToString(""))
        input.clearInput()
        Assert.assertEquals("", input.toCharArray().joinToString(""))
        Assert.assertEquals(0, input.size())
        Assert.assertEquals(0, input.inputLengthStateFlow.value)
    }
}