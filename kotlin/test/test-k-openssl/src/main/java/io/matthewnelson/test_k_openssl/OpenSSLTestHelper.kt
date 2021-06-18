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
package io.matthewnelson.test_k_openssl

import io.matthewnelson.test_concept_coroutines.CoroutineTestHelper
import org.junit.AfterClass
import org.junit.BeforeClass
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.util.*

/**
 * Requires Linux to run tests and that openssl is installed at /usr/bin/openssl
 *
 * Will setup a test directory at /tmp/junit/KOpenSSLUnitTest
 *
 * See [CoroutineTestHelper]
 * */
abstract class OpenSSLTestHelper: CoroutineTestHelper() {

    companion object {
        var openSSLExe: File? = null
        var testDirectory: File? = null
        var script: File? = null

        @JvmStatic
        @BeforeClass
        fun setupBeforeClassOpenSSLTestHelper() {
            try {
                val openssLExeTemp = File("/usr/bin/", "openssl")
                if (!openssLExeTemp.exists()) {
                    throw IOException(
                        "${openssLExeTemp.absolutePath} is required to be installed to run these tests"
                    )
                } else {
                    openSSLExe = openssLExeTemp
                }

                if (!File("/tmp").isDirectory) {
                    throw IOException(
                        "/tmp directory is needed to run these tests"
                    )
                }

                val testDirectoryTemp = File("/tmp/junit/KOpenSSLUnitTest")
                if (!testDirectoryTemp.exists() && !testDirectoryTemp.mkdirs()) {
                    throw IOException(
                        "Could not create test dirs to run these tests"
                    )
                } else {
                    testDirectory = testDirectoryTemp
                }

                val scriptTemp = File(testDirectoryTemp, "openssl_testing_script.sh")

                // Have to write a script to execute OpenSSL commands b/c OpenSSL
                // has it's own shell that interferes with Process execution.
                scriptTemp.createNewFile()
                scriptTemp.setExecutable(true)

                if (!scriptTemp.exists()) {
                    throw IOException(
                        "${scriptTemp.name} was unable to be created and is needed to run these tests"
                    )
                }

                if (!scriptTemp.canExecute()) {
                    throw IOException(
                        "${scriptTemp.name} was unable to be set executable and is needed to run these tests"
                    )
                } else {
                    script = scriptTemp
                }

                scriptTemp.writeText(
                    "#!/usr/bin/env bash\n\n" +
                            "echo \"$1\" |\n" +
                            "/usr/bin/openssl aes-256-cbc \"$2\" -a -salt -pbkdf2 -iter \"$3\" -k \"$4\"\n"
                )

            } catch (e: Exception) {
                openSSLExe = null
                testDirectory?.deleteRecursively()
                testDirectory = null
                script = null
                println("\n***************************\n\n${e.message}\n\n***************************")
            }
        }

        @JvmStatic
        @AfterClass
        fun tearDownAfterClassOpenSSLTestHelper() {
            testDirectory?.deleteRecursively()
            openSSLExe = null
            testDirectory = null
            script = null
        }

    }

    fun openSSLExecute(
        printOutput: Boolean,
        decrypt: Boolean,
        stringToEcho: String,
        iterations: Int,
        password: String
    ): String? {
        return script?.let { nnScript ->
            val cmds = arrayListOf<String>(
                "bash", "-c",
                nnScript.absolutePath +
                        " \"$stringToEcho\"" +
                        " \"${if (decrypt) "-d" else "-e"}\"" +
                        " \"${iterations}\"" +
                        " \"${password}\""
            )

            if (printOutput)
                println(cmds.joinToString(" "))

            val processBuilder = ProcessBuilder().command(cmds)
            var process: Process? = null
            var inputStreamReader: InputStreamReader? = null
            var errorStreamReader: InputStreamReader? = null
            var inputScanner: Scanner? = null
            var errorScanner: Scanner? = null
            var output = ""

            try {
                process = processBuilder.start()
                inputStreamReader = InputStreamReader(process.inputStream)
                errorStreamReader = InputStreamReader(process.errorStream)
                inputScanner = Scanner(inputStreamReader)
                errorScanner = Scanner(errorStreamReader)
                while (inputScanner.hasNextLine()) {
                    try {
                        output += inputScanner.nextLine()
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                    if (inputScanner.hasNextLine())
                        output += "\n"
                }

                while (errorScanner.hasNextLine()) {
                    println("ERROR: ${errorScanner.nextLine()}")
                }

                if (printOutput)
                    println(output)

            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                inputScanner?.close()
                inputStreamReader?.close()
                errorScanner?.close()
                errorStreamReader?.close()
                process?.destroy()
            }

            output
        }
    }
}
