package org.bouncycastle_ktx.util

import org.bouncycastle_ktx.util.encoders.UTF8
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.security.AccessController
import java.security.PrivilegedAction
import java.util.*
import kotlin.collections.ArrayList

/**
 * String utilities.
 */
object Strings {
    private var LINE_SEPARATOR: String? = null
    fun fromUTF8ByteArray(bytes: ByteArray): String {
        val chars = CharArray(bytes.size)
        val len = UTF8.transcodeToUTF16(bytes, chars)
        require(len >= 0) { "Invalid UTF-8 input" }
        return String(chars, 0, len)
    }

    fun toUTF8ByteArray(string: String): ByteArray {
        return toUTF8ByteArray(string.toCharArray())
    }

    fun toUTF8ByteArray(string: CharArray): ByteArray {
        val bOut = ByteArrayOutputStream()
        try {
            toUTF8ByteArray(string, bOut)
        } catch (e: IOException) {
            throw IllegalStateException("cannot encode string to byte array!")
        }
        return bOut.toByteArray()
    }

    @Throws(IOException::class)
    fun toUTF8ByteArray(string: CharArray, sOut: OutputStream) {
        var i = 0
        while (i < string.size) {
            var ch = string[i]
            if (ch.code < 0x0080) {
                sOut.write(ch.code)
            } else if (ch.code < 0x0800) {
                sOut.write(0xc0 or (ch.code shr 6))
                sOut.write(0x80 or (ch.code and 0x3f))
            } else if (ch.code in 0xD800..0xDFFF) {
                // in error - can only happen, if the Java String class has a
                // bug.
                check(i + 1 < string.size) { "invalid UTF-16 codepoint" }
                val W1 = ch
                ch = string[++i]
                val W2 = ch
                // in error - can only happen, if the Java String class has a
                // bug.
                check(W1.code <= 0xDBFF) { "invalid UTF-16 codepoint" }
                val codePoint = (W1.code and 0x03FF shl 10 or (W2.code and 0x03FF)) + 0x10000
                sOut.write(0xf0 or (codePoint shr 18))
                sOut.write(0x80 or (codePoint shr 12 and 0x3F))
                sOut.write(0x80 or (codePoint shr 6 and 0x3F))
                sOut.write(0x80 or (codePoint and 0x3F))
            } else {
                sOut.write(0xe0 or (ch.code shr 12))
                sOut.write(0x80 or (ch.code shr 6 and 0x3F))
                sOut.write(0x80 or (ch.code and 0x3F))
            }
            i++
        }
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    fun toUpperCase(string: String): String {
        var changed = false
        val chars = string.toCharArray()
        for (i in chars.indices) {
            val ch = chars[i]
            if (ch in 'a'..'z') {
                changed = true
                chars[i] = (ch - 'a' + 'A'.code).toChar()
            }
        }
        return if (changed) {
            String(chars)
        } else string
    }

    /**
     * A locale independent version of toLowerCase.
     *
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    fun toLowerCase(string: String): String {
        var changed = false
        val chars = string.toCharArray()
        for (i in chars.indices) {
            val ch = chars[i]
            if (ch in 'A'..'Z') {
                changed = true
                chars[i] = (ch - 'A' + 'a'.code).toChar()
            }
        }
        return if (changed) {
            String(chars)
        } else string
    }

    fun toByteArray(chars: CharArray): ByteArray {
        val bytes = ByteArray(chars.size)
        for (i in bytes.indices) {
            bytes[i] = chars[i].code.toByte()
        }
        return bytes
    }

    fun toByteArray(string: String): ByteArray {
        val bytes = ByteArray(string.length)
        for (i in bytes.indices) {
            val ch = string[i]
            bytes[i] = ch.code.toByte()
        }
        return bytes
    }

    fun toByteArray(s: String, buf: ByteArray, off: Int): Int {
        val count = s.length
        for (i in 0 until count) {
            val c = s[i]
            buf[off + i] = c.code.toByte()
        }
        return count
    }

    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    fun fromByteArray(bytes: ByteArray): String {
        return String(asCharArray(bytes))
    }

    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes 8 bit characters.
     * @return resulting String.
     */
    fun asCharArray(bytes: ByteArray): CharArray {
        val chars = CharArray(bytes.size)
        for (i in chars.indices) {
            chars[i] = (bytes[i].toInt() and 0xff).toChar()
        }
        return chars
    }

    fun split(input: String, delimiter: Char): Array<String> {
        var inputVar = input
        val v: Vector<String> = Vector<String>()
        var moreTokens = true
        var subString: String
        while (moreTokens) {
            val tokenLocation = inputVar.indexOf(delimiter)
            if (tokenLocation > 0) {
                subString = inputVar.substring(0, tokenLocation)
                v.addElement(subString)
                inputVar = inputVar.substring(tokenLocation + 1)
            } else {
                moreTokens = false
                v.addElement(inputVar)
            }
        }
        val res = ArrayList<String>(v.size)
        for (i in res.indices) {
            res[i] = v.elementAt(i) as String
        }
        return res.toTypedArray()
    }

    fun newList(): StringList {
        return StringListImpl()
    }

    fun lineSeparator(): String? {
        return LINE_SEPARATOR
    }

    private class StringListImpl: ArrayList<String>(), StringList {
        override fun add(element: String): Boolean {
            return super.add(element)
        }

        override operator fun set(index: Int, element: String): String {
            return super.set(index, element)
        }

        override fun add(index: Int, element: String) {
            super.add(index, element)
        }

        override fun toStringArray(): Array<String> {
            val strs = ArrayList<String>(this.size)
            for (i in strs.indices) {
                strs[i] = this[i]
            }
            return strs.toTypedArray()
        }

        override fun toStringArray(from: Int, to: Int): Array<String> {
            val strs = ArrayList<String>(to - from)
            var i = from
            while (i != this.size && i != to) {
                strs[i - from] = this[i]
                i++
            }
            return strs.toTypedArray()
        }
    }

    init {
        LINE_SEPARATOR = try {
            AccessController.doPrivileged(
                PrivilegedAction { // the easy way
                    System.getProperty("line.separator")
                })
        } catch (e: Exception) {
            try {
                // the harder way
                String.format("%n")
            } catch (ef: Exception) {
                "\n" // we're desperate use this...
            }
        }
    }
}
