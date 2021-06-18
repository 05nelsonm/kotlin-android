package org.bouncycastle_ktx.util.encoders

object UTF8 {
    // Constants for the categorization of code units
    private const val C_ILL: Byte = 0 //- C0..C1, F5..FF  ILLEGAL octets that should never appear in a UTF-8 sequence
    private const val C_CR1: Byte = 1 //- 80..8F          Continuation range 1
    private const val C_CR2: Byte = 2 //- 90..9F          Continuation range 2
    private const val C_CR3: Byte = 3 //- A0..BF          Continuation range 3
    private const val C_L2A: Byte = 4 //- C2..DF          Leading byte range A / 2-byte sequence
    private const val C_L3A: Byte = 5 //- E0              Leading byte range A / 3-byte sequence
    private const val C_L3B: Byte = 6 //- E1..EC, EE..EF  Leading byte range B / 3-byte sequence
    private const val C_L3C: Byte = 7 //- ED              Leading byte range C / 3-byte sequence
    private const val C_L4A: Byte = 8 //- F0              Leading byte range A / 4-byte sequence
    private const val C_L4B: Byte = 9 //- F1..F3          Leading byte range B / 4-byte sequence
    private const val C_L4C: Byte = 10 //- F4              Leading byte range C / 4-byte sequence

    //  private static final byte C_ASC = 11;           //- 00..7F          ASCII leading byte range
    // Constants for the states of a DFA
    private const val S_ERR: Byte = -2 //- Error state
    private const val S_END: Byte = -1 //- End (or Accept) state
    private const val S_CS1: Byte = 0x00 //- Continuation state 1
    private const val S_CS2: Byte = 0x10 //- Continuation state 2
    private const val S_CS3: Byte = 0x20 //- Continuation state 3
    private const val S_P3A: Byte = 0x30 //- Partial 3-byte sequence state A
    private const val S_P3B: Byte = 0x40 //- Partial 3-byte sequence state B
    private const val S_P4A: Byte = 0x50 //- Partial 4-byte sequence state A
    private const val S_P4B: Byte = 0x60 //- Partial 4-byte sequence state B
    private val firstUnitTable = ShortArray(128)
    private val transitionTable = ByteArray(S_P4B + 16)
    private fun fill(table: ByteArray, first: Int, last: Int, b: Byte) {
        for (i in first..last) {
            table[i] = b
        }
    }

    /**
     * Transcode a UTF-8 encoding into a UTF-16 representation. In the general case the output
     * `utf16` array should be at least as long as the input `utf8` one to handle
     * arbitrary inputs. The number of output UTF-16 code units is returned, or -1 if any errors are
     * encountered (in which case an arbitrary amount of data may have been written into the output
     * array). Errors that will be detected are malformed UTF-8, including incomplete, truncated or
     * "overlong" encodings, and unmappable code points. In particular, no unmatched surrogates will
     * be produced. An error will also result if `utf16` is found to be too small to store the
     * complete output.
     *
     * @param utf8 A non-null array containing a well-formed UTF-8 encoding.
     * @param utf16 A non-null array, at least as long as the `utf8` array in order to ensure
     * the output will fit.
     * @return The number of UTF-16 code units written to `utf16` (beginning from index 0), or
     * else -1 if the input was either malformed or encoded any unmappable characters, or if
     * the `utf16` is too small.
     */
    fun transcodeToUTF16(utf8: ByteArray, utf16: CharArray): Int {
        var i = 0
        var j = 0
        while (i < utf8.size) {
            var codeUnit = utf8[i++]
            if (codeUnit >= 0) {
                if (j >= utf16.size) {
                    return -1
                }
                utf16[j++] = codeUnit.toInt().toChar()
                continue
            }
            val first = firstUnitTable[codeUnit.toInt() and 0x7F]
            var codePoint: Int = first.toInt() ushr 8
            var state = first.toByte()
            while (state >= 0) {
                if (i >= utf8.size) {
                    return -1
                }
                codeUnit = utf8[i++]
                codePoint = codePoint shl 6 or (codeUnit.toInt() and 0x3F)
                state = transitionTable[state + (codeUnit.toInt() and 0xFF ushr 4)]
            }
            if (state == S_ERR) {
                return -1
            }
            if (codePoint <= 0xFFFF) {
                if (j >= utf16.size) {
                    return -1
                }

                // Code points from U+D800 to U+DFFF are caught by the DFA
                utf16[j++] = codePoint.toChar()
            } else {
                if (j >= utf16.size - 1) {
                    return -1
                }

                // Code points above U+10FFFF are caught by the DFA
                utf16[j++] = (0xD7C0 + (codePoint ushr 10)).toChar()
                utf16[j++] = (0xDC00 or (codePoint and 0x3FF)).toChar()
            }
        }
        return j
    }

    init {
        val categories = ByteArray(128)
        fill(categories, 0x00, 0x0F, C_CR1)
        fill(categories, 0x10, 0x1F, C_CR2)
        fill(categories, 0x20, 0x3F, C_CR3)
        fill(categories, 0x40, 0x41, C_ILL)
        fill(categories, 0x42, 0x5F, C_L2A)
        fill(categories, 0x60, 0x60, C_L3A)
        fill(categories, 0x61, 0x6C, C_L3B)
        fill(categories, 0x6D, 0x6D, C_L3C)
        fill(categories, 0x6E, 0x6F, C_L3B)
        fill(categories, 0x70, 0x70, C_L4A)
        fill(categories, 0x71, 0x73, C_L4B)
        fill(categories, 0x74, 0x74, C_L4C)
        fill(categories, 0x75, 0x7F, C_ILL)
        fill(transitionTable, 0, transitionTable.size - 1, S_ERR)
        fill(transitionTable, S_CS1 + 0x8, S_CS1 + 0xB, S_END)
        fill(transitionTable, S_CS2 + 0x8, S_CS2 + 0xB, S_CS1)
        fill(transitionTable, S_CS3 + 0x8, S_CS3 + 0xB, S_CS2)
        fill(transitionTable, S_P3A + 0xA, S_P3A + 0xB, S_CS1)
        fill(transitionTable, S_P3B + 0x8, S_P3B + 0x9, S_CS1)
        fill(transitionTable, S_P4A + 0x9, S_P4A + 0xB, S_CS2)
        fill(transitionTable, S_P4B + 0x8, S_P4B + 0x8, S_CS2)
        val firstUnitMasks =
            byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x1F, 0x0F, 0x0F, 0x0F, 0x07, 0x07, 0x07)
        val firstUnitTransitions =
            byteArrayOf(S_ERR, S_ERR, S_ERR, S_ERR, S_CS1, S_P3A, S_CS2, S_P3B, S_P4A, S_CS3, S_P4B)
        for (i in 0x00..0x7f) {
            val category = categories[i]
            val codePoint = i and firstUnitMasks[category.toInt()].toInt()
            val state = firstUnitTransitions[category.toInt()]
            firstUnitTable[i] = (codePoint shl 8 or state.toInt()).toShort()
        }
    }
}
