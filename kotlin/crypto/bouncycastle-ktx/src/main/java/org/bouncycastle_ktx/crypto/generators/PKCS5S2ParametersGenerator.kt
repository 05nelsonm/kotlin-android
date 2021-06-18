package org.bouncycastle_ktx.crypto.generators

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.bouncycastle_ktx.crypto.CipherParameters
import org.bouncycastle_ktx.crypto.Digest
import org.bouncycastle_ktx.crypto.Mac
import org.bouncycastle_ktx.crypto.PBEParametersGenerator
import org.bouncycastle_ktx.crypto.digests.SHA256Digest
import org.bouncycastle_ktx.crypto.macs.HMac
import org.bouncycastle_ktx.crypto.params.KeyParameter
import org.bouncycastle_ktx.crypto.params.ParametersWithIV
import kotlin.coroutines.cancellation.CancellationException
import kotlin.experimental.xor

class PKCS5S2ParametersGenerator(digest: Digest = SHA256Digest()): PBEParametersGenerator() {

    private val hMac: Mac
    private val state: ByteArray

    @Suppress("FunctionName")
    @Throws(CancellationException::class, IllegalArgumentException::class)
    private suspend fun F(
        S: ByteArray?,
        c: Int,
        iBuf: ByteArray,
        out: ByteArray,
        outOff: Int
    ) {
        require(c != 0) { "iteration count must be at least 1." }
        if (S != null) {
            hMac.update(S, 0, S.size)
        }
        hMac.update(iBuf, 0, iBuf.size)
        hMac.doFinal(state, 0)
        System.arraycopy(state, 0, out, outOff, state.size)
        for (count in 1 until c) {
            currentCoroutineContext().ensureActive()
            hMac.update(state, 0, state.size)
            hMac.doFinal(state, 0)
            for (j in state.indices) {
                out[outOff + j] = out[outOff + j] xor state[j]
            }
        }
    }

    @Throws(
        CancellationException::class,
        IllegalArgumentException::class,
        NullPointerException::class
    )
    private suspend fun generateDerivedKey(dkLen: Int): ByteArray {
        val hLen = hMac.getMacSize()
        val l = (dkLen + hLen - 1) / hLen
        val iBuf = ByteArray(4)
        val outBytes = ByteArray(l * hLen)
        var outPos = 0
        val param: CipherParameters = KeyParameter(
            password ?: throw NullPointerException("Password has yet to be initialized")
        )
        hMac.init(param)
        for (i in 1..l) {
            // Increment the value in 'iBuf'
            var pos = 3
            while (++iBuf[pos] == 0.toByte()) {
                --pos
            }
            F(salt, iterationCount, iBuf, outBytes, outPos)
            outPos += hLen
        }
        return outBytes
    }

    /**
     * Generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    @Throws(
        CancellationException::class,
        IllegalArgumentException::class
    )
    override suspend fun generateDerivedParameters(keySize: Int): CipherParameters {
        var keySizeVar = keySize
        keySizeVar /= 8
        val dKey = generateDerivedKey(keySizeVar)
        return KeyParameter(dKey, 0, keySizeVar)
    }

    /**
     * Generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param keySize the size of the key we want (in bits)
     * @param ivSize the size of the iv we want (in bits)
     * @return a ParametersWithIV object.
     */
    @Throws(
        CancellationException::class,
        IllegalArgumentException::class
    )
    override suspend fun generateDerivedParameters(keySize: Int, ivSize: Int): CipherParameters {
        var keySizeVar = keySize
        var ivSizeVar = ivSize
        keySizeVar /= 8
        ivSizeVar /= 8
        val dKey = generateDerivedKey(keySizeVar + ivSizeVar)
        return ParametersWithIV(KeyParameter(dKey, 0, keySizeVar), dKey, keySizeVar, ivSizeVar)
    }

    /**
     * Generate a key parameter for use with a MAC derived from the password,
     * salt, and iteration count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    @Throws(
        CancellationException::class,
        IllegalArgumentException::class
    )
    override suspend fun generateDerivedMacParameters(keySize: Int): CipherParameters {
        return generateDerivedParameters(keySize)
    }

    /**
     * construct a PKCS5 Scheme 2 Parameters generator.
     */
    init {
        hMac = HMac(digest)
        state = ByteArray(hMac.getMacSize())
    }
}