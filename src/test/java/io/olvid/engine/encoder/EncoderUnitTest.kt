/*
 *  Olvid Kotlin Engine
 *  Copyright © 2019-2026 Olvid SAS
 *
 *  This file is part of the Olvid Kotlin Engine.
 *
 *  The Olvid Kotlin Engine is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  The Olvid Kotlin Engine is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with the Olvid Kotlin Engine.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.olvid.engine.encoder

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.MappingIterator
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesPublicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom

class EncoderUnitTest {
    internal class testVector {
        @JvmField var algorithmImplementationByteIdValue: Byte = 0
        @JvmField var encodedPublicKey: String = ""
        @JvmField var encodedPrivateKey: String = ""
        @JvmField var xCoordinate: String = ""
        @JvmField var yCoordinate: String = ""
        @JvmField var scalar: String = ""
    }

    companion object {
        fun fromHex(hex: String): ByteArray {
            val len = hex.length
            val data = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            }
            return data
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_encodeEncryptionKey() {
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader.getResource("TestVectorsEncodeEncryptionEciesPublicKey.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, testVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as testVector
                val key = HashMap<DictionaryKey, Encoded>()
                key[DictionaryKey(EncryptionEciesPublicKey.PUBLIC_X_COORD_KEY_NAME)] = Encoded.of(BigInteger(vec.xCoordinate), 32)
                key[DictionaryKey(EncryptionEciesPublicKey.PUBLIC_Y_COORD_KEY_NAME)] = Encoded.of(BigInteger(vec.yCoordinate), 32)
                val publicKey = EncryptionPublicKey.of(vec.algorithmImplementationByteIdValue, key) as EncryptionEciesPublicKey

                val decodedPublicKey = Encoded(fromHex(vec.encodedPublicKey)).decodePublicKey() as EncryptionEciesPublicKey
                assertEquals(publicKey.javaClass, decodedPublicKey.javaClass)
                assertEquals(publicKey.ax, decodedPublicKey.ax)
                assertEquals(publicKey.ay, decodedPublicKey.ay)
            }
        }
        run {
            val mapper = ObjectMapper()
            val jsonURL = javaClass.classLoader.getResource("TestVectorsEncodeEncryptionEciesPrivateKey.json")
            val parser = JsonFactory().createParser(jsonURL).enable(JsonParser.Feature.ALLOW_TRAILING_COMMA)
            parser.nextToken()
            parser.nextToken()
            val iter: MappingIterator<*> = mapper.readValues(parser, testVector::class.java)
            while (iter.hasNext()) {
                val vec = iter.next() as testVector
                val key = HashMap<DictionaryKey, Encoded>()
                key[DictionaryKey(EncryptionEciesPrivateKey.SECRET_EXPONENT_KEY_NAME)] = Encoded.of(BigInteger(vec.scalar), 32)
                val privateKey = EncryptionPrivateKey.of(vec.algorithmImplementationByteIdValue, key) as EncryptionEciesPrivateKey

                val decodedPrivateKey = Encoded(fromHex(vec.encodedPrivateKey)).decodePrivateKey() as EncryptionEciesPrivateKey
                assertEquals(privateKey.javaClass, decodedPrivateKey.javaClass)
                assertEquals(privateKey.a, decodedPrivateKey.a)
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun test_encodeBigUInt() {
        val rand = SecureRandom()
        for (i in 0 until 1024) {
            val len = rand.nextInt(513)
            val r = BigInteger(len, rand)
            assertEquals(r, Encoded.of(r, 1 + (len - 1) / 8).decodeBigUInt())
        }
        val expected = byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x00, 0x02, 0x00, 0x03)
        assertArrayEquals(expected, Encoded.of(BigInteger.valueOf(3), 2).bytes)
    }

    @Test
    @Throws(Exception::class)
    fun test_encodeBytes() {
        val rand = SecureRandom()
        for (i in 0 until 1024) {
            val len = rand.nextInt(100)
            val m = ByteArray(len)
            rand.nextBytes(m)
            assertArrayEquals(m, Encoded.of(m).decodeBytes())
        }
        val src = byteArrayOf()
        val expected = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00)
        assertArrayEquals(expected, Encoded.of(src).bytes)
        val src2 = byteArrayOf(1, 2, 3, 4, 5)
        val expected2 = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5)
        assertArrayEquals(expected2, Encoded.of(src2).bytes)
    }

    // replace the 4 length bytes of an encoded value with the given length
    private fun withOuterLength(bytes: ByteArray, len: Int): ByteArray {
        val copy = bytes.copyOf()
        System.arraycopy(Encoded.bytesFromUInt32(len), 0, copy, 1, 4)
        return copy
    }

    // append some bytes inside an encoded list/dictionary, updating its outer length accordingly
    private fun withTrailingBytes(bytes: ByteArray, trailing: Int): ByteArray =
        withOuterLength(bytes + ByteArray(trailing), bytes.size - 5 + trailing)

    private fun assertDecodingFails(block: () -> Unit) {
        try {
            block()
            fail("Expected DecodingException")
        } catch (_: DecodingException) {
            // expected
        }
    }

    private val sampleList: ByteArray = Encoded.of(arrayOf(Encoded.of(byteArrayOf(1, 2, 3)), Encoded.of(42L))).bytes
    private val sampleDictionary: ByteArray = Encoded.of(
        hashMapOf(DictionaryKey("a") to Encoded.of(byteArrayOf(1, 2, 3)), DictionaryKey("b") to Encoded.of(42L))
    ).bytes

    @Test
    fun test_decodeListAndDictionaryRejectTrailingBytes() {
        assertEquals(2, Encoded(sampleList).decodeList().size)
        assertEquals(2, Encoded(sampleList).decodeListWithPadding().size)
        assertEquals(2, Encoded(sampleDictionary).decodeDictionary().size)
        assertEquals(2, Encoded(sampleDictionary).decodeDictionaryWithPadding().size)

        // (5 zero bytes would be a valid encoding of an empty byte array)
        for (trailing in 1..4) {
            val list = withTrailingBytes(sampleList, trailing)
            val dictionary = withTrailingBytes(sampleDictionary, trailing)
            assertDecodingFails { Encoded(list).decodeList() }
            assertDecodingFails { Encoded(list).decodeListWithPadding() }
            assertDecodingFails { Encoded(dictionary).decodeDictionary() }
            assertDecodingFails { Encoded(dictionary).decodeDictionaryWithPadding() }
        }
    }

    @Test
    fun test_decodeWithPaddingAcceptsPaddingAfterTotalLength() {
        for (padding in listOf(1, 4, 5, 100)) {
            assertEquals(2, Encoded(sampleList + ByteArray(padding)).decodeListWithPadding().size)
            assertEquals(2, Encoded(sampleDictionary + ByteArray(padding)).decodeDictionaryWithPadding().size)
        }
    }

    @Test(timeout = 10_000)
    fun test_decodeRejectsNegativeLengths() {
        for (negativeLength in listOf(-1, -5, -6, Int.MIN_VALUE)) {
            // a list containing a single element with a negative length
            val elementHeader = byteArrayOf(0x00) + Encoded.bytesFromUInt32(negativeLength)
            val list = withOuterLength(sampleList.copyOfRange(0, 5) + elementHeader, 5)
            assertDecodingFails { Encoded(list).decodeList() }
            assertDecodingFails { Encoded(list + ByteArray(16)).decodeListWithPadding() }

            // a dictionary whose key, or value, has a negative length
            val dictionaryWithNegativeKey = withOuterLength(sampleDictionary.copyOfRange(0, 5) + elementHeader, 5)
            assertDecodingFails { Encoded(dictionaryWithNegativeKey).decodeDictionary() }
            assertDecodingFails { Encoded(dictionaryWithNegativeKey + ByteArray(16)).decodeDictionaryWithPadding() }
            val key = Encoded.of(byteArrayOf(0x61)).bytes
            val dictionaryWithNegativeValue = withOuterLength(sampleDictionary.copyOfRange(0, 5) + key + elementHeader, key.size + 5)
            assertDecodingFails { Encoded(dictionaryWithNegativeValue).decodeDictionary() }
            assertDecodingFails { Encoded(dictionaryWithNegativeValue + ByteArray(16)).decodeDictionaryWithPadding() }

            // negative outer lengths
            assertDecodingFails { Encoded(withOuterLength(sampleList, negativeLength)).decodeListWithPadding() }
            assertDecodingFails { Encoded(withOuterLength(sampleDictionary, negativeLength)).decodeDictionaryWithPadding() }
            assertDecodingFails { Encoded.fromLongerByteArray(withOuterLength(sampleList, negativeLength)) }
        }
    }

    @Test(timeout = 10_000)
    fun test_decodeRejectsOverflowingLengths() {
        for (hugeLength in listOf(Int.MAX_VALUE, Int.MAX_VALUE - 4, Int.MAX_VALUE - 9)) {
            val elementHeader = byteArrayOf(0x00) + Encoded.bytesFromUInt32(hugeLength)
            val list = withOuterLength(sampleList.copyOfRange(0, 5) + elementHeader, 5)
            assertDecodingFails { Encoded(list).decodeList() }
            assertDecodingFails { Encoded(list + ByteArray(16)).decodeListWithPadding() }
            assertDecodingFails { Encoded(withOuterLength(sampleList, hugeLength)).decodeListWithPadding() }
            assertDecodingFails { Encoded.fromLongerByteArray(withOuterLength(sampleList, hugeLength)) }
        }
    }
}
