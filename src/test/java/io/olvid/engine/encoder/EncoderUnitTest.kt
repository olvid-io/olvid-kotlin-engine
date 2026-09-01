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
}
