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

import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

/**
 * The decoder must reject malformed input with a DecodingException, never with
 * an unchecked exception (index out of bounds, illegal argument...).
 */
class EncodedShortInputTest {
    private val decoders: List<Pair<String, (Encoded) -> Any?>> = listOf(
        "decodeBytes" to { it.decodeBytes() },
        "decodeString" to { it.decodeString() },
        "decodeUid" to { it.decodeUid() },
        "decodeIdentity" to { it.decodeIdentity() },
        "decodeSeed" to { it.decodeSeed() },
        "decodeUuid" to { it.decodeUuid() },
        "decodeEncryptedData" to { it.decodeEncryptedData() },
        "decodeLong" to { it.decodeLong() },
        "decodeBoolean" to { it.decodeBoolean() },
        "decodePublicKey" to { it.decodePublicKey() },
        "decodePrivateKey" to { it.decodePrivateKey() },
        "decodeSymmetricKey" to { it.decodeSymmetricKey() },
        "decodeBigUInt" to { it.decodeBigUInt() },
        "decodeListWithPadding" to { it.decodeListWithPadding() },
        "decodeList" to { it.decodeList() },
        "decodeDictionary" to { it.decodeDictionary() },
        "decodeDictionaryWithPadding" to { it.decodeDictionaryWithPadding() },
        "decodeUidArray" to { it.decodeUidArray() },
        "decodeIdentityArray" to { it.decodeIdentityArray() },
        "decodeStringArray" to { it.decodeStringArray() },
        "decodeStringMap" to { it.decodeStringMap() },
        "decodeDictionaryArray" to { it.decodeDictionaryArray() },
    )

    // every type byte the encoder knows, plus an unknown one
    private val typeBytes = listOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x80, 0x90, 0x91, 0x92, 0x7f).map { it.toByte() }

    @Test
    fun everyDecoder_inputShorterThanHeader_throwsDecodingException() {
        for (len in 0 until 5) {
            for (type in typeBytes) {
                val bytes = ByteArray(len) { 0xff.toByte() }
                if (len > 0) {
                    bytes[0] = type
                }
                val encoded = Encoded(bytes)
                assertFalse("isEncodedValue, length $len, type $type", encoded.isEncodedValue)
                for ((name, decoder) in decoders) {
                    assertThrows("$name, length $len, type $type", DecodingException::class.java) {
                        decoder(encoded)
                    }
                }
            }
        }
    }

    @Test
    fun decodeUid_wrongLength_throwsDecodingException() {
        for (len in listOf(0, 1, UID.UID_LENGTH - 1, UID.UID_LENGTH + 1)) {
            assertThrows("length $len", DecodingException::class.java) {
                Encoded.of(ByteArray(len)).decodeUid()
            }
        }
        val uid = UID(ByteArray(UID.UID_LENGTH) { it.toByte() })
        assertEquals(uid, Encoded.of(uid).decodeUid())
    }

    @Test
    fun decodeSeed_tooShort_throwsDecodingException() {
        for (len in 0 until Seed.MIN_SEED_LENGTH) {
            assertThrows("length $len", DecodingException::class.java) {
                Encoded.of(ByteArray(len)).decodeSeed()
            }
        }
        val seedBytes = ByteArray(Seed.MIN_SEED_LENGTH) { it.toByte() }
        assertEquals(Seed(seedBytes), Encoded.of(Seed(seedBytes)).decodeSeed())
    }

    @Test
    fun decodeUuid_malformed_throwsDecodingException() {
        for (string in listOf("", "not-a-uuid", "1-2")) {
            assertThrows("\"$string\"", DecodingException::class.java) {
                Encoded.of(string).decodeUuid()
            }
        }
        val uuid = UUID.randomUUID()
        assertEquals(uuid, Encoded.of(uuid).decodeUuid())
    }
}
