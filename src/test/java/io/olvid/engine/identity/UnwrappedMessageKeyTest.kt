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

package io.olvid.engine.identity

import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.CryptographicKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACHmacSha256Key
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/**
 * Anyone can encrypt a message key for an identity (asymmetric channel), so the
 * unwrapped plaintext is attacker controlled. Decoding it must yield null for anything but a valid AuthEncKey,
 * never an unchecked exception (which escaped the reception path and made the message be retried forever).
 */
class UnwrappedMessageKeyTest {
    private lateinit var prng: PRNGService
    private lateinit var validKey: AuthEncKey

    @Before
    fun setUp() {
        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))
        validKey = Suite.getDefaultAuthEnc(0).generateKey(prng)!!
    }

    // Encodes a symmetric key with arbitrary class, implementation and dictionary (Encoded.of(SymmetricKey) only
    // accepts well-formed keys): same layout as a list, with the symmetric key type byte.
    private fun symmetricKeyEncoding(algoClass: Byte, algoImpl: Byte, dict: HashMap<DictionaryKey, Encoded>): ByteArray {
        val bytes = Encoded.of(arrayOf(Encoded.of(byteArrayOf(algoClass, algoImpl)), Encoded.of(dict))).bytes.copyOf()
        bytes[0] = 0x90.toByte()
        return bytes
    }

    private fun authEncEncoding(dict: HashMap<DictionaryKey, Encoded>): ByteArray {
        return symmetricKeyEncoding(CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION, AuthEncKey.ALGO_IMPL_AES256_THEN_SHA256, dict)
    }

    private fun maliciousPayloads(): Map<String, ByteArray> {
        val shortMacKey = HashMap(validKey.key)
        shortMacKey[DictionaryKey(MACKey.MACKEY_KEY_NAME)] = Encoded.of(ByteArray(5))
        val macKeyNotBytes = HashMap(validKey.key)
        macKeyNotBytes[DictionaryKey(MACKey.MACKEY_KEY_NAME)] = Encoded.of(42L)
        val noMacKey = HashMap(validKey.key)
        noMacKey.remove(DictionaryKey(MACKey.MACKEY_KEY_NAME))

        return mapOf(
            "empty dictionary" to authEncEncoding(HashMap()),
            "missing mac key" to authEncEncoding(noMacKey),
            "short mac key" to authEncEncoding(shortMacKey),
            "mac key is not bytes" to authEncEncoding(macKeyNotBytes),
            "unknown implementation" to symmetricKeyEncoding(CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION, 0x7f, HashMap(validKey.key)),
            "MAC key instead of AuthEnc key" to Encoded.of(MACHmacSha256Key.of(prng.bytes(32))).bytes,
            "not a symmetric key" to Encoded.of("hello").bytes,
            "empty" to ByteArray(0),
            "too short" to byteArrayOf(0x90.toByte(), 0, 0),
        )
    }

    @Test
    fun maliciousPayloads_makeKeyConstructorsFailWithDecodingException() {
        // these used to throw NullPointerException / InvalidParameterException out of decodeSymmetricKey
        for (name in listOf("empty dictionary", "missing mac key", "short mac key", "mac key is not bytes")) {
            assertThrows(name, DecodingException::class.java) {
                Encoded(maliciousPayloads().getValue(name)).decodeSymmetricKey()
            }
        }
    }

    @Test
    fun decodeUnwrappedMessageKey_maliciousPayload_returnsNull() {
        for ((name, payload) in maliciousPayloads()) {
            assertNull(name, IdentityManager.decodeUnwrappedMessageKey(payload))
        }
    }

    @Test
    fun decodeUnwrappedMessageKey_validKey_returnsIt() {
        assertArrayEquals(Encoded.of(validKey).bytes, Encoded.of(IdentityManager.decodeUnwrappedMessageKey(Encoded.of(validKey).bytes)!!).bytes)
        // the hand-made encoding of a valid key is accepted too, so the malicious ones only differ by their content
        assertNotNull(IdentityManager.decodeUnwrappedMessageKey(authEncEncoding(HashMap(validKey.key))))
    }

    @Test
    fun maliciousPayloadEncryptedForIdentity_unwrapsToNull() {
        // what an attacker does: ECIES-encrypt a crafted payload with the victim's public encryption key
        val keyPair = Suite.generateEncryptionKeyPair(null, prng)!!
        val publicKey = keyPair.publicKey as EncryptionPublicKey
        val privateKey = keyPair.privateKey as EncryptionPrivateKey
        val pke = Suite.getPublicKeyEncryption(publicKey)!!

        for ((name, payload) in maliciousPayloads()) {
            val unwrappedBytes = pke.decrypt(privateKey, pke.encrypt(publicKey, payload, prng))!!
            assertNull(name, IdentityManager.decodeUnwrappedMessageKey(unwrappedBytes))
        }

        val unwrappedBytes = pke.decrypt(privateKey, pke.encrypt(publicKey, Encoded.of(validKey).bytes, prng))!!
        assertNotNull(IdentityManager.decodeUnwrappedMessageKey(unwrappedBytes))
    }
}
