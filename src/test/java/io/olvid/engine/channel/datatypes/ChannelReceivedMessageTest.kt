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

package io.olvid.engine.channel.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.AuthEnc
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class ChannelReceivedMessageTest {

    private lateinit var authEnc: AuthEnc
    private lateinit var prng: PRNGService
    private lateinit var ownedIdentity: Identity
    private lateinit var remoteIdentity: Identity
    private lateinit var messageUid: UID
    private lateinit var remoteDeviceUid: UID
    private lateinit var wrappedKey: EncryptedBytes

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        authEnc = Suite.getDefaultAuthEnc(0)
        // Deterministic PRNG for reproducible tests
        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(Seed.MIN_SEED_LENGTH)))

        val authKp1 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKp1 = EncryptionEciesCurve25519KeyPair.generate(prng)
        ownedIdentity = Identity(
            "owned.olvid.io",
            authKp1.publicKey as ServerAuthenticationPublicKey,
            encKp1.publicKey as EncryptionPublicKey
        )

        val authKp2 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKp2 = EncryptionEciesCurve25519KeyPair.generate(prng)
        remoteIdentity = Identity(
            "remote.olvid.io",
            authKp2.publicKey as ServerAuthenticationPublicKey,
            encKp2.publicKey as EncryptionPublicKey
        )

        messageUid = UID(prng)
        remoteDeviceUid = UID(prng)
        wrappedKey = EncryptedBytes(prng.bytes(64))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Build a padded plaintext that wraps the given encoded list, matching what
     * NetworkChannel does at send time: pad up to next multiple of 512 bytes.
     */
    private fun pad(plaintextContent: Encoded): ByteArray {
        val len = plaintextContent.bytes.size
        val paddedLen = ((len - 1) or 511) + 1
        val padded = ByteArray(paddedLen)
        System.arraycopy(plaintextContent.bytes, 0, padded, 0, len)
        return padded
    }

    /**
     * Build a NetworkReceivedMessage carrying [paddedPlaintext] encrypted with [keyForEncryption].
     */
    private fun buildReceivedMessage(
        keyForEncryption: AuthEncKey,
        paddedPlaintext: ByteArray,
        hasExtendedPayload: Boolean = false
    ): NetworkReceivedMessage {
        val encryptedContent = authEnc.encrypt(keyForEncryption, paddedPlaintext, prng)
        val header = NetworkReceivedMessage.Header(ownedIdentity, wrappedKey)
        return NetworkReceivedMessage(
            messageUid,
            1_700_000_000_000L,
            encryptedContent,
            header,
            hasExtendedPayload
        )
    }

    private fun protocolPayload(messageType: Int, payload: Encoded): Encoded {
        return Encoded.of(arrayOf(
            Encoded.of(messageType.toLong()),
            payload
        ))
    }

    // -------------------------------------------------------------------------
    // 1. Happy path
    // -------------------------------------------------------------------------

    @Test
    fun testHappyPathReturnsDecryptedMessageTypeAndElements() {
        val messageType = 42
        val payload = Encoded.of("hello, channel".toByteArray())
        val plaintext = protocolPayload(messageType, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)
        val recv = ReceptionChannelInfo.createLocalChannelInfo()

        val crm = ChannelReceivedMessage(received, messageKey, recv)

        assertEquals(messageType, crm.messageType)
        assertArrayEquals(payload.bytes, crm.encodedElements!!.bytes)
    }

    @Test
    fun testHappyPathPassesThroughReceptionChannelInfoAndMessage() {
        val payload = Encoded.of(arrayOf(Encoded.of(1L), Encoded.of("nested".toByteArray())))
        val plaintext = protocolPayload(7, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)
        val recv = ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)

        val crm = ChannelReceivedMessage(received, messageKey, recv)

        // Pass-through references must be the same objects (Java field assignment, not copies)
        assertSame(recv, crm.receptionChannelInfo)
        assertSame(received, crm.message)
    }

    @Test
    fun testGetOwnedIdentityDelegatesToUnderlyingMessage() {
        val payload = Encoded.of("x".toByteArray())
        val plaintext = protocolPayload(0, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        assertSame(ownedIdentity, crm.ownedIdentity)
    }

    @Test
    fun testGetMessageUidDelegatesToUnderlyingMessage() {
        val payload = Encoded.of("y".toByteArray())
        val plaintext = protocolPayload(0, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        assertSame(messageUid, crm.messageUid)
    }

    @Test
    fun testMessageTypeIsDecodedFromFirstListElementAsLong() {
        // Use a "large-ish" int value to make sure the (Long -> Int) cast contract is exercised.
        val messageType = 0x0000_7FFF
        val payload = Encoded.of("z".toByteArray())
        val plaintext = protocolPayload(messageType, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        assertEquals(messageType, crm.messageType)
    }

    // -------------------------------------------------------------------------
    // 2. Extended payload key derivation
    // -------------------------------------------------------------------------

    @Test
    fun testExtendedPayloadKeyIsNullWhenMessageHasNoExtendedPayload() {
        val payload = Encoded.of("no-extended".toByteArray())
        val plaintext = protocolPayload(3, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded, hasExtendedPayload = false)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        assertNull(crm.extendedPayloadKey)
    }

    @Test
    fun testExtendedPayloadKeyIsNonNullWhenMessageHasExtendedPayload() {
        val payload = Encoded.of("with-extended".toByteArray())
        val plaintext = protocolPayload(3, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded, hasExtendedPayload = true)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        assertNotNull(crm.extendedPayloadKey)
    }

    @Test
    fun testExtendedPayloadKeyMatchesDeterministicDerivation() {
        // The class derives extendedPayloadKey = authEnc.generateKey(Suite.getDefaultPRNG(0, Seed.of(messageKey))).
        // Re-deriving with the same recipe must yield the exact same key bytes.
        val payload = Encoded.of("derive-me".toByteArray())
        val plaintext = protocolPayload(9, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded, hasExtendedPayload = true)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        val expectedPrng = Suite.getDefaultPRNG(0, Seed.of(messageKey))
        val expectedKey = authEnc.generateKey(expectedPrng)!!

        // AuthEncKey doesn't override equals — compare via the encoded representation.
        assertArrayEquals(
            Encoded.of(expectedKey).bytes,
            Encoded.of(crm.extendedPayloadKey!!).bytes
        )
    }

    @Test
    fun testExtendedPayloadKeyDifferentFromMessageKey() {
        // Sanity guard: the derived extended-payload key must not just be the messageKey reused.
        val payload = Encoded.of("distinct".toByteArray())
        val plaintext = protocolPayload(11, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded, hasExtendedPayload = true)

        val crm = ChannelReceivedMessage(
            received,
            messageKey,
            ReceptionChannelInfo.createLocalChannelInfo()
        )

        val msgKeyEncoded = Encoded.of(messageKey).bytes
        val extKeyEncoded = Encoded.of(crm.extendedPayloadKey!!).bytes
        if (msgKeyEncoded.contentEquals(extKeyEncoded)) {
            fail("Extended payload key must be derived, not equal to the messageKey")
        }
    }

    // -------------------------------------------------------------------------
    // 3. MessageKey verification failure
    // -------------------------------------------------------------------------

    @Test
    fun testFailingMessageKeyCheckThrows() {
        // Using authEnc.generateKey() (instead of generateMessageKey(...)) yields a key whose
        // MAC component is NOT bound to the plaintext, so verifyMessageKey returns false.
        // The ciphertext still decrypts correctly (we use the same key for enc/dec), so the
        // failure happens at the verifyMessageKey() step — exactly the contract under test.
        val payload = Encoded.of("won't verify".toByteArray())
        val plaintext = protocolPayload(5, payload)
        val padded = pad(plaintext)

        val messageKey = authEnc.generateKey(prng)!! // NOT generateMessageKey
        val received = buildReceivedMessage(messageKey, padded)

        try {
            ChannelReceivedMessage(
                received,
                messageKey,
                ReceptionChannelInfo.createLocalChannelInfo()
            )
            fail("Expected exception when verifyMessageKey returns false")
        } catch (e: Exception) {
            // The class throws `new Exception()` (no message) for this case.
            // It must NOT be the "Undecipherable message." path.
            assertEquals(null, e.message)
        }
    }

    // -------------------------------------------------------------------------
    // 4. Malformed payload (list size != 2)
    // -------------------------------------------------------------------------

    @Test
    fun testDecodedListWithOneElementThrows() {
        // Build a payload whose decoded list has exactly 1 element.
        val plaintext = Encoded.of(arrayOf(Encoded.of(7L)))
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)

        try {
            ChannelReceivedMessage(
                received,
                messageKey,
                ReceptionChannelInfo.createLocalChannelInfo()
            )
            fail("Expected exception for decoded list size 1")
        } catch (e: Exception) {
            // The constructor throws `new Exception()` with no message for malformed lists.
            assertEquals(null, e.message)
        }
    }

    @Test
    fun testDecodedListWithThreeElementsThrows() {
        // Build a payload whose decoded list has 3 elements.
        val plaintext = Encoded.of(arrayOf(
            Encoded.of(1L),
            Encoded.of("a".toByteArray()),
            Encoded.of("extra".toByteArray())
        ))
        val padded = pad(plaintext)

        val messageKey = authEnc.generateMessageKey(prng, padded)!!
        val received = buildReceivedMessage(messageKey, padded)

        try {
            ChannelReceivedMessage(
                received,
                messageKey,
                ReceptionChannelInfo.createLocalChannelInfo()
            )
            fail("Expected exception for decoded list size 3")
        } catch (e: Exception) {
            assertEquals(null, e.message)
        }
    }

    // -------------------------------------------------------------------------
    // 5. Undecipherable message
    // -------------------------------------------------------------------------

    @Test
    fun testWrongMessageKeyRaisesUndecipherableMessage() {
        val payload = Encoded.of("legit content".toByteArray())
        val plaintext = protocolPayload(2, payload)
        val padded = pad(plaintext)

        // Encrypt with one key, but attempt to decrypt with a *different* key.
        val encKey = authEnc.generateMessageKey(prng, padded)!!
        val wrongKey = authEnc.generateKey(prng)!!

        val received = buildReceivedMessage(encKey, padded)

        try {
            ChannelReceivedMessage(
                received,
                wrongKey,
                ReceptionChannelInfo.createLocalChannelInfo()
            )
            fail("Expected exception when decrypting with the wrong key")
        } catch (e: Exception) {
            // The class catches DecryptionException and rewraps with this exact message.
            assertEquals("Undecipherable message.", e.message)
        }
    }
}
