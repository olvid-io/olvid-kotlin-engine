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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.MessageType
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
import org.junit.Before
import org.junit.Test

class ChannelReceivedApplicationMessageTest {

    private lateinit var prng: PRNGService
    private lateinit var ownedIdentity: Identity
    private lateinit var remoteIdentity: Identity
    private lateinit var remoteDeviceUid: UID
    private lateinit var messageUid: UID

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

        prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val ownedAuthKp = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val ownedEncKp = EncryptionEciesCurve25519KeyPair.generate(prng)
        ownedIdentity = Identity(
            "test.olvid.io",
            ownedAuthKp.publicKey as ServerAuthenticationPublicKey,
            ownedEncKp.publicKey as EncryptionPublicKey
        )

        val remoteAuthKp = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val remoteEncKp = EncryptionEciesCurve25519KeyPair.generate(prng)
        remoteIdentity = Identity(
            "remote.olvid.io",
            remoteAuthKp.publicKey as ServerAuthenticationPublicKey,
            remoteEncKp.publicKey as EncryptionPublicKey
        )

        remoteDeviceUid = UID(prng)
        messageUid = UID(prng)
    }

    // -----------------------------------------------------------------------
    // Helpers to build a real ChannelReceivedMessage by encrypting a payload.
    // -----------------------------------------------------------------------

    /**
     * Builds an encrypted ChannelReceivedMessage whose decrypted payload is
     * `[messageType, encodedElements]`. The message-key is generated via
     * `generateMessageKey(prng, plaintext)` so that `verifyMessageKey` passes
     * inside `ChannelReceivedMessage`'s constructor.
     *
     * If [tamperedEncodedElements] is non-null, that encoded value is placed
     * as the second element of the encrypted payload (this lets us produce
     * a successfully decrypted ChannelReceivedMessage whose `encodedElements`
     * are deliberately malformed for `decodeList()` purposes).
     */
    private fun buildChannelReceivedMessage(
        messageType: Int,
        encodedElements: Encoded,
        channelInfo: ReceptionChannelInfo
    ): ChannelReceivedMessage {
        val authEnc = Suite.getDefaultAuthEnc(0)
        val plaintextList = arrayOf(
            Encoded.of(messageType.toLong()),
            encodedElements
        )
        val plaintext: Encoded = Encoded.of(plaintextList)
        val key: AuthEncKey = authEnc.generateMessageKey(prng, plaintext.bytes)!!
        val cipher = authEnc.encrypt(key, plaintext.bytes, prng)

        val header = NetworkReceivedMessage.Header(ownedIdentity, null)
        val network = NetworkReceivedMessage(
            messageUid,
            1234567890L,
            cipher,
            header,
            false
        )
        return ChannelReceivedMessage(network, key, channelInfo)
    }

    /**
     * Build the canonical application-message `encodedElements`:
     *
     *   [ [attKey0, attMeta0], [attKey1, attMeta1], ..., payload ]
     */
    private fun buildAttachmentsAndPayloadEncoded(
        attachments: List<Pair<AuthEncKey, ByteArray>>,
        payload: ByteArray
    ): Encoded {
        val list = ArrayList<Encoded>(attachments.size + 1)
        for ((key, metadata) in attachments) {
            list.add(
                Encoded.of(arrayOf(Encoded.of(key), Encoded.of(metadata)))
            )
        }
        list.add(Encoded.of(payload))
        return Encoded.of(list.toTypedArray())
    }

    private fun obliviousChannel(): ReceptionChannelInfo =
        ReceptionChannelInfo.createObliviousChannelInfo(remoteDeviceUid, remoteIdentity)

    private fun preKeyChannel(): ReceptionChannelInfo =
        ReceptionChannelInfo.createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)

    private fun makeAttachmentKey(): AuthEncKey =
        Suite.getDefaultAuthEnc(0).generateKey(prng)!!

    // -----------------------------------------------------------------------
    // Guard 1: wrong message type → null
    // -----------------------------------------------------------------------

    @Test
    fun testReturnsNullForNonApplicationMessageType() {
        val payload = byteArrayOf(1, 2, 3)
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), payload)
        val crm = buildChannelReceivedMessage(
            MessageType.PROTOCOL_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullForDialogMessageType() {
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), byteArrayOf(9))
        val crm = buildChannelReceivedMessage(
            MessageType.DIALOG_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullForServerQueryMessageType() {
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), byteArrayOf(7))
        val crm = buildChannelReceivedMessage(
            MessageType.SERVER_QUERY_TYPE,
            elements,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    // -----------------------------------------------------------------------
    // Guard 2: wrong channel type → null
    // -----------------------------------------------------------------------

    @Test
    fun testReturnsNullForLocalChannel() {
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), byteArrayOf(0))
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            ReceptionChannelInfo.createLocalChannelInfo()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullForAsymmetricChannel() {
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), byteArrayOf(0))
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            ReceptionChannelInfo.createAsymmetricChannelInfo()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullForAnyObliviousOrPreKeyWithOwnedDeviceChannel() {
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), byteArrayOf(0))
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            ReceptionChannelInfo.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    // -----------------------------------------------------------------------
    // Guard 3: malformed encodedElements → null
    // -----------------------------------------------------------------------

    @Test
    fun testReturnsNullWhenEncodedElementsIsNotAList() {
        // encodedElements is a plain byte-array (not a list) → decodeList() throws DecodingException
        val notAList = Encoded.of(byteArrayOf(1, 2, 3, 4))
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            notAList,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullWhenAttachmentTupleHasWrongArity() {
        // Build an "attachment" element that is a list of 3 (instead of 2).
        val malformedAttachment = Encoded.of(
            arrayOf(
                Encoded.of(makeAttachmentKey()),
                Encoded.of(byteArrayOf(1, 2)),
                Encoded.of(byteArrayOf(3, 4)) // unexpected extra
            )
        )
        val payload = Encoded.of(byteArrayOf(7, 7, 7))
        val elements = Encoded.of(arrayOf(malformedAttachment, payload))

        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    @Test
    fun testReturnsNullWhenAttachmentKeyIsNotASymmetricKey() {
        // First element of attachment tuple is a UID (not a symmetric key) →
        // decodeSymmetricKey() returns a non-AuthEncKey/null and the cast in
        // ChannelReceivedApplicationMessage.of throws ClassCastException
        // (or returns null) → factory must return null.
        val notAKey = Encoded.of(UID(prng))
        val attachment = Encoded.of(arrayOf(notAKey, Encoded.of(byteArrayOf(1))))
        val payload = Encoded.of(byteArrayOf(2))
        val elements = Encoded.of(arrayOf(attachment, payload))

        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )
        assertNull(ChannelReceivedApplicationMessage.of(crm))
    }

    // -----------------------------------------------------------------------
    // Happy paths
    // -----------------------------------------------------------------------

    @Test
    fun testZeroAttachmentsOverObliviousChannel() {
        val payload = "hello-world".toByteArray()
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), payload)
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )

        val result = ChannelReceivedApplicationMessage.of(crm)
        assertNotNull(result)
        result!!
        assertEquals(0, result.attachmentsKeyAndMetadata.size)
        assertArrayEquals(payload, result.messagePayload)
        assertSame(crm, result.message)
        assertEquals(ownedIdentity, result.ownedIdentity)
        assertEquals(messageUid, result.messageUid)
    }

    @Test
    fun testSingleAttachmentOverPreKeyChannel() {
        val k0 = makeAttachmentKey()
        val m0 = byteArrayOf(10, 20, 30)
        val payload = byteArrayOf(99)
        val elements = buildAttachmentsAndPayloadEncoded(listOf(k0 to m0), payload)

        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            preKeyChannel()
        )

        val result = ChannelReceivedApplicationMessage.of(crm)
        assertNotNull(result)
        result!!
        assertEquals(1, result.attachmentsKeyAndMetadata.size)
        assertEquals(k0, result.attachmentsKeyAndMetadata[0]!!.key)
        assertArrayEquals(m0, result.attachmentsKeyAndMetadata[0]!!.metadata)
        assertArrayEquals(payload, result.messagePayload)
    }

    @Test
    fun testManyAttachmentsPreserveOrderAndContent() {
        val n = 5
        val pairs = (0 until n).map { i ->
            makeAttachmentKey() to "metadata-$i".toByteArray()
        }
        val payload = "the-actual-payload".toByteArray()
        val elements = buildAttachmentsAndPayloadEncoded(pairs, payload)

        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )

        val result = ChannelReceivedApplicationMessage.of(crm)
        assertNotNull(result)
        result!!
        assertEquals(n, result.attachmentsKeyAndMetadata.size)
        for (i in 0 until n) {
            assertEquals(
                "attachment $i: key mismatch",
                pairs[i].first,
                result.attachmentsKeyAndMetadata[i]!!.key
            )
            assertArrayEquals(
                "attachment $i: metadata mismatch",
                pairs[i].second,
                result.attachmentsKeyAndMetadata[i]!!.metadata
            )
        }
        assertArrayEquals(payload, result.messagePayload)
    }

    @Test
    fun testEmptyPayloadBytesIsAccepted() {
        // The last element is a zero-length byte string — must still parse.
        val payload = ByteArray(0)
        val elements = buildAttachmentsAndPayloadEncoded(emptyList(), payload)
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            obliviousChannel()
        )

        val result = ChannelReceivedApplicationMessage.of(crm)
        assertNotNull(result)
        result!!
        assertEquals(0, result.messagePayload.size)
        assertEquals(0, result.attachmentsKeyAndMetadata.size)
    }

    @Test
    fun testGetterDelegationMatchesUnderlyingMessage() {
        // Confirm getOwnedIdentity / getMessageUid / getMessage all delegate
        // to the wrapped ChannelReceivedMessage (and through it to
        // NetworkReceivedMessage). Use distinct UID / Identity to make the
        // delegation meaningful.
        val k0 = makeAttachmentKey()
        val elements = buildAttachmentsAndPayloadEncoded(
            listOf(k0 to byteArrayOf(0x42)),
            byteArrayOf(0x01, 0x02)
        )
        val crm = buildChannelReceivedMessage(
            MessageType.APPLICATION_MESSAGE_TYPE,
            elements,
            preKeyChannel()
        )

        val result = ChannelReceivedApplicationMessage.of(crm)!!
        assertSame(crm, result.message)
        assertEquals(crm.ownedIdentity, result.ownedIdentity)
        assertEquals(crm.messageUid, result.messageUid)
        // Also confirm the wrapped identity is the one we put on the header.
        assertEquals(ownedIdentity, result.ownedIdentity)
        assertEquals(messageUid, result.messageUid)
    }
}
