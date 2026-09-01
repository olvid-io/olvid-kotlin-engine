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

package io.olvid.engine.engine.types

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.ReceivedAttachment
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for three message-related public DTOs:
 *   1. [ObvOutboundAttachment] — small outbound attachment (path, length, metadata)
 *   2. [ObvAttachment]         — inbound attachment with identity and computed properties
 *   3. [ObvMessage]            — inbound message that wraps [DecryptedApplicationMessage]
 *                               and constructs [ObvAttachment] instances from [ReceivedAttachment]
 *
 * These DTOs are pure data containers with no encode/decode wire format of their own.
 * The critical contracts are:
 *   - Constructor field-storage (reference identity for objects, exact value for primitives)
 *   - Getters delegate straight to the stored field or compute from it
 *   - equals/hashCode follow reference identity (no override in any of the three classes)
 *   - ObvAttachment.getBytesOwnedIdentity() and getMessageIdentifier() are computed
 *     delegates, not stored fields — they must agree with the corresponding source objects
 *   - ObvMessage.getIdentifier() delegates to messageUid.getBytes()
 *   - ObvMessage constructor correctly translates null fromIdentity / fromDeviceUid /
 *     toIdentity to null byte arrays
 *   - ObvMessage constructor fans out ReceivedAttachment[] into ObvAttachment[] with
 *     the server timestamp taken from the message (not the attachment)
 */
class ObvMessageAndAttachmentsTest {

    // ─── Shared test data ─────────────────────────────────────────────────────

    private lateinit var identity: Identity
    private lateinit var messageUid: UID
    private lateinit var attachmentUid: UID

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

        // Deterministic PRNG seeded with all-zeros so tests are reproducible.
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        identity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )

        messageUid = UID(ByteArray(UID.UID_LENGTH) { (it + 1).toByte() })
        attachmentUid = UID(ByteArray(UID.UID_LENGTH) { (it + 11).toByte() })
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvOutboundAttachment
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Simple three-field DTO: path (String), attachmentLength (long), metadata (byte[]).
    // One constructor, three getters, no computed properties, reference-identity equals.

    // ─── Constructor field-storage ────────────────────────────────────────────

    @Test
    fun outbound_constructor_storesPathByReference() {
        val path = "attachments/photo.jpg"
        val obj = ObvOutboundAttachment(path, 1024L, ByteArray(4))
        assertSame(path, obj.path)
    }

    @Test
    fun outbound_constructor_storesAttachmentLengthExactly() {
        val obj = ObvOutboundAttachment("file.bin", Long.MAX_VALUE, ByteArray(0))
        assertEquals(Long.MAX_VALUE, obj.attachmentLength)
    }

    @Test
    fun outbound_constructor_storesZeroLength() {
        val obj = ObvOutboundAttachment("empty.bin", 0L, ByteArray(0))
        assertEquals(0L, obj.attachmentLength)
    }

    @Test
    fun outbound_constructor_storesMetadataByReference() {
        val metadata = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val obj = ObvOutboundAttachment("file.bin", 42L, metadata)
        assertSame(metadata, obj.metadata)
    }

    @Test
    fun outbound_constructor_acceptsNullMetadata() {
        val obj = ObvOutboundAttachment("file.bin", 42L, null)
        assertNull(obj.metadata)
    }

    @Test
    fun outbound_constructor_acceptsNullPath() {
        val obj = ObvOutboundAttachment(null, 100L, byteArrayOf(1, 2, 3))
        assertNull(obj.path)
    }

    // ─── Getters delegate ─────────────────────────────────────────────────────

    @Test
    fun outbound_getPath_returnsStoredPath() {
        val path = "no_backup/data/attach-1"
        val obj = ObvOutboundAttachment(path, 8L, ByteArray(0))
        assertEquals(path, obj.path)
    }

    @Test
    fun outbound_getAttachmentLength_returnsStoredLength() {
        val obj = ObvOutboundAttachment("x", 999_999_999L, ByteArray(0))
        assertEquals(999_999_999L, obj.attachmentLength)
    }

    @Test
    fun outbound_getMetadata_returnsStoredMetadata() {
        val metadata = byteArrayOf(1, 2, 3, 4, 5)
        val obj = ObvOutboundAttachment("x", 1L, metadata)
        assertSame(metadata, obj.metadata)
    }

    // ─── equals / hashCode (reference identity — no override) ────────────────

    @Test
    fun outbound_equalsIsSameReferenceOnly() {
        val obj1 = ObvOutboundAttachment("path", 10L, byteArrayOf(1, 2))
        val obj2 = ObvOutboundAttachment("path", 10L, byteArrayOf(1, 2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Different instances with same field values must not be equal", obj1.equals(obj2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("An instance must equal itself", obj1.equals(obj1))
    }

    @Test
    fun outbound_hashCodeIsStableAcrossCalls() {
        val obj = ObvOutboundAttachment("path", 10L, byteArrayOf(1))
        assertEquals(obj.hashCode(), obj.hashCode())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvAttachment
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Nine-field inbound attachment DTO.  Two important computed properties:
    //   - getBytesOwnedIdentity() → ownedIdentity.getBytes()  (not a stored field)
    //   - getMessageIdentifier()  → messageUid.getBytes()      (not a stored field)
    //
    // The only way to construct an ObvAttachment outside this package is via
    // ObvMessage (which builds them during its own construction) or via the
    // package-private constructor — we use ObvMessage here.
    //
    // A helper constructs one ObvMessage with one ReceivedAttachment so that
    // each test can extract the single ObvAttachment.

    private fun makeObvAttachment(
        metadata: ByteArray? = byteArrayOf(0x01, 0x02),
        url: String? = "no_backup/attach/1",
        downloadRequested: Boolean = true,
        ownedIdentity: Identity = identity,
        attachmentMessageUid: UID = attachmentUid,
        attachmentNumber: Int = 0,
        expectedLength: Long = 512L,
        receivedLength: Long = 256L,
        messageServerTimestamp: Long = 1_700_000_000_000L,
    ): ObvAttachment {
        val receivedAttachment = ReceivedAttachment(
            ownedIdentity,
            attachmentMessageUid,
            attachmentNumber,
            metadata,
            url,
            expectedLength,
            receivedLength,
            false,
            downloadRequested,
        )
        val message = DecryptedApplicationMessage(
            messageUid,
            byteArrayOf(0xFF.toByte()),
            /* fromIdentity = */ identity,
            /* fromDeviceUid = */ null,
            /* toIdentity = */ identity,
            messageServerTimestamp,
            /* downloadTimestamp = */ messageServerTimestamp + 1_000L,
            /* localDownloadTimestamp = */ messageServerTimestamp + 2_000L,
        )
        return ObvMessage(message, arrayOf(receivedAttachment)).attachments[0]!!
    }

    // ─── Constructor field-storage (via ObvMessage fan-out) ───────────────────

    @Test
    fun attachment_metadata_storedByReference() {
        val metadata = byteArrayOf(0xAA.toByte(), 0xBB.toByte())
        val att = makeObvAttachment(metadata = metadata)
        assertSame(metadata, att.metadata)
    }

    @Test
    fun attachment_url_storedByReference() {
        val url = "no_backup/attachments/video.mp4"
        val att = makeObvAttachment(url = url)
        assertEquals(url, att.url)
    }

    @Test
    fun attachment_downloadRequested_true_storedExactly() {
        val att = makeObvAttachment(downloadRequested = true)
        assertTrue(att.isDownloadRequested())
    }

    @Test
    fun attachment_downloadRequested_false_storedExactly() {
        val att = makeObvAttachment(downloadRequested = false)
        assertFalse(att.isDownloadRequested())
    }

    @Test
    fun attachment_ownedIdentity_storedBySameReference() {
        val att = makeObvAttachment(ownedIdentity = identity)
        assertSame(identity, att.ownedIdentity)
    }

    @Test
    fun attachment_messageUid_storedBySameReference() {
        val att = makeObvAttachment(attachmentMessageUid = attachmentUid)
        assertSame(attachmentUid, att.messageUid)
    }

    @Test
    fun attachment_number_storedExactly() {
        val att = makeObvAttachment(attachmentNumber = 3)
        assertEquals(3, att.number)
    }

    @Test
    fun attachment_expectedLength_storedExactly() {
        val att = makeObvAttachment(expectedLength = 1_048_576L)
        assertEquals(1_048_576L, att.expectedLength)
    }

    @Test
    fun attachment_receivedLength_storedExactly() {
        val att = makeObvAttachment(receivedLength = 32_768L)
        assertEquals(32_768L, att.receivedLength)
    }

    // ─── Server timestamp comes from the MESSAGE, not the ReceivedAttachment ──
    //
    // This is a subtle invariant in ObvMessage's constructor: it passes
    // receivedMessage.getServerTimestamp() (not any field from receivedAttachment)
    // when constructing each ObvAttachment.

    @Test
    fun attachment_messageServerTimestamp_takesValueFromParentMessage() {
        val msgTimestamp = 1_700_123_456_789L
        val att = makeObvAttachment(messageServerTimestamp = msgTimestamp)
        assertEquals(msgTimestamp, att.messageServerTimestamp)
    }

    // ─── Computed properties ──────────────────────────────────────────────────

    @Test
    fun attachment_getBytesOwnedIdentity_matchesIdentityGetBytes() {
        val att = makeObvAttachment(ownedIdentity = identity)
        assertArrayEquals(identity.getBytes(), att.getBytesOwnedIdentity())
    }

    @Test
    fun attachment_getMessageIdentifier_matchesMessageUidBytes() {
        val att = makeObvAttachment(attachmentMessageUid = attachmentUid)
        assertArrayEquals(attachmentUid.bytes, att.messageIdentifier)
    }

    @Test
    fun attachment_getMessageIdentifier_returnsDistinctArrayEachCall() {
        // messageUid.getBytes() returns the same backing array; confirm the value is stable
        val att = makeObvAttachment()
        assertArrayEquals(att.messageIdentifier, att.messageIdentifier)
    }

    // ─── Getters delegate to stored fields ────────────────────────────────────

    @Test
    fun attachment_getUrl_returnsStoredUrl() {
        val url = "no_backup/a/b/c.bin"
        val att = makeObvAttachment(url = url)
        assertEquals(url, att.url)
    }

    @Test
    fun attachment_getNumber_returnsStoredNumber() {
        val att = makeObvAttachment(attachmentNumber = 7)
        assertEquals(7, att.number)
    }

    @Test
    fun attachment_getOwnedIdentity_returnsSameObject() {
        val att = makeObvAttachment(ownedIdentity = identity)
        assertSame(identity, att.ownedIdentity)
    }

    @Test
    fun attachment_getMessageUid_returnsSameObject() {
        val att = makeObvAttachment(attachmentMessageUid = attachmentUid)
        assertSame(attachmentUid, att.messageUid)
    }

    // ─── equals / hashCode (reference identity — no override) ────────────────

    @Test
    fun attachment_equalsIsSameReferenceOnly() {
        val att1 = makeObvAttachment()
        val att2 = makeObvAttachment()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Two separately constructed ObvAttachments must not be equal", att1.equals(att2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("An ObvAttachment must equal itself", att1.equals(att1))
    }

    @Test
    fun attachment_hashCodeIsStableAcrossCalls() {
        val att = makeObvAttachment()
        assertEquals(att.hashCode(), att.hashCode())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvMessage
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Constructed from a DecryptedApplicationMessage + ReceivedAttachment[].
    // Key behaviors:
    //   - getIdentifier() returns messageUid.getBytes()  (computed, not stored bytes)
    //   - null fromIdentity / fromDeviceUid / toIdentity → null byte[] fields
    //   - non-null Identity / UID → their .getBytes() stored as byte[]
    //   - attachments[] has same length as receivedAttachments[]
    //   - empty receivedAttachments[] → empty attachments[]
    //   - getServerTimestamp / getDownloadTimestamp / getLocalDownloadTimestamp
    //     exactly reflect the message fields

    private fun makeMessage(
        msgUid: UID = messageUid,
        payload: ByteArray = byteArrayOf(0x42),
        fromIdentity: Identity? = identity,
        fromDeviceUid: UID? = attachmentUid,
        toIdentity: Identity? = identity,
        serverTimestamp: Long = 1_700_000_000_000L,
        downloadTimestamp: Long = 1_700_000_001_000L,
        localDownloadTimestamp: Long = 1_700_000_002_000L,
        attachments: Array<ReceivedAttachment> = emptyArray(),
    ): ObvMessage {
        val decrypted = DecryptedApplicationMessage(
            msgUid, payload, fromIdentity, fromDeviceUid, toIdentity,
            serverTimestamp, downloadTimestamp, localDownloadTimestamp,
        )
        return ObvMessage(decrypted, attachments)
    }

    // ─── getIdentifier() — computed from messageUid.getBytes() ───────────────

    @Test
    fun message_getIdentifier_matchesMessageUidBytes() {
        val msg = makeMessage(msgUid = messageUid)
        assertArrayEquals(messageUid.bytes, msg.identifier)
    }

    @Test
    fun message_getIdentifier_hasCorrectLength() {
        val msg = makeMessage()
        assertEquals(UID.UID_LENGTH, msg.identifier!!.size)
    }

    // ─── Timestamp fields stored exactly ──────────────────────────────────────

    @Test
    fun message_getServerTimestamp_matchesInput() {
        val ts = 9_876_543_210_123L
        val msg = makeMessage(serverTimestamp = ts)
        assertEquals(ts, msg.serverTimestamp)
    }

    @Test
    fun message_getDownloadTimestamp_matchesInput() {
        val ts = 1_111_111_111_111L
        val msg = makeMessage(downloadTimestamp = ts)
        assertEquals(ts, msg.downloadTimestamp)
    }

    @Test
    fun message_getLocalDownloadTimestamp_matchesInput() {
        val ts = 2_222_222_222_222L
        val msg = makeMessage(localDownloadTimestamp = ts)
        assertEquals(ts, msg.localDownloadTimestamp)
    }

    // ─── messagePayload stored by reference ───────────────────────────────────

    @Test
    fun message_getMessagePayload_returnsStoredReference() {
        val payload = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val msg = makeMessage(payload = payload)
        assertSame(payload, msg.messagePayload)
    }

    // ─── fromIdentity / fromDeviceUid / toIdentity: non-null → bytes ─────────

    @Test
    fun message_getBytesFromIdentity_nonNull_matchesIdentityBytes() {
        val msg = makeMessage(fromIdentity = identity)
        assertArrayEquals(identity.getBytes(), msg.bytesFromIdentity)
    }

    @Test
    fun message_getBytesFromDeviceUid_nonNull_matchesUidBytes() {
        val deviceUid = attachmentUid
        val msg = makeMessage(fromDeviceUid = deviceUid)
        assertArrayEquals(deviceUid.bytes, msg.bytesFromDeviceUid)
    }

    @Test
    fun message_getBytesToIdentity_nonNull_matchesIdentityBytes() {
        val msg = makeMessage(toIdentity = identity)
        assertArrayEquals(identity.getBytes(), msg.bytesToIdentity)
    }

    // ─── fromIdentity / fromDeviceUid / toIdentity: null → null ──────────────

    @Test
    fun message_getBytesFromIdentity_nullInput_returnsNull() {
        val msg = makeMessage(fromIdentity = null)
        assertNull(msg.bytesFromIdentity)
    }

    @Test
    fun message_getBytesFromDeviceUid_nullInput_returnsNull() {
        val msg = makeMessage(fromDeviceUid = null)
        assertNull(msg.bytesFromDeviceUid)
    }

    @Test
    fun message_getBytesToIdentity_nullInput_returnsNull() {
        val msg = makeMessage(toIdentity = null)
        assertNull(msg.bytesToIdentity)
    }

    // ─── Attachments array fan-out ────────────────────────────────────────────

    @Test
    fun message_noAttachments_producesEmptyArray() {
        val msg = makeMessage(attachments = emptyArray())
        assertNotNull(msg.attachments)
        assertEquals(0, msg.attachments.size)
    }

    @Test
    fun message_oneAttachment_producesArrayOfSizeOne() {
        val received = ReceivedAttachment(
            identity, attachmentUid, 0, byteArrayOf(0x01), "url/1", 100L, 50L, false, false,
        )
        val msg = makeMessage(attachments = arrayOf(received))
        assertEquals(1, msg.attachments.size)
    }

    @Test
    fun message_threeAttachments_producesArrayOfSizeThree() {
        val received = Array(3) { i ->
            ReceivedAttachment(identity, attachmentUid, i, byteArrayOf(i.toByte()), "url/$i", 100L, 0L, false, true)
        }
        val msg = makeMessage(attachments = received)
        assertEquals(3, msg.attachments.size)
    }

    @Test
    fun message_attachmentFanOut_preservesAttachmentNumber() {
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 2, byteArrayOf(0x02), "u/2", 64L, 32L, false, true),
        )
        val msg = makeMessage(attachments = received)
        assertEquals(2, msg.attachments[0]!!.number)
    }

    @Test
    fun message_attachmentFanOut_preservesMetadata() {
        val metadata = byteArrayOf(0xCA.toByte(), 0xFE.toByte())
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, metadata, "u/0", 64L, 0L, false, false),
        )
        val msg = makeMessage(attachments = received)
        assertSame(metadata, msg.attachments[0]!!.metadata)
    }

    @Test
    fun message_attachmentFanOut_preservesUrl() {
        val url = "no_backup/attach/video.mp4"
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), url, 1_000L, 500L, false, true),
        )
        val msg = makeMessage(attachments = received)
        assertEquals(url, msg.attachments[0]!!.url)
    }

    @Test
    fun message_attachmentFanOut_usesMessageServerTimestampNotAttachmentTimestamp() {
        // The server timestamp propagated to ObvAttachment must come from the
        // DecryptedApplicationMessage, not from ReceivedAttachment (which doesn't
        // even have a server timestamp field).
        val msgTimestamp = 1_600_000_000_000L
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), "u/0", 100L, 0L, false, false),
        )
        val msg = makeMessage(serverTimestamp = msgTimestamp, attachments = received)
        assertEquals(msgTimestamp, msg.attachments[0]!!.messageServerTimestamp)
    }

    @Test
    fun message_attachmentFanOut_preservesExpectedLength() {
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), "u/0", 2_097_152L, 1_024L, false, true),
        )
        val msg = makeMessage(attachments = received)
        assertEquals(2_097_152L, msg.attachments[0]!!.expectedLength)
    }

    @Test
    fun message_attachmentFanOut_preservesReceivedLength() {
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), "u/0", 2_097_152L, 65_536L, false, true),
        )
        val msg = makeMessage(attachments = received)
        assertEquals(65_536L, msg.attachments[0]!!.receivedLength)
    }

    @Test
    fun message_attachmentFanOut_preservesDownloadRequested_false() {
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), "u/0", 100L, 0L, false, false),
        )
        val msg = makeMessage(attachments = received)
        assertFalse(msg.attachments[0]!!.isDownloadRequested())
    }

    @Test
    fun message_attachmentFanOut_preservesDownloadRequested_true() {
        val received = arrayOf(
            ReceivedAttachment(identity, attachmentUid, 0, byteArrayOf(), "u/0", 100L, 0L, false, true),
        )
        val msg = makeMessage(attachments = received)
        assertTrue(msg.attachments[0]!!.isDownloadRequested())
    }

    // ─── equals / hashCode (reference identity — no override) ────────────────

    @Test
    fun message_equalsIsSameReferenceOnly() {
        val msg1 = makeMessage()
        val msg2 = makeMessage()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Two separately constructed ObvMessages must not be equal", msg1.equals(msg2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("An ObvMessage must equal itself", msg1.equals(msg1))
    }

    @Test
    fun message_hashCodeIsStableAcrossCalls() {
        val msg = makeMessage()
        assertEquals(msg.hashCode(), msg.hashCode())
    }
}
