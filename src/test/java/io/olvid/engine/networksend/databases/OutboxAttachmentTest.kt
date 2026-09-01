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

package io.olvid.engine.networksend.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.AuthEnc
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Chunk
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.networksend.datatypes.SendManagerSession
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Field

/**
 * Characterization tests for [OutboxAttachment] before its Java→Kotlin migration.
 *
 * Scope: pure in-memory behavior that does NOT touch a live database:
 *  - [OutboxAttachment.computeUniqueUid]: determinism, sensitivity to each input, output
 *    length, and a wire-format pin that catches any byte-order regression in the hash input.
 *  - [OutboxAttachment.getChunkUploadPrivateUrls]: null → empty array; `"¦"`-split logic
 *    including the -1 limit semantics (trailing empties kept).
 *  - [OutboxAttachment.getCleartextChunkLength]: memoisation — computed once, cached.
 *  - [OutboxAttachment.getNumberOfChunks]: integer-division formula across boundary cases.
 *  - [OutboxAttachment.getRemainingByteCountToSend]: floor at 0; simple subtraction.
 *  - [OutboxAttachment.getPriority]: delegates to [OutboxAttachment.getRemainingByteCountToSend].
 *  - [OutboxAttachment.isAcknowledged]: exposes the `acknowledged` field correctly.
 *  - [OutboxAttachment.create] null-guards (four guarded params).
 *  - Private constructor: all fields stored and returned by getters.
 *  - `equals` / `hashCode` preserve reference-identity semantics (not overridden).
 *  - `wasCommitted()` with `commitHookBits == 0` does not throw with a null session.
 *
 * Out of scope: insert/delete/get/getAll/getAllToCancel/createTable/upgradeTable,
 * all setters that issue SQL (setCancelExternallyRequested, setCancelProcessed,
 * setAcknowledgedChunkCount, setChunkUploadPrivateUrls), and the notification paths in
 * wasCommitted — all require a live [io.olvid.engine.datatypes.Session].
 */
class OutboxAttachmentTest {

    // ─── Test fixtures ─────────────────────────────────────────────────────────

    private lateinit var ownedIdentity: Identity
    private lateinit var secondIdentity: Identity
    private lateinit var messageUid: UID
    private lateinit var secondMessageUid: UID
    private lateinit var authEncKey: AuthEncKey

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

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        fun makeIdentity(server: String): Identity {
            val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
            val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
            return Identity(
                server,
                serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
                encryptionKeyPair.publicKey as EncryptionPublicKey,
            )
        }

        ownedIdentity = makeIdentity("test.olvid.io")
        secondIdentity = makeIdentity("other.olvid.io")
        messageUid = UID(prng)
        secondMessageUid = UID(prng)
        authEncKey = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!.generateKey(prng)!!
    }

    // ─── Reflection helpers ────────────────────────────────────────────────────

    /**
     * Builds an [OutboxAttachment] via the private (SendManagerSession, Identity, UID, int,
     * String, boolean, long, AuthEncKey) constructor without going through [OutboxAttachment.create]
     * (which calls `insert()` and requires a real Session).
     */
    private fun build(
        session: SendManagerSession? = null,
        ownedIdentity: Identity = this.ownedIdentity,
        messageUid: UID = this.messageUid,
        attachmentNumber: Int = 0,
        url: String = "fyles/ABCDEF1234567890",
        deleteAfterSend: Boolean = false,
        attachmentLength: Long = 1024L,
        key: AuthEncKey = this.authEncKey,
    ): OutboxAttachment {
        val ctor = OutboxAttachment::class.java.getDeclaredConstructor(
            SendManagerSession::class.java,
            Identity::class.java,
            UID::class.java,
            Int::class.javaPrimitiveType,
            String::class.java,
            Boolean::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            AuthEncKey::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(session, ownedIdentity, messageUid, attachmentNumber, url, deleteAfterSend, attachmentLength, key)
    }

    private fun setField(obj: OutboxAttachment, name: String, value: Any?) {
        val f: Field = OutboxAttachment::class.java.getDeclaredField(name)
        f.isAccessible = true
        f.set(obj, value)
    }

    private fun getField(obj: OutboxAttachment, name: String): Any? {
        val f: Field = OutboxAttachment::class.java.getDeclaredField(name)
        f.isAccessible = true
        return f.get(obj)
    }

    // ─── 1. computeUniqueUid — determinism ────────────────────────────────────

    @Test
    fun testComputeUniqueUidIsDeterministic() {
        val uid1 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        val uid2 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        assertArrayEquals(uid1.bytes, uid2.bytes)
    }

    @Test
    fun testComputeUniqueUidOutputIs32Bytes() {
        val uid = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        assertEquals(UID.UID_LENGTH, uid.bytes.size)
    }

    @Test
    fun testComputeUniqueUidChangesWhenOwnedIdentityChanges() {
        val uid1 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        val uid2 = OutboxAttachment.computeUniqueUid(secondIdentity, messageUid, 0)
        assertFalse(uid1.bytes.contentEquals(uid2.bytes))
    }

    @Test
    fun testComputeUniqueUidChangesWhenMessageUidChanges() {
        val uid1 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        val uid2 = OutboxAttachment.computeUniqueUid(ownedIdentity, secondMessageUid, 0)
        assertFalse(uid1.bytes.contentEquals(uid2.bytes))
    }

    @Test
    fun testComputeUniqueUidChangesWhenAttachmentNumberChanges() {
        val uid0 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 0)
        val uid1 = OutboxAttachment.computeUniqueUid(ownedIdentity, messageUid, 1)
        assertFalse(uid0.bytes.contentEquals(uid1.bytes))
    }

    /**
     * Wire-format pin test.
     *
     * Uses a fixed PRNG reseed (all-zero 32-byte seed) and all-zero messageUid so the
     * computation is fully deterministic. The expected hex was captured on the first run
     * and pinned here. Any Kotlin migration that changes the byte-layout of the hash input
     * (e.g. wrong concatenation order, missing encoded header) will change this value and
     * fail the test — exactly what we want.
     *
     * Expected value computed as:
     *   SHA-256( ownedIdentity.getBytes() ++ messageUid.getBytes(32 zeros) ++ Encoded.of(0).getBytes() )
     */
    @Test
    fun testComputeUniqueUidWireFormatPin() {
        // Fresh deterministic PRNG — separate from @Before to be fully self-contained.
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val pinIdentity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
        val zeroUid = UID(ByteArray(UID.UID_LENGTH))

        val uid = OutboxAttachment.computeUniqueUid(pinIdentity, zeroUid, 0)

        // Captured on first run — DO NOT change this literal; it is the wire-format
        // contract.  Update only if the hash input format is intentionally changed AND
        // the protocol team approves.
        //
        // Input layout: ownedIdentity.getBytes() ++ messageUid.getBytes(32 zeros)
        //               ++ Encoded.of(0).getBytes()  (13 bytes: 5-byte header + 8-byte int)
        // Hash: SHA-256 of the concatenated input.
        val expectedHex = "98571db23f7e4d9982c735e521bbd76ca4512e2ff54b88d5b484a1f26476cb22"
        assertEquals(UID.UID_LENGTH, uid.bytes.size)
        assertArrayEquals(
            fromHex(expectedHex),
            uid.bytes,
        )
    }

    // ─── 2. getChunkUploadPrivateUrls — split logic ───────────────────────────

    @Test
    fun testGetChunkUploadPrivateUrlsNullReturnsEmptyArray() {
        val obj = build()
        // chunkUploadPrivateUrls is null by constructor default
        val result = obj.getChunkUploadPrivateUrls()
        assertEquals(0, result.size)
    }

    @Test
    fun testGetChunkUploadPrivateUrlsThreeElements() {
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "a¦b¦c")
        val result = obj.getChunkUploadPrivateUrls()
        assertArrayEquals(arrayOf("a", "b", "c"), result)
    }

    @Test
    fun testGetChunkUploadPrivateUrlsMiddleEmptyElement() {
        // "a¦¦b" with -1 limit: empty string between the two separators is preserved
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "a¦¦b")
        val result = obj.getChunkUploadPrivateUrls()
        assertArrayEquals(arrayOf("a", "", "b"), result)
    }

    @Test
    fun testGetChunkUploadPrivateUrlsEmptyString() {
        // split("¦", -1) on "" returns [""] — a single-element array containing the
        // empty string.  This is standard Java/Kotlin split semantics.
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "")
        val result = obj.getChunkUploadPrivateUrls()
        assertEquals(1, result.size)
        assertEquals("", result[0])
    }

    @Test
    fun testGetChunkUploadPrivateUrlsNoSeparator() {
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "a")
        val result = obj.getChunkUploadPrivateUrls()
        assertArrayEquals(arrayOf("a"), result)
    }

    @Test
    fun testGetChunkUploadPrivateUrlsJustSeparator() {
        // "¦" split with -1 limit → ["", ""]
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "¦")
        val result = obj.getChunkUploadPrivateUrls()
        assertArrayEquals(arrayOf("", ""), result)
    }

    @Test
    fun testGetChunkUploadPrivateUrlsTrailingEmpty() {
        // "a¦" split with -1 limit keeps the trailing empty string
        val obj = build()
        setField(obj, "chunkUploadPrivateUrls", "a¦")
        val result = obj.getChunkUploadPrivateUrls()
        assertArrayEquals(arrayOf("a", ""), result)
    }

    // ─── 3. getCleartextChunkLength — memoisation ────────────────────────────

    @Test
    fun testGetCleartextChunkLengthIsNonZero() {
        // DEFAULT_ATTACHMENT_CHUNK_LENGTH is 4*2048*1024 = 8 388 608 bytes of ciphertext.
        // After stripping the AES-IV (16 bytes) and HMAC-SHA256 (32 bytes) overhead, and
        // then the Chunk encoding header, the cleartext chunk is still > 0.
        val obj = build(attachmentLength = 1024L)
        val cleartextChunkLength = obj.cleartextChunkLength
        assertTrue("cleartextChunkLength must be > 0", cleartextChunkLength > 0)
    }

    @Test
    fun testGetCleartextChunkLengthIsMemoised() {
        // Calling twice must return the identical value, and that value must not be 0
        // after the first call (proving the cache was filled).
        val obj = build(attachmentLength = 1024L)
        val first = obj.cleartextChunkLength
        val second = obj.cleartextChunkLength
        assertEquals(first, second)
        assertTrue(first > 0)
    }

    @Test
    fun testGetCleartextChunkLengthCachedInField() {
        // After the first call, the private `attachmentChunkLength` field must be non-zero.
        val obj = build(attachmentLength = 1024L)
        obj.cleartextChunkLength  // trigger computation
        val cached = getField(obj, "attachmentChunkLength") as Int
        assertTrue("attachmentChunkLength field must be cached after first call", cached > 0)
    }

    // ─── 4. getNumberOfChunks — integer-division formula ─────────────────────

    /**
     * Helper: build an instance whose `ciphertextChunkLength` is [Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH]
     * (set by the constructor) and whose `attachmentLength` is [attachmentLength].
     * Then compute the cleartext chunk length once so memoisation is primed.
     */
    private fun buildForChunks(attachmentLength: Long): OutboxAttachment {
        return build(attachmentLength = attachmentLength)
    }

    @Test
    fun testGetNumberOfChunksExactlyOneChunkLength() {
        // attachmentLength == cleartextChunkLength → 1 chunk
        val obj = buildForChunks(1024L)
        val n = obj.cleartextChunkLength.toLong()
        val obj2 = buildForChunks(n)
        assertEquals(1, obj2.numberOfChunks)
    }

    @Test
    fun testGetNumberOfChunksOneBeyondOneChunkLength() {
        // attachmentLength == cleartextChunkLength + 1 → 2 chunks
        val obj = buildForChunks(1024L)
        val n = obj.cleartextChunkLength.toLong()
        val obj2 = buildForChunks(n + 1)
        assertEquals(2, obj2.numberOfChunks)
    }

    @Test
    fun testGetNumberOfChunksMinimum() {
        // attachmentLength = 1 → 1 chunk
        val obj = buildForChunks(1L)
        assertEquals(1, obj.numberOfChunks)
    }

    @Test
    fun testGetNumberOfChunksTwoExactChunkLengths() {
        // attachmentLength == 2 * cleartextChunkLength → 2 chunks
        // formula: 1 + (2N - 1) / N = 1 + 1 = 2 (for N > 1, integer division)
        val obj = buildForChunks(1024L)
        val n = obj.cleartextChunkLength.toLong()
        val obj2 = buildForChunks(2 * n)
        assertEquals(2, obj2.numberOfChunks)
    }

    @Test
    fun testGetNumberOfChunksTwoChunkLengthsPlusOne() {
        // attachmentLength == 2 * cleartextChunkLength + 1 → 3 chunks
        val obj = buildForChunks(1024L)
        val n = obj.cleartextChunkLength.toLong()
        val obj2 = buildForChunks(2 * n + 1)
        assertEquals(3, obj2.numberOfChunks)
    }

    // ─── 5. getRemainingByteCountToSend — floor at 0 ─────────────────────────

    @Test
    fun testGetRemainingByteCountToSendFloorAtZeroWhenOverAcknowledged() {
        // When acknowledgedChunkCount * ciphertextChunkLength exceeds the ciphertextLength
        // (can happen e.g. on a server re-ack after full upload), the result is 0 — not
        // negative.
        val obj = build(attachmentLength = 1024L)
        // Force acknowledgedChunkCount to a huge value via reflection
        setField(obj, "acknowledgedChunkCount", Int.MAX_VALUE)
        assertEquals(0L, obj.remainingByteCountToSend)
    }

    @Test
    fun testGetRemainingByteCountToSendSimpleSubtraction() {
        // With 0 acknowledged chunks, remaining == ciphertextLength.
        val obj = build(attachmentLength = 1024L)
        setField(obj, "acknowledgedChunkCount", 0)
        val remaining = obj.remainingByteCountToSend
        assertEquals(obj.ciphertextLength, remaining)
    }

    @Test
    fun testGetRemainingByteCountToSendPartialAcknowledgement() {
        // After acknowledging 1 chunk, remaining decreases by ciphertextChunkLength
        // (unless the final value would go negative, which is clamped to 0).
        val obj = build(attachmentLength = (Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH.toLong() * 3))
        setField(obj, "acknowledgedChunkCount", 1)
        val remaining = obj.remainingByteCountToSend
        val expected = obj.ciphertextLength - obj.ciphertextChunkLength.toLong()
        assertTrue(remaining >= 0L)
        assertEquals(expected, remaining)
    }

    @Test
    fun testGetRemainingByteCountToSendIsNeverNegative() {
        val obj = build(attachmentLength = 1024L)
        setField(obj, "acknowledgedChunkCount", 999_999)
        assertTrue(obj.remainingByteCountToSend >= 0L)
    }

    // ─── 6. getPriority — delegates to getRemainingByteCountToSend ───────────

    @Test
    fun testGetPriorityEqualsRemainingByteCountToSend() {
        val obj = build(attachmentLength = 1024L)
        assertEquals(obj.remainingByteCountToSend, obj.priority)
    }

    @Test
    fun testGetPriorityEqualsRemainingByteCountToSendAfterPartialAcknowledgement() {
        val obj = build(attachmentLength = (Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH.toLong() * 2))
        setField(obj, "acknowledgedChunkCount", 1)
        assertEquals(obj.remainingByteCountToSend, obj.priority)
    }

    // ─── 7. isAcknowledged — field access ────────────────────────────────────

    @Test
    fun testIsAcknowledgedIsFalseByDefault() {
        val obj = build()
        assertFalse(obj.isAcknowledged)
    }

    @Test
    fun testIsAcknowledgedReturnsTrueAfterFieldIsSet() {
        val obj = build()
        setField(obj, "isAcknowledged",true)
        assertTrue(obj.isAcknowledged)
    }

    @Test
    fun testIsAcknowledgedReturnsFalseAfterFieldResetToFalse() {
        val obj = build()
        setField(obj, "isAcknowledged",true)
        setField(obj, "isAcknowledged",false)
        assertFalse(obj.isAcknowledged)
    }

    // ─── 8. create() null-guards ──────────────────────────────────────────────

    @Test
    fun testCreateReturnsNullWhenOwnedIdentityIsNull() {
        val result = OutboxAttachment.create(null, null, messageUid, 0, "fyles/ABCDEF", false, 1024L, authEncKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenMessageUidIsNull() {
        val result = OutboxAttachment.create(null, ownedIdentity, null, 0, "fyles/ABCDEF", false, 1024L, authEncKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenUrlIsNull() {
        val result = OutboxAttachment.create(null, ownedIdentity, messageUid, 0, null, false, 1024L, authEncKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenKeyIsNull() {
        val result = OutboxAttachment.create(null, ownedIdentity, messageUid, 0, "fyles/ABCDEF", false, 1024L, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenAllGuardedParamsAreNull() {
        val result = OutboxAttachment.create(null, null, null, 0, null, false, 1024L, null)
        assertNull(result)
    }

    // ─── 9. Constructor field storage ────────────────────────────────────────

    @Test
    fun testConstructorStoresOwnedIdentity() {
        val obj = build(ownedIdentity = ownedIdentity)
        assertSame(ownedIdentity, obj.getOwnedIdentity())
    }

    @Test
    fun testConstructorStoresMessageUid() {
        val obj = build(messageUid = messageUid)
        assertSame(messageUid, obj.messageUid)
    }

    @Test
    fun testConstructorStoresAttachmentNumber() {
        val obj = build(attachmentNumber = 7)
        assertEquals(7, obj.attachmentNumber)
    }

    @Test
    fun testConstructorStoresUrl() {
        val obj = build(url = "fyles/DEADBEEF")
        assertEquals("fyles/DEADBEEF", obj.url)
    }

    @Test
    fun testConstructorStoresDeleteAfterSendTrue() {
        val obj = build(deleteAfterSend = true)
        assertTrue(obj.shouldBeDeletedAfterSend())
    }

    @Test
    fun testConstructorStoresDeleteAfterSendFalse() {
        val obj = build(deleteAfterSend = false)
        assertFalse(obj.shouldBeDeletedAfterSend())
    }

    @Test
    fun testConstructorStoresAttachmentLength() {
        val obj = build(attachmentLength = 987654321L)
        assertEquals(987654321L, obj.attachmentLength)
    }

    @Test
    fun testConstructorStoresKey() {
        val obj = build(key = authEncKey)
        assertSame(authEncKey, obj.key)
    }

    @Test
    fun testConstructorInitialisesAcknowledgedChunkCountToZero() {
        val obj = build()
        assertEquals(0, obj.getAcknowledgedChunkCount())
    }

    @Test
    fun testConstructorInitialisesAcknowledgedToFalse() {
        val obj = build()
        assertFalse(obj.isAcknowledged)
    }

    @Test
    fun testConstructorInitialisesChunkUploadPrivateUrlsToNull() {
        val obj = build()
        // null → getChunkUploadPrivateUrls() returns empty array
        assertEquals(0, obj.getChunkUploadPrivateUrls().size)
        assertNull(getField(obj, "chunkUploadPrivateUrls"))
    }

    @Test
    fun testConstructorInitialisesCancelExternallyRequestedToFalse() {
        val obj = build()
        assertFalse(obj.isCancelExternallyRequested)
    }

    @Test
    fun testConstructorSetsCiphertextChunkLengthToDefault() {
        val obj = build()
        assertEquals(Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH, obj.ciphertextChunkLength)
    }

    // ─── 10. Getters delegate to fields (no transformation) ──────────────────

    @Test
    fun testGetOwnedIdentityReturnsField() {
        val obj = build(ownedIdentity = ownedIdentity)
        assertEquals(ownedIdentity, obj.getOwnedIdentity())
    }

    @Test
    fun testGetMessageUidReturnsField() {
        val obj = build(messageUid = messageUid)
        assertEquals(messageUid, obj.messageUid)
    }

    @Test
    fun testGetAttachmentNumberReturnsField() {
        val obj = build(attachmentNumber = 42)
        assertEquals(42, obj.attachmentNumber)
    }

    @Test
    fun testGetUrlReturnsField() {
        val obj = build(url = "fyles/11223344")
        assertEquals("fyles/11223344", obj.url)
    }

    @Test
    fun testGetAttachmentLengthReturnsField() {
        val obj = build(attachmentLength = 5_000_000L)
        assertEquals(5_000_000L, obj.attachmentLength)
    }

    @Test
    fun testGetKeyReturnsField() {
        val obj = build(key = authEncKey)
        assertSame(authEncKey, obj.key)
    }

    @Test
    fun testGetAcknowledgedChunkCountReturnsField() {
        val obj = build()
        setField(obj, "acknowledgedChunkCount", 5)
        assertEquals(5, obj.getAcknowledgedChunkCount())
    }

    @Test
    fun testGetCiphertextChunkLengthReturnsField() {
        val obj = build()
        assertEquals(Constants.DEFAULT_ATTACHMENT_CHUNK_LENGTH, obj.ciphertextChunkLength)
    }

    @Test
    fun testIsCancelExternallyRequestedReturnsField() {
        val obj = build()
        assertFalse(obj.isCancelExternallyRequested)
        setField(obj, "isCancelExternallyRequested",true)
        assertTrue(obj.isCancelExternallyRequested)
    }

    // ─── 11. equals / hashCode — reference identity (not overridden) ─────────

    @Test
    fun testEqualsIsReferenceIdentity() {
        val obj1 = build()
        val obj2 = build()
        // Java source does NOT override equals; same-fields instances must NOT be equal.
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj1.equals(obj1))
    }

    @Test
    fun testHashCodeIsStableAcrossCalls() {
        val obj = build()
        assertEquals(obj.hashCode(), obj.hashCode())
    }

    @Test
    fun testTwoDistinctInstancesAreNotSame() {
        val obj1 = build()
        val obj2 = build()
        assertNotSame(obj1, obj2)
    }

    // ─── 12. wasCommitted() with commitHookBits == 0 does not throw ───────────

    @Test
    fun testWasCommittedWithZeroHookBitsDoesNotThrow() {
        // Fresh instances have commitHookBits == 0 and sendManagerSession == null.
        // wasCommitted() must not NPE when the notification delegates are unreachable.
        val obj = build(session = null)
        // Must complete without throwing
        obj.wasCommitted()
    }

    @Test
    fun testWasCommittedDoesNotMutateVisibleState() {
        val obj = build()
        val ownedIdentityBefore = obj.getOwnedIdentity()
        val messageUidBefore = obj.messageUid
        val acknowledgedBefore = obj.isAcknowledged

        obj.wasCommitted()

        assertSame(ownedIdentityBefore, obj.getOwnedIdentity())
        assertSame(messageUidBefore, obj.messageUid)
        assertEquals(acknowledgedBefore, obj.isAcknowledged)
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    private fun fromHex(hex: String): ByteArray {
        val len = hex.length
        val result = ByteArray(len / 2)
        for (i in 0 until len / 2) {
            result[i] = ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return result
    }
}
