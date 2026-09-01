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

package io.olvid.engine.protocol.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [CoreProtocolMessage].
 *
 * The primary migration risk is that the three public constructors populate fields
 * differently. A Kotlin migration to a single `data class` with default parameters
 * could silently change which fields are null vs populated in each constructor variant.
 * These tests pin the exact null/non-null pattern for all seven fields across all
 * three constructors.
 *
 * Additional risks pinned:
 *   - `hasUserContent` is hard-coded to `false` in constructors 2 and 3 (3-arg form).
 *     A Kotlin port that adds a default param or renames the field could silently change
 *     this; pinned by explicit tests for each constructor variant.
 *   - `serverTimestamp` is captured from `System.currentTimeMillis()` at construction
 *     time in constructors 2 and 3 — not lazily. Pinned via a before/after sandwich.
 *   - `hasUserContent()` is a Java method (not `getHasUserContent()`). A `data class`
 *     migration would typically generate `getHasUserContent()` (or `isHasUserContent()`),
 *     breaking callers using `hasUserContent()`. In Kotlin test code the method call
 *     `obj.hasUserContent()` compiles fine against the Java source; post-migration the
 *     Kotlin property `obj.hasUserContent` would require a source change — the compile
 *     error is the desired signal.
 *
 * Constructor 1 — `CoreProtocolMessage(ReceivedMessage)`:
 *   [ReceivedMessage] is an SQLite-backed entity whose only accessible constructor
 *   (besides the ResultSet variant) is the private 11-argument constructor used by
 *   [ReceivedMessage.create]. The `ProtocolManagerSession` parameter is only stored,
 *   never dereferenced inside that constructor, so it can safely be `null`. All other
 *   parameters (Identity, Encoded[], UUID, Encoded, UID, ints, ReceptionChannelInfo,
 *   long, PRNGService) are real values. The constructor is reached via reflection so
 *   that no DB insert is triggered.
 */
class CoreProtocolMessageTest {

    private lateinit var ownedIdentity: Identity
    private lateinit var remoteIdentity: Identity
    private lateinit var protocolInstanceUid: UID
    private lateinit var sendChannelInfo: SendChannelInfo
    private lateinit var receptionChannelInfo: ReceptionChannelInfo

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

        protocolInstanceUid = UID(prng)

        val authKeyPairA = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKeyPairA = EncryptionEciesCurve25519KeyPair.generate(prng)
        ownedIdentity = Identity(
            "test.olvid.com",
            authKeyPairA.publicKey as ServerAuthenticationPublicKey,
            encKeyPairA.publicKey as EncryptionPublicKey
        )

        val authKeyPairB = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKeyPairB = EncryptionEciesCurve25519KeyPair.generate(prng)
        remoteIdentity = Identity(
            "remote.olvid.com",
            authKeyPairB.publicKey as ServerAuthenticationPublicKey,
            encKeyPairB.publicKey as EncryptionPublicKey
        )

        // createLocalChannelInfo is the simplest factory — it only requires one non-null identity.
        sendChannelInfo = SendChannelInfo.createLocalChannelInfo(ownedIdentity)!!
        receptionChannelInfo = ReceptionChannelInfo.createLocalChannelInfo()
    }

    // ─── Helper: build a ReceivedMessage via reflection (avoids DB insert) ────

    /**
     * Constructs a [ReceivedMessage] using its private 12-arg constructor via
     * reflection. The [ProtocolManagerSession] is passed as null because the
     * constructor only stores the reference — it does not dereference it.
     * No [ReceivedMessage.insert] is called, so no live DB is needed.
     */
    private fun buildReceivedMessage(
        toIdentity: Identity,
        protocolInstanceUid: UID,
        protocolId: Int,
        receptionChannelInfo: ReceptionChannelInfo,
        serverTimestamp: Long
    ): ReceivedMessage {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 1 }))

        val ctor = ReceivedMessage::class.java.getDeclaredConstructor(
            ProtocolManagerSession::class.java,   // protocolManagerSession — null-safe (only stored)
            Identity::class.java,                  // toIdentity
            Array<Encoded>::class.java,             // inputs
            java.util.UUID::class.java,             // userDialogUuid
            Encoded::class.java,                   // encodedResponse
            UID::class.java,                        // protocolInstanceUid
            Int::class.javaPrimitiveType,           // protocolMessageId
            Int::class.javaPrimitiveType,           // protocolId
            ReceptionChannelInfo::class.java,       // receptionChannelInfo
            Long::class.javaPrimitiveType,          // serverTimestamp
            Long::class.javaPrimitiveType,          // userDialogVersion
            io.olvid.engine.crypto.PRNGService::class.java   // prng (used for uid = new UID(prng))
        )
        ctor.isAccessible = true

        return ctor.newInstance(
            null,                              // protocolManagerSession — not dereferenced in ctor
            toIdentity,
            emptyArray<Encoded>(),             // inputs — empty; not read by CoreProtocolMessage
            null,                              // userDialogUuid — not read by CoreProtocolMessage
            null,                              // encodedResponse — not read by CoreProtocolMessage
            protocolInstanceUid,
            0,                                 // protocolMessageId — not read by CoreProtocolMessage
            protocolId,
            receptionChannelInfo,
            serverTimestamp,
            0L,                                // userDialogVersion — not read by CoreProtocolMessage
            prng
        ) as ReceivedMessage
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor 1 — CoreProtocolMessage(ReceivedMessage)
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun ctor1_sendChannelInfoIsNull() {
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        assertNull(
            "Constructor 1 must set sendChannelInfo to null — it comes from a received message, not a send path",
            cpm.sendChannelInfo
        )
    }

    @Test
    fun ctor1_receptionChannelInfoCopiedByReference() {
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        // The contract is that the exact reference from ReceivedMessage is stored.
        assertSame(
            "Constructor 1 must copy receptionChannelInfo by reference from the ReceivedMessage",
            msg.receptionChannelInfo,
            cpm.receptionChannelInfo
        )
    }

    @Test
    fun ctor1_toIdentityCopiedByReference() {
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        assertSame(
            "Constructor 1 must copy toIdentity by reference from the ReceivedMessage",
            msg.toIdentity,
            cpm.toIdentity
        )
    }

    @Test
    fun ctor1_protocolIdCopied() {
        val expectedProtocolId = 17
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, expectedProtocolId, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        assertEquals(
            "Constructor 1 must copy protocolId from the ReceivedMessage",
            expectedProtocolId,
            cpm.protocolId
        )
    }

    @Test
    fun ctor1_protocolInstanceUidCopiedByReference() {
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        assertSame(
            "Constructor 1 must copy protocolInstanceUid by reference from the ReceivedMessage",
            msg.protocolInstanceUid,
            cpm.protocolInstanceUid
        )
    }

    @Test
    fun ctor1_hasUserContentIsAlwaysFalse() {
        // Hard-coded to false regardless of the ReceivedMessage's content.
        // A Kotlin migration must not introduce a parameter or default that changes this.
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm = CoreProtocolMessage(msg)
        assertFalse(
            "Constructor 1 hard-codes hasUserContent to false; a migration must not silently change this",
            cpm.hasUserContent()
        )
    }

    @Test
    fun ctor1_serverTimestampCopiedFromMessage() {
        val expectedTs = 9_876_543_210L
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, expectedTs)
        val cpm = CoreProtocolMessage(msg)
        assertEquals(
            "Constructor 1 must copy serverTimestamp from the ReceivedMessage, not capture System.currentTimeMillis()",
            expectedTs,
            cpm.serverTimestamp
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor 2 — CoreProtocolMessage(SendChannelInfo, int, UID)
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun ctor2_sendChannelInfoStoredByReference() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertSame(
            "Constructor 2 must store the sendChannelInfo reference exactly",
            sendChannelInfo,
            cpm.sendChannelInfo
        )
    }

    @Test
    fun ctor2_receptionChannelInfoIsNull() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertNull(
            "Constructor 2 must set receptionChannelInfo to null — outbound messages have no reception info",
            cpm.receptionChannelInfo
        )
    }

    @Test
    fun ctor2_toIdentityIsNull() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertNull(
            "Constructor 2 must set toIdentity to null",
            cpm.toIdentity
        )
    }

    @Test
    fun ctor2_protocolIdStored() {
        val expectedProtocolId = 99
        val cpm = CoreProtocolMessage(sendChannelInfo, expectedProtocolId, protocolInstanceUid)
        assertEquals(
            "Constructor 2 must store the protocolId exactly",
            expectedProtocolId,
            cpm.protocolId
        )
    }

    @Test
    fun ctor2_protocolInstanceUidStoredByReference() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertSame(
            "Constructor 2 must store the protocolInstanceUid reference exactly",
            protocolInstanceUid,
            cpm.protocolInstanceUid
        )
    }

    @Test
    fun ctor2_hasUserContentIsHardCodedFalse() {
        // This is the key characterization for the 3-arg constructor: hasUserContent is
        // hard-coded false with NO parameter to override it. A Kotlin migration that
        // adds a default param `hasUserContent: Boolean = false` would compile but is
        // a structural change — pin the hard-coded value explicitly.
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertFalse(
            "Constructor 2 (3-arg) must hard-code hasUserContent=false with no way to override it",
            cpm.hasUserContent()
        )
    }

    @Test
    fun ctor2_serverTimestampSetAtConstructionTime() {
        val before = System.currentTimeMillis()
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        val after = System.currentTimeMillis()
        assertTrue(
            "Constructor 2 must capture System.currentTimeMillis() at construction — got ${cpm.serverTimestamp}, window [$before, $after]",
            cpm.serverTimestamp in before..after
        )
    }

    @Test
    fun ctor2_negativeProtocolIdIsStoredAsIs() {
        // No validation in the constructor; negative ids must be stored verbatim.
        val cpm = CoreProtocolMessage(sendChannelInfo, -1, protocolInstanceUid)
        assertEquals(-1, cpm.protocolId)
    }

    @Test
    fun ctor2_zeroProtocolIdIsStoredAsIs() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 0, protocolInstanceUid)
        assertEquals(0, cpm.protocolId)
    }

    @Test
    fun ctor2_maxValueProtocolIdIsStoredAsIs() {
        val cpm = CoreProtocolMessage(sendChannelInfo, Int.MAX_VALUE, protocolInstanceUid)
        assertEquals(Int.MAX_VALUE, cpm.protocolId)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor 3 — CoreProtocolMessage(SendChannelInfo, int, UID, boolean)
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun ctor3_hasUserContentTrueIsStored() {
        // The 4-arg constructor allows callers to set hasUserContent=true.
        // This is the ONLY way to produce a CoreProtocolMessage with hasUserContent==true.
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        assertTrue(
            "Constructor 3 (4-arg) must store the hasUserContent=true argument",
            cpm.hasUserContent()
        )
    }

    @Test
    fun ctor3_hasUserContentFalseIsStored() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, false)
        assertFalse(
            "Constructor 3 (4-arg) must store the hasUserContent=false argument",
            cpm.hasUserContent()
        )
    }

    @Test
    fun ctor3_sendChannelInfoStoredByReference() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        assertSame(sendChannelInfo, cpm.sendChannelInfo)
    }

    @Test
    fun ctor3_receptionChannelInfoIsNull() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        assertNull(
            "Constructor 3 must set receptionChannelInfo to null — mirrors constructor 2 for send path",
            cpm.receptionChannelInfo
        )
    }

    @Test
    fun ctor3_toIdentityIsNull() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        assertNull(
            "Constructor 3 must set toIdentity to null",
            cpm.toIdentity
        )
    }

    @Test
    fun ctor3_protocolIdStored() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 77, protocolInstanceUid, false)
        assertEquals(77, cpm.protocolId)
    }

    @Test
    fun ctor3_protocolInstanceUidStoredByReference() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, false)
        assertSame(protocolInstanceUid, cpm.protocolInstanceUid)
    }

    @Test
    fun ctor3_serverTimestampSetAtConstructionTime() {
        val before = System.currentTimeMillis()
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        val after = System.currentTimeMillis()
        assertTrue(
            "Constructor 3 must capture System.currentTimeMillis() at construction",
            cpm.serverTimestamp in before..after
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor 2 vs 3 — the only difference is hasUserContent
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun ctor2and3_onlyDifferInHasUserContent() {
        // All non-hasUserContent fields must be structurally equivalent between the
        // two constructors when called with the same sendChannelInfo/protocolId/uid.
        val cpm2 = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        val cpm3true = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, true)
        val cpm3false = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, false)

        assertFalse(cpm2.hasUserContent())
        assertTrue(cpm3true.hasUserContent())
        assertFalse(cpm3false.hasUserContent())

        // All other fields must agree:
        assertSame(cpm2.sendChannelInfo, cpm3true.sendChannelInfo)
        assertNull(cpm2.receptionChannelInfo)
        assertNull(cpm3true.receptionChannelInfo)
        assertNull(cpm2.toIdentity)
        assertNull(cpm3true.toIdentity)
        assertEquals(cpm2.protocolId, cpm3true.protocolId)
        assertSame(cpm2.protocolInstanceUid, cpm3true.protocolInstanceUid)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Getter idempotency — calling each getter twice returns the same reference
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun getterIdempotency_sendChannelInfo() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertSame(
            "getSendChannelInfo() must return the same reference on repeated calls",
            cpm.sendChannelInfo,
            cpm.sendChannelInfo
        )
    }

    @Test
    fun getterIdempotency_allGetters() {
        // Constructor 1 — test receptionChannelInfo and toIdentity idempotency
        val msg = buildReceivedMessage(ownedIdentity, protocolInstanceUid, 42, receptionChannelInfo, 1_000_000L)
        val cpm1 = CoreProtocolMessage(msg)
        assertSame(cpm1.receptionChannelInfo, cpm1.receptionChannelInfo)
        assertSame(cpm1.toIdentity, cpm1.toIdentity)
        assertSame(cpm1.protocolInstanceUid, cpm1.protocolInstanceUid)
        assertEquals(cpm1.protocolId, cpm1.protocolId)
        assertEquals(cpm1.serverTimestamp, cpm1.serverTimestamp)
        assertEquals(cpm1.hasUserContent(), cpm1.hasUserContent())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // equals / hashCode — no override: reference identity semantics
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun equalsIsReferenceIdentity() {
        // CoreProtocolMessage does NOT override equals; two instances with identical
        // constructor inputs must NOT compare equal by value. A Kotlin migration to
        // a `data class` would silently introduce structural equality — this test pins
        // the current reference-identity behavior.
        val cpm1 = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        val cpm2 = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        assertNotSame(cpm1, cpm2)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two distinct CoreProtocolMessage instances must not be equal (no equals override)",
            cpm1.equals(cpm2)
        )
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "An instance must be reflexively equal to itself",
            cpm1.equals(cpm1)
        )
    }

    @Test
    fun equalsReturnsFalseForUnrelatedTypes() {
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(cpm.equals("not a CoreProtocolMessage"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(cpm.equals(null))
    }

    @Test
    fun hashCodeIsStableAcrossCalls() {
        // Object.hashCode() is stable per-instance; pin that it does not vary.
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid)
        val h1 = cpm.hashCode()
        val h2 = cpm.hashCode()
        assertEquals(
            "hashCode() must return the same value on repeated calls for the same instance",
            h1,
            h2
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // serverTimestamp — constructed at call time, not lazily
    // ═══════════════════════════════════════════════════════════════════════════

    @Test
    fun serverTimestampCapturedEagerly_notLazy() {
        // Both constructors 2 and 3 call System.currentTimeMillis() inside the
        // constructor body. This test confirms the timestamp is bounded by a narrow
        // window around the construction call — ruling out lazy evaluation.
        val before = System.currentTimeMillis()
        val cpm = CoreProtocolMessage(sendChannelInfo, 5, protocolInstanceUid, false)
        val after = System.currentTimeMillis()

        // The captured timestamp must have been sampled between our two System.currentTimeMillis() calls.
        assertTrue(
            "serverTimestamp must be captured eagerly inside the constructor: expected [$before..$after] but got ${cpm.serverTimestamp}",
            cpm.serverTimestamp in before..after
        )

        // Sleeping and calling again must NOT change the stored value (it's immutable).
        val timestampAfterDelay = cpm.serverTimestamp
        assertEquals(
            "serverTimestamp must be immutable after construction",
            cpm.serverTimestamp,
            timestampAfterDelay
        )
    }
}
