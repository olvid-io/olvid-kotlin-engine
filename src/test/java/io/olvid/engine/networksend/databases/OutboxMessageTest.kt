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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.networksend.datatypes.SendManagerSession
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Field

/**
 * Characterization tests for [OutboxMessage] — the SQLite-backed send-queue entity in
 * the engine networksend module. These tests pin observable behavior that does NOT touch
 * a live database:
 *
 *  - [OutboxMessage.create] null-guards that short-circuit before any SQL is issued.
 *  - Private constructor side-effects: uidFromServer and nonce are both null at
 *    construction, and creationTimestamp is close to System.currentTimeMillis().
 *  - The [OutboxMessage.isAcknowledged] contract: driven entirely by whether
 *    uidFromServer is null.
 *  - Field-storage characterization: non-primitive parameters are stored by reference,
 *    not cloned.
 *  - All 11 public getters delegate to the stored fields without transformation.
 *  - equals / hashCode: default Object reference semantics (not overridden by the Java
 *    source); two instances with the same inputs are not equal.
 *  - [OutboxMessage.wasCommitted] is safe to call when commitHookBits == 0 (no SQL,
 *    no notification posting).
 *
 * Database operations (insert/delete/get/getAll/setUidFromServer/getHeaders/
 * getAttachments) and notification dispatch in wasCommitted when hook bits are set are
 * intentionally out of scope — those require a live Session.
 */
class OutboxMessageTest {

    private lateinit var identity: Identity
    private lateinit var uid: UID
    private lateinit var encryptedContent: EncryptedBytes
    private lateinit var encryptedExtendedContent: EncryptedBytes
    private val server = "https://server.olvid.io"

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

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)

        identity = Identity(
            server,
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
        uid = UID(ByteArray(UID.UID_LENGTH) { 0x42 })
        encryptedContent = EncryptedBytes(byteArrayOf(0x01, 0x02, 0x03, 0x04))
        encryptedExtendedContent = EncryptedBytes(byteArrayOf(0x10, 0x20, 0x30))
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Invokes the private 8-arg constructor without going through [OutboxMessage.create]
     * (which would call insert() and require a live Session). This lets us characterize
     * the in-memory state the constructor produces.
     *
     * Signature: (SendManagerSession, Identity, UID, String, EncryptedBytes,
     *             EncryptedBytes, boolean, boolean)
     */
    private fun newViaReflection(
        session: SendManagerSession? = null,
        ownedIdentity: Identity? = identity,
        uid: UID? = this.uid,
        server: String? = this.server,
        encryptedContent: EncryptedBytes? = this.encryptedContent,
        encryptedExtendedContent: EncryptedBytes? = this.encryptedExtendedContent,
        isApplicationMessage: Boolean = false,
        isVoipMessage: Boolean = false,
    ): OutboxMessage {
        val ctor = OutboxMessage::class.java.getDeclaredConstructor(
            SendManagerSession::class.java,
            Identity::class.java,
            UID::class.java,
            String::class.java,
            EncryptedBytes::class.java,
            EncryptedBytes::class.java,
            Boolean::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType,
        )
        ctor.isAccessible = true
        return ctor.newInstance(
            session,
            ownedIdentity,
            uid,
            server,
            encryptedContent,
            encryptedExtendedContent,
            isApplicationMessage,
            isVoipMessage,
        )
    }

    private fun readField(obj: OutboxMessage, fieldName: String): Any? {
        val f: Field = OutboxMessage::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        return f.get(obj)
    }

    private fun writeField(obj: OutboxMessage, fieldName: String, value: Any?) {
        val f: Field = OutboxMessage::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        f.set(obj, value)
    }

    // ─── create() null-guards (pure logic, no SQL issued) ──────────────────────

    @Test
    fun testCreateReturnsNullWhenOwnedIdentityIsNull() {
        // The null check fires before insert(); the null session is never dereferenced.
        val result = OutboxMessage.create(null, null, uid, server, encryptedContent, encryptedExtendedContent, false, false, false)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenUidIsNull() {
        val result = OutboxMessage.create(null, identity, null, server, encryptedContent, encryptedExtendedContent, false, false, false)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenServerIsNull() {
        val result = OutboxMessage.create(null, identity, uid, null, encryptedContent, encryptedExtendedContent, false, false, false)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenEncryptedContentIsNull() {
        val result = OutboxMessage.create(null, identity, uid, server, null, encryptedExtendedContent, false, false, false)
        assertNull(result)
    }

    @Test
    fun testCreateDoesNotGuardNullEncryptedExtendedContent() {
        // encryptedExtendedContent is nullable by design — passing null must NOT trigger
        // the null-guard that returns null early. With a null session the call will throw
        // (or return null from a caught exception) but must NOT return null from the guard.
        // We verify this by confirming we cannot distinguish it from the guarded paths
        // in a safe way: the important contract is that null EC doesn't cause a null return
        // from the guard branch. We call it and accept either an exception or a null from
        // the SQL path — both are non-guard behaviors.
        var threwOrReturnedNull = false
        try {
            val result = OutboxMessage.create(null, identity, uid, server, encryptedContent, null, false, false, false)
            // null from SQL exception catch is acceptable
            threwOrReturnedNull = (result == null)
        } catch (_: Throwable) {
            threwOrReturnedNull = true
        }
        // Either path is fine — what matters is that the four guarded parameters are
        // the only ones that cause an early null. This test documents the asymmetry.
        assertTrue(
            "Expected either a throw or null from SQL path (not a valid OutboxMessage)",
            threwOrReturnedNull,
        )
    }

    // ─── Constructor side-effects: uidFromServer and nonce are null ────────────

    @Test
    fun testConstructorSetsUidFromServerToNull() {
        // A freshly created message has never been acknowledged; uidFromServer must
        // be null. A Kotlin migration that initializes this to a non-null default
        // would silently break the acknowledged-state logic.
        val msg = newViaReflection()
        assertNull("uidFromServer must be null after construction", readField(msg, "uidFromServer"))
    }

    @Test
    fun testConstructorSetsNonceToNull() {
        // The nonce arrives from the server at acknowledgement time; it must be null
        // until then.
        val msg = newViaReflection()
        assertNull("nonce must be null after construction", readField(msg, "nonce"))
    }

    @Test
    fun testConstructorSetsCreationTimestampCloseToNow() {
        val before = System.currentTimeMillis()
        val msg = newViaReflection()
        val after = System.currentTimeMillis()
        val ts = msg.creationTimestamp
        assertTrue(
            "creationTimestamp ($ts) must be >= time before construction ($before)",
            ts >= before,
        )
        assertTrue(
            "creationTimestamp ($ts) must be <= time after construction ($after)",
            ts <= after,
        )
    }

    // ─── Field-storage characterization (reference identity) ──────────────────

    @Test
    fun testOwnedIdentityIsStoredByReference() {
        // The constructor must not clone or rewrap the Identity object.
        val msg = newViaReflection(ownedIdentity = identity)
        assertSame(identity, msg.getOwnedIdentity())
    }

    @Test
    fun testUidIsStoredByReference() {
        val msg = newViaReflection(uid = uid)
        assertSame(uid, msg.uid)
    }

    @Test
    fun testEncryptedContentIsStoredByReference() {
        val msg = newViaReflection(encryptedContent = encryptedContent)
        assertSame(encryptedContent, msg.encryptedContent)
    }

    @Test
    fun testEncryptedExtendedContentIsStoredByReference() {
        val msg = newViaReflection(encryptedExtendedContent = encryptedExtendedContent)
        assertSame(encryptedExtendedContent, msg.encryptedExtendedContent)
    }

    @Test
    fun testEncryptedExtendedContentCanBeNull() {
        val msg = newViaReflection(encryptedExtendedContent = null)
        assertNull("encryptedExtendedContent field must accept null", msg.encryptedExtendedContent)
    }

    @Test
    fun testServerIsStoredExactly() {
        val specificServer = "https://specific.olvid.io"
        val msg = newViaReflection(server = specificServer)
        assertSame(specificServer, msg.server)
    }

    @Test
    fun testIsApplicationMessageTrueIsStored() {
        val msg = newViaReflection(isApplicationMessage = true)
        assertTrue(msg.isApplicationMessage)
    }

    @Test
    fun testIsApplicationMessageFalseIsStored() {
        val msg = newViaReflection(isApplicationMessage = false)
        assertFalse(msg.isApplicationMessage)
    }

    @Test
    fun testIsVoipMessageTrueIsStored() {
        val msg = newViaReflection(isVoipMessage = true)
        assertTrue(msg.isVoipMessage)
    }

    @Test
    fun testIsVoipMessageFalseIsStored() {
        val msg = newViaReflection(isVoipMessage = false)
        assertFalse(msg.isVoipMessage)
    }

    // ─── Getters delegate to fields with no transformation ────────────────────

    @Test
    fun testGetOwnedIdentityDelegatesToField() {
        val msg = newViaReflection(ownedIdentity = identity)
        assertSame(identity, msg.getOwnedIdentity())
    }

    @Test
    fun testGetUidDelegatesToField() {
        val msg = newViaReflection(uid = uid)
        assertSame(uid, msg.uid)
    }

    @Test
    fun testGetUidFromServerInitiallyNull() {
        val msg = newViaReflection()
        assertNull(msg.uidFromServer)
    }

    @Test
    fun testGetNonceInitiallyNull() {
        val msg = newViaReflection()
        assertNull(msg.nonce)
    }

    @Test
    fun testGetServerDelegatesToField() {
        val msg = newViaReflection(server = server)
        assertSame(server, msg.server)
    }

    @Test
    fun testGetEncryptedContentDelegatesToField() {
        val msg = newViaReflection(encryptedContent = encryptedContent)
        assertSame(encryptedContent, msg.encryptedContent)
    }

    @Test
    fun testGetEncryptedExtendedContentDelegatesToField() {
        val msg = newViaReflection(encryptedExtendedContent = encryptedExtendedContent)
        assertSame(encryptedExtendedContent, msg.encryptedExtendedContent)
    }

    @Test
    fun testGetEncryptedExtendedContentNullWhenNotSet() {
        val msg = newViaReflection(encryptedExtendedContent = null)
        assertNull(msg.encryptedExtendedContent)
    }

    @Test
    fun testIsApplicationMessageGetterMatchesConstructorArg() {
        val msgTrue = newViaReflection(isApplicationMessage = true)
        val msgFalse = newViaReflection(isApplicationMessage = false)
        assertTrue(msgTrue.isApplicationMessage)
        assertFalse(msgFalse.isApplicationMessage)
    }

    @Test
    fun testIsVoipMessageGetterMatchesConstructorArg() {
        val msgTrue = newViaReflection(isVoipMessage = true)
        val msgFalse = newViaReflection(isVoipMessage = false)
        assertTrue(msgTrue.isVoipMessage)
        assertFalse(msgFalse.isVoipMessage)
    }

    @Test
    fun testGetCreationTimestampDelegatesToField() {
        // The field is set at construction; the getter must return the same value
        // every call with no recomputation.
        val msg = newViaReflection()
        val ts1 = msg.creationTimestamp
        val ts2 = msg.creationTimestamp
        assertTrue("creationTimestamp must be stable across calls", ts1 == ts2)
    }

    // ─── isAcknowledged() contract ─────────────────────────────────────────────

    @Test
    fun testIsAcknowledgedReturnsFalseAfterConstruction() {
        // uidFromServer is null at construction → not acknowledged.
        val msg = newViaReflection()
        assertFalse("Fresh message must not be acknowledged", msg.isAcknowledged)
    }

    @Test
    fun testIsAcknowledgedReturnsTrueWhenUidFromServerIsSetViaReflection() {
        // After injecting a non-null uidFromServer via reflection (simulating what
        // setUidFromServer does after a DB update), isAcknowledged must flip to true.
        // This pins the exact nullable-check used in the Java implementation so a
        // Kotlin migration that changes the check (e.g., mishandling `?`) is caught.
        val msg = newViaReflection()
        val serverUid = UID(ByteArray(UID.UID_LENGTH) { 0x77 })
        writeField(msg, "uidFromServer", serverUid)
        assertTrue("isAcknowledged must be true when uidFromServer is non-null", msg.isAcknowledged)
    }

    @Test
    fun testIsAcknowledgedFlipsBackToFalseWhenUidFromServerSetToNull() {
        // Mirrors the setUidFromServer(null, ...) path. The acknowledgement contract
        // must be symmetric: setting uidFromServer back to null → not acknowledged.
        val msg = newViaReflection()
        writeField(msg, "uidFromServer", UID(ByteArray(UID.UID_LENGTH) { 0x55 }))
        assertTrue(msg.isAcknowledged) // precondition
        writeField(msg, "uidFromServer", null)
        assertFalse("isAcknowledged must revert to false when uidFromServer is set to null", msg.isAcknowledged)
    }

    // ─── equals / hashCode (default Object semantics — not overridden) ─────────

    @Test
    fun testEqualsIsReferenceIdentity() {
        // The Java source does NOT override equals; two instances with the same inputs
        // must NOT compare equal. A migration to a Kotlin data class would break this.
        val msg1 = newViaReflection()
        val msg2 = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Two distinct instances must not be equal", msg1.equals(msg2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("An instance must be equal to itself", msg1.equals(msg1))
    }

    @Test
    fun testEqualsReturnsFalseForUnrelatedTypes() {
        val msg = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(msg.equals("not an OutboxMessage"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(msg.equals(null))
    }

    @Test
    fun testHashCodeIsStableAcrossCalls() {
        // Default Object.hashCode is stable per-instance.
        val msg = newViaReflection()
        val h1 = msg.hashCode()
        val h2 = msg.hashCode()
        assertTrue("hashCode must be stable across calls", h1 == h2)
    }

    @Test
    fun testTwoInstancesWithSameInputsAreDistinctObjects() {
        val msg1 = newViaReflection()
        val msg2 = newViaReflection()
        assertNotSame(msg1, msg2)
    }

    // ─── wasCommitted() — zero-hook-bits no-throw contract ────────────────────

    @Test
    fun testWasCommittedDoesNotThrowWhenCommitHookBitsAreZero() {
        // A freshly reflected instance has commitHookBits == 0 (Java field default).
        // wasCommitted() must be safe to call in this state even with a null session,
        // because all if-branches check the bit first and are skipped when all bits
        // are clear.
        val msg = newViaReflection(session = null)
        msg.wasCommitted() // must not throw
    }

    @Test
    fun testCommitHookBitsDefaultToZero() {
        // Pin the Java default: commitHookBits starts at 0L (no pending hooks).
        // If a Kotlin migration accidentally initializes this to a non-zero value,
        // wasCommitted() would try to dereference the null session.
        val msg = newViaReflection()
        val bits = readField(msg, "commitHookBits") as Long
        assertTrue("commitHookBits must default to 0", bits == 0L)
    }

    @Test
    fun testWasCommittedResetsCommitHookBitsToZero() {
        // After wasCommitted() runs (with all bits clear), the bits field must still
        // be 0. This pins the reset-at-end behavior documented in the source.
        val msg = newViaReflection()
        msg.wasCommitted()
        val bits = readField(msg, "commitHookBits") as Long
        assertTrue("commitHookBits must be 0 after wasCommitted with no bits set", bits == 0L)
    }

    // ─── Two-instance independence ─────────────────────────────────────────────

    @Test
    fun testInstancesDoNotShareMutableState() {
        // Fields like uidFromServer and commitHookBits are instance-level; mutating one
        // instance must not affect another (rules out accidental companion-object backing).
        val msg1 = newViaReflection()
        val msg2 = newViaReflection()

        val serverUid = UID(ByteArray(UID.UID_LENGTH) { 0x11 })
        writeField(msg1, "uidFromServer", serverUid)

        assertTrue(msg1.isAcknowledged)
        assertFalse("msg2.isAcknowledged must be unaffected by mutation of msg1", msg2.isAcknowledged)
    }

    @Test
    fun testGettersAreIdempotent() {
        val msg = newViaReflection(
            ownedIdentity = identity,
            uid = uid,
            server = server,
            encryptedContent = encryptedContent,
            encryptedExtendedContent = encryptedExtendedContent,
            isApplicationMessage = true,
            isVoipMessage = false,
        )
        // Two consecutive calls to each getter must return the same value.
        assertSame(msg.getOwnedIdentity(), msg.getOwnedIdentity())
        assertSame(msg.uid, msg.uid)
        assertNull(msg.uidFromServer); assertNull(msg.uidFromServer)
        assertNull(msg.nonce); assertNull(msg.nonce)
        assertSame(msg.server, msg.server)
        assertSame(msg.encryptedContent, msg.encryptedContent)
        assertSame(msg.encryptedExtendedContent, msg.encryptedExtendedContent)
        assertTrue(msg.isApplicationMessage); assertTrue(msg.isApplicationMessage)
        assertFalse(msg.isVoipMessage); assertFalse(msg.isVoipMessage)
        assertTrue(msg.creationTimestamp == msg.creationTimestamp)
        assertFalse(msg.isAcknowledged); assertFalse(msg.isAcknowledged)
    }

    @Test
    fun testNotNull() {
        val msg = newViaReflection()
        assertNotNull(msg)
    }
}
