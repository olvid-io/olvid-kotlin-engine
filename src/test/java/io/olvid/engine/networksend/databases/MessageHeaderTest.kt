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

/**
 * Characterization tests for [MessageHeader] — the SQLite-backed entity in the engine
 * network-send module. These tests pin observable behavior that does NOT touch a live
 * database:
 *
 *  - The static factory [MessageHeader.create] null-guards for each of the five
 *    non-nullable parameters, which short-circuit BEFORE any SQL is issued. Every
 *    null path is testable with a null [SendManagerSession] because no DB call is made.
 *  - The field-initialization invariants of the private all-args constructor, reached
 *    via reflection. We pin reference identity (assertSame) for every reference-typed
 *    parameter so a migration that promotes this to a Kotlin data class (which copies
 *    fields) would be caught.
 *  - The five public getters expose the stored fields without transformation.
 *  - [MessageHeader] does NOT override equals/hashCode; we pin the default
 *    reference-identity semantics so an accidental migration to a data class is caught.
 *  - [MessageHeader.wasCommitted] is a deliberate no-op; we confirm it completes without
 *    throwing and does not mutate observable state.
 *
 * Database operations (insert/delete/getAll/deleteAll/createTable/upgradeTable) are
 * intentionally out of scope — they require a live [io.olvid.engine.datatypes.Session].
 */
class MessageHeaderTest {

    private lateinit var ownedIdentity: Identity
    private lateinit var toIdentity: Identity
    private lateinit var messageUid: UID
    private lateinit var deviceUid: UID
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

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPairA = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairA = EncryptionEciesCurve25519KeyPair.generate(prng)
        ownedIdentity = Identity(
            "owned.olvid.io",
            serverAuthKeyPairA.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairA.publicKey as EncryptionPublicKey,
        )

        val serverAuthKeyPairB = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairB = EncryptionEciesCurve25519KeyPair.generate(prng)
        toIdentity = Identity(
            "to.olvid.io",
            serverAuthKeyPairB.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairB.publicKey as EncryptionPublicKey,
        )

        messageUid = UID(prng)
        deviceUid = UID(prng)
        wrappedKey = EncryptedBytes(ByteArray(16) { it.toByte() })
    }

    // ─── Reflection helper ─────────────────────────────────────────────────────

    /**
     * Invokes the private (SendManagerSession, Identity, UID, UID, Identity, EncryptedBytes)
     * constructor without going through [MessageHeader.create] (which would call insert()
     * and require a real Session). This lets us characterize the in-memory state the
     * constructor produces.
     */
    private fun newViaReflection(
        session: SendManagerSession? = null,
        ownedIdentity: Identity? = this.ownedIdentity,
        messageUid: UID? = this.messageUid,
        deviceUid: UID? = this.deviceUid,
        toIdentity: Identity? = this.toIdentity,
        wrappedKey: EncryptedBytes? = this.wrappedKey,
    ): MessageHeader {
        val ctor = MessageHeader::class.java.getDeclaredConstructor(
            SendManagerSession::class.java,
            Identity::class.java,
            UID::class.java,
            UID::class.java,
            Identity::class.java,
            EncryptedBytes::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(session, ownedIdentity, messageUid, deviceUid, toIdentity, wrappedKey)
    }

    // ─── create() null-guards (pure logic, no SQL issued) ─────────────────────

    @Test
    fun testCreateReturnsNullWhenOwnedIdentityIsNull() {
        // The null check fires before insert(); the null session is never dereferenced.
        val result = MessageHeader.create(null, null, messageUid, deviceUid, toIdentity, wrappedKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenMessageUidIsNull() {
        val result = MessageHeader.create(null, ownedIdentity, null, deviceUid, toIdentity, wrappedKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenDeviceUidIsNull() {
        val result = MessageHeader.create(null, ownedIdentity, messageUid, null, toIdentity, wrappedKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenToIdentityIsNull() {
        val result = MessageHeader.create(null, ownedIdentity, messageUid, deviceUid, null, wrappedKey)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenWrappedKeyIsNull() {
        val result = MessageHeader.create(null, ownedIdentity, messageUid, deviceUid, toIdentity, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenAllParamsAreNull() {
        // All five nullable params null — still short-circuits at the first null check.
        val result = MessageHeader.create(null, null, null, null, null, null)
        assertNull(result)
    }

    // ─── Constructor: stored fields (reference identity) ──────────────────────

    @Test
    fun testConstructorStoresOwnedIdentityByReference() {
        // The constructor must not clone or rewrap the Identity. A migration to a data
        // class that copies fields would break this assertSame, catching the regression.
        val header = newViaReflection()
        assertSame(ownedIdentity, header.getOwnedIdentity())
    }

    @Test
    fun testConstructorStoresMessageUidByReference() {
        val header = newViaReflection()
        assertSame(messageUid, header.messageUid)
    }

    @Test
    fun testConstructorStoresDeviceUidByReference() {
        val header = newViaReflection()
        assertSame(deviceUid, header.deviceUid)
    }

    @Test
    fun testConstructorStoresToIdentityByReference() {
        val header = newViaReflection()
        assertSame(toIdentity, header.getToIdentity())
    }

    @Test
    fun testConstructorStoresWrappedKeyByReference() {
        val header = newViaReflection()
        assertSame(wrappedKey, header.wrappedKey)
    }

    // ─── Getters return stored values with no transformation ──────────────────

    @Test
    fun testGetOwnedIdentityIsNotNull() {
        val header = newViaReflection()
        assertNotNull(header.getOwnedIdentity())
    }

    @Test
    fun testGetMessageUidIsNotNull() {
        val header = newViaReflection()
        assertNotNull(header.messageUid)
    }

    @Test
    fun testGetDeviceUidIsNotNull() {
        val header = newViaReflection()
        assertNotNull(header.deviceUid)
    }

    @Test
    fun testGetToIdentityIsNotNull() {
        val header = newViaReflection()
        assertNotNull(header.getToIdentity())
    }

    @Test
    fun testGetWrappedKeyIsNotNull() {
        val header = newViaReflection()
        assertNotNull(header.wrappedKey)
    }

    @Test
    fun testGettersAreIdempotent() {
        // Getters must be pure: repeated calls return the same reference.
        val header = newViaReflection()
        assertSame(header.getOwnedIdentity(), header.getOwnedIdentity())
        assertSame(header.messageUid, header.messageUid)
        assertSame(header.deviceUid, header.deviceUid)
        assertSame(header.getToIdentity(), header.getToIdentity())
        assertSame(header.wrappedKey, header.wrappedKey)
    }

    @Test
    fun testOwnedIdentityAndToIdentityAreDifferentObjects() {
        // Sanity: the two Identity slots are independent, not aliased.
        val header = newViaReflection()
        assertFalse(
            "ownedIdentity and toIdentity must refer to distinct objects",
            header.getOwnedIdentity() === header.getToIdentity(),
        )
    }

    @Test
    fun testMessageUidAndDeviceUidAreDifferentObjects() {
        // Sanity: the two UID slots are independent.
        val header = newViaReflection()
        assertFalse(
            "messageUid and deviceUid must refer to distinct objects",
            header.messageUid === header.deviceUid,
        )
    }

    // ─── equals / hashCode (default Object semantics — not overridden) ─────────

    @Test
    fun testEqualsIsReferenceIdentity() {
        // MessageHeader does NOT override equals; two instances with identical fields
        // must NOT compare equal. An accidental migration to a Kotlin data class would
        // break this contract — this test pins the current behavior.
        val h1 = newViaReflection()
        val h2 = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Two distinct instances must not be equal", h1.equals(h2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("An instance must be equal to itself", h1.equals(h1))
    }

    @Test
    fun testEqualsReturnsFalseForUnrelatedTypes() {
        val header = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(header.equals("not a MessageHeader"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(header.equals(null))
    }

    @Test
    fun testHashCodeIsStableAcrossCalls() {
        // Default Object.hashCode is stable per-instance; pin that.
        val header = newViaReflection()
        val h1 = header.hashCode()
        val h2 = header.hashCode()
        assertTrue("hashCode must be stable across calls", h1 == h2)
    }

    // ─── Two instances with identical inputs are distinct, non-equal objects ───

    @Test
    fun testTwoInstancesWithSameInputsAreNotSameObject() {
        // The constructor does not intern or cache; each call yields a fresh instance.
        val h1 = newViaReflection()
        val h2 = newViaReflection()
        assertNotSame(h1, h2)
    }

    @Test
    fun testTwoInstancesWithSameInputsAreNotEqual() {
        // Complements the assertNotSame above: also not equal under Object.equals.
        val h1 = newViaReflection()
        val h2 = newViaReflection()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two separately constructed instances must not be equal even with same args",
            h1.equals(h2),
        )
    }

    @Test
    fun testTwoInstancesHaveIndependentGetters() {
        // If a migration accidentally introduces shared static state, different
        // instances would expose the same getter results despite different construction.
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 0x77.toByte() }))
        val altMessageUid = UID(prng)
        val altDeviceUid = UID(prng)
        val altWrappedKey = EncryptedBytes(ByteArray(16) { 0xFF.toByte() })

        val h1 = newViaReflection(
            messageUid = messageUid,
            deviceUid = deviceUid,
            wrappedKey = wrappedKey,
        )
        val h2 = newViaReflection(
            messageUid = altMessageUid,
            deviceUid = altDeviceUid,
            wrappedKey = altWrappedKey,
        )

        assertSame(messageUid, h1.messageUid)
        assertSame(altMessageUid, h2.messageUid)
        assertFalse("messageUid must differ between the two instances", h1.messageUid === h2.messageUid)

        assertSame(deviceUid, h1.deviceUid)
        assertSame(altDeviceUid, h2.deviceUid)
        assertFalse("deviceUid must differ between the two instances", h1.deviceUid === h2.deviceUid)
    }

    // ─── wasCommitted() hook ───────────────────────────────────────────────────

    @Test
    fun testWasCommittedIsNoOpAndDoesNotThrow() {
        // wasCommitted() has an empty body ("No hooks"); it must complete cleanly even
        // with a null SendManagerSession.
        val header = newViaReflection()
        header.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotMutateState() {
        // After calling wasCommitted(), all getters must return the same references
        // they held before the call.
        val header = newViaReflection()
        val ownedBefore = header.getOwnedIdentity()
        val msgBefore = header.messageUid
        val devBefore = header.deviceUid
        val toBefore = header.getToIdentity()
        val keyBefore = header.wrappedKey

        header.wasCommitted()

        assertSame(ownedBefore, header.getOwnedIdentity())
        assertSame(msgBefore, header.messageUid)
        assertSame(devBefore, header.deviceUid)
        assertSame(toBefore, header.getToIdentity())
        assertSame(keyBefore, header.wrappedKey)
    }
}
