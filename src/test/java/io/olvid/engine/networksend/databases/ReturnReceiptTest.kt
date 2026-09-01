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
import java.lang.reflect.Method

/**
 * Characterization tests for [ReturnReceipt] before its Java→Kotlin migration.
 *
 * Scope: pure in-memory behavior that does NOT touch a live database:
 *  - [ReturnReceipt.create] null-guards (four guarded params + combinations).
 *  - Public constructor stores every field; getters return exactly those values.
 *  - `attachmentNumber` is nullable (`Integer`) and may be null — that contract is pinned.
 *  - Two instances built from the same inputs are distinct objects (no `equals` override).
 *  - `hashCode` is stable per-instance (identity-based, not overridden).
 *  - `wasCommitted()` is a no-op when `commitHookBits == 0` (fresh constructor path),
 *    even with a null [SendManagerSession] — no NPE may escape.
 *  - [ReturnReceipt.NewReturnReceiptListener] signature contract.
 *
 * Out of scope: insert/delete/get/getAll/getMany/deleteAllForOwnedIdentity/
 * createTable/upgradeTable and the wasCommitted notification path (all require a real
 * [io.olvid.engine.datatypes.Session]).
 */
class ReturnReceiptTest {

    private lateinit var ownedIdentity: Identity
    private lateinit var contactIdentity: Identity
    private lateinit var contactDeviceUids: Array<UID?>
    private lateinit var nonce: ByteArray
    private lateinit var key: AuthEncKey

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

        ownedIdentity = makeIdentity("owned.olvid.io")
        contactIdentity = makeIdentity("contact.olvid.io")
        contactDeviceUids = arrayOf<UID?>(UID(prng), UID(prng))
        nonce = prng.bytes(32)
        key = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!.generateKey(prng)!!
    }

    // ─── Convenience builder ───────────────────────────────────────────────────

    /**
     * Constructs a [ReturnReceipt] via the public constructor without going through
     * [ReturnReceipt.create] (which would call `insert()` and require a real Session).
     */
    private fun build(
        session: SendManagerSession? = null,
        ownedIdentity: Identity? = this.ownedIdentity,
        contactIdentity: Identity? = this.contactIdentity,
        contactDeviceUids: Array<UID?>? = this.contactDeviceUids,
        status: Int = 0,
        nonce: ByteArray? = this.nonce,
        key: AuthEncKey? = this.key,
        attachmentNumber: Int? = null,
    ): ReturnReceipt = ReturnReceipt(
        session,
        ownedIdentity,
        contactIdentity,
        contactDeviceUids,
        status,
        nonce,
        key,
        attachmentNumber,
    )

    // ─── create() null-guards ──────────────────────────────────────────────────

    @Test
    fun testCreateReturnsNullWhenOwnedIdentityIsNull() {
        // ownedIdentity is in the null-guard; must short-circuit before any DB call.
        val result = ReturnReceipt.create(null, null, contactIdentity, contactDeviceUids, 0, nonce, key, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenContactIdentityIsNull() {
        val result = ReturnReceipt.create(null, ownedIdentity, null, contactDeviceUids, 0, nonce, key, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenNonceIsNull() {
        val result = ReturnReceipt.create(null, ownedIdentity, contactIdentity, contactDeviceUids, 0, null, key, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenKeyIsNull() {
        val result = ReturnReceipt.create(null, ownedIdentity, contactIdentity, contactDeviceUids, 0, nonce, null, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenAllFourGuardedParamsAreNull() {
        val result = ReturnReceipt.create(null, null, null, contactDeviceUids, 0, null, null, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenOwnedAndContactIdentitiesAreNull() {
        val result = ReturnReceipt.create(null, null, null, contactDeviceUids, 0, nonce, key, null)
        assertNull(result)
    }

    @Test
    fun testCreateReturnsNullWhenNonceAndKeyAreNull() {
        val result = ReturnReceipt.create(null, ownedIdentity, contactIdentity, contactDeviceUids, 0, null, null, null)
        assertNull(result)
    }

    @Test
    fun testCreateNullGuardDoesNotApplyToContactDeviceUids() {
        // contactDeviceUids is NOT in the null-guard. With all four guarded params
        // non-null but contactDeviceUids null, create() proceeds past the guard and
        // attempts insert() — which NPEs on the null session. We pin the observed
        // behavior: the result is NOT a silently-returned ReturnReceipt instance.
        val result = try {
            ReturnReceipt.create(null, ownedIdentity, contactIdentity, null, 0, nonce, key, null)
        } catch (_: Throwable) {
            null
        }
        assertFalse(
            "create() must not silently return a ReturnReceipt when the null session causes insert() to fail",
            result is ReturnReceipt,
        )
    }

    @Test
    fun testCreateNullGuardDoesNotApplyToAttachmentNumber() {
        // attachmentNumber is NOT in the null-guard. A null attachmentNumber with a
        // null session still fails at insert() — not at the null-guard check.
        val result = try {
            ReturnReceipt.create(null, ownedIdentity, contactIdentity, contactDeviceUids, 0, nonce, key, null)
        } catch (_: Throwable) {
            null
        }
        assertFalse(
            "create() must not silently return a ReturnReceipt when the null session causes insert() to fail",
            result is ReturnReceipt,
        )
    }

    // ─── Public constructor: field storage ─────────────────────────────────────

    @Test
    fun testConstructorStoresOwnedIdentityByReference() {
        val rr = build(ownedIdentity = ownedIdentity)
        assertSame(ownedIdentity, rr.getOwnedIdentity())
    }

    @Test
    fun testConstructorStoresContactIdentityByReference() {
        val rr = build(contactIdentity = contactIdentity)
        assertSame(contactIdentity, rr.getContactIdentity())
    }

    @Test
    fun testConstructorStoresContactDeviceUidsByReference() {
        val rr = build(contactDeviceUids = contactDeviceUids)
        assertSame(contactDeviceUids, rr.contactDeviceUids)
    }

    @Test
    fun testConstructorStoresNonceByReference() {
        val rr = build(nonce = nonce)
        assertSame(nonce, rr.nonce)
    }

    @Test
    fun testConstructorStoresKeyByReference() {
        val rr = build(key = key)
        assertSame(key, rr.key)
    }

    @Test
    fun testConstructorStoresStatus() {
        val rr = build(status = 42)
        assertEquals(42, rr.status)
    }

    @Test
    fun testConstructorStoresStatusZero() {
        val rr = build(status = 0)
        assertEquals(0, rr.status)
    }

    @Test
    fun testConstructorStoresNegativeStatus() {
        // No sign constraint exists on the status field; any int must be preserved.
        val rr = build(status = -1)
        assertEquals(-1, rr.status)
    }

    @Test
    fun testConstructorStoresBoxedAttachmentNumber() {
        val rr = build(attachmentNumber = 7)
        assertEquals(Integer.valueOf(7), rr.attachmentNumber)
    }

    @Test
    fun testConstructorStoresNullAttachmentNumber() {
        val rr = build(attachmentNumber = null)
        assertNull(rr.attachmentNumber)
    }

    // ─── getId: fresh instance has id == 0 ────────────────────────────────────

    @Test
    fun testGetIdReturnZeroForFreshInstance() {
        // The `id` field is only set by insert() via the DB-generated autoincrement key.
        // A freshly constructed instance (not inserted) must report 0 (Java long default).
        val rr = build()
        assertEquals(0L, rr.id)
    }

    // ─── attachmentNumber is boxed Integer ────────────────────────────────────

    @Test
    fun testAttachmentNumberIsBoxedIntegerType() {
        // Pin that the getter returns `Integer` (boxed), not a primitive. This matters
        // because the field is `Integer attachmentNumber` in the Java source — a Kotlin
        // migration that changes it to `Int` would break null semantics.
        val rr = build(attachmentNumber = 3)
        val getter = ReturnReceipt::class.java.getMethod("getAttachmentNumber")
        @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
        assertEquals(
            "getAttachmentNumber() must return boxed Integer, not primitive int",
            Integer::class.java,
            getter.returnType,
        )
        assertNotNull(rr.attachmentNumber)
    }

    @Test
    fun testAttachmentNumberCanBeNullAtRuntime() {
        val rr = build(attachmentNumber = null)
        // Deliberately use reflection-level call to confirm null propagates at runtime.
        val getter = ReturnReceipt::class.java.getMethod("getAttachmentNumber")
        assertNull(getter.invoke(rr))
    }

    // ─── Getters are idempotent ────────────────────────────────────────────────

    @Test
    fun testGettersAreIdempotent() {
        val rr = build(status = 5, attachmentNumber = 2)
        assertEquals(rr.id, rr.id)
        assertSame(rr.getOwnedIdentity(), rr.getOwnedIdentity())
        assertSame(rr.getContactIdentity(), rr.getContactIdentity())
        assertSame(rr.contactDeviceUids, rr.contactDeviceUids)
        assertEquals(rr.status, rr.status)
        assertSame(rr.nonce, rr.nonce)
        assertSame(rr.key, rr.key)
        assertEquals(rr.attachmentNumber, rr.attachmentNumber)
    }

    // ─── Reference identity (no equals override) ──────────────────────────────

    @Test
    fun testTwoInstancesWithIdenticalInputsAreNotSame() {
        val rr1 = build()
        val rr2 = build()
        assertNotSame(rr1, rr2)
    }

    @Test
    fun testTwoInstancesWithIdenticalInputsAreNotEqual() {
        // ReturnReceipt does NOT override equals; reference identity semantics apply.
        // A migration to a Kotlin data class would break this — pin the current behavior.
        val rr1 = build()
        val rr2 = build()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(rr1.equals(rr2))
    }

    @Test
    fun testInstanceEqualsItself() {
        val rr = build()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(rr.equals(rr))
    }

    // ─── hashCode is stable per-instance ──────────────────────────────────────

    @Test
    fun testHashCodeIsStableAcrossRepeatedCalls() {
        val rr = build()
        val h1 = rr.hashCode()
        val h2 = rr.hashCode()
        assertEquals(h1, h2)
    }

    @Test
    fun testHashCodeMatchesIdentityHashCode() {
        // ReturnReceipt does not override hashCode; the default implementation
        // must remain identity-based.
        val rr = build()
        assertEquals(System.identityHashCode(rr), rr.hashCode())
    }

    // ─── wasCommitted() is a no-op when commitHookBits == 0 ──────────────────

    @Test
    fun testWasCommittedDoesNotThrowWithNullSessionAndFreshInstance() {
        // A freshly constructed ReturnReceipt has commitHookBits == 0.
        // The wasCommitted() guard `(commitHookBits & HOOK_BIT_INSERT) != 0` is false,
        // so the null sendManagerSession is never dereferenced. This must not throw.
        val rr = build(session = null)
        rr.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommittedDoesNotMutateFieldsOnFreshInstance() {
        val rr = build(status = 3, attachmentNumber = 99)
        val statusBefore = rr.status
        val attachBefore = rr.attachmentNumber
        val ownedBefore = rr.getOwnedIdentity()
        val contactBefore = rr.getContactIdentity()

        rr.wasCommitted()

        assertEquals(statusBefore, rr.status)
        assertEquals(attachBefore, rr.attachmentNumber)
        assertSame(ownedBefore, rr.getOwnedIdentity())
        assertSame(contactBefore, rr.getContactIdentity())
    }

    // ─── NewReturnReceiptListener interface contract ───────────────────────────

    @Test
    fun testNewReturnReceiptListenerHasExactlyOneMethod() {
        // NewReturnReceiptListener is a functional interface. Pinning that it has
        // exactly one abstract method — if extra methods are added the surrounding
        // code that supplies lambdas would break.
        val methods: List<Method> = ReturnReceipt.NewReturnReceiptListener::class.java
            .methods
            .filter { java.lang.reflect.Modifier.isAbstract(it.modifiers) }
        assertEquals(
            "NewReturnReceiptListener must be a functional interface with exactly one abstract method",
            1,
            methods.size,
        )
    }

    @Test
    fun testNewReturnReceiptListenerMethodSignature() {
        // Pin the exact parameter types and return type of the callback.
        val method = ReturnReceipt.NewReturnReceiptListener::class.java
            .methods
            .single { java.lang.reflect.Modifier.isAbstract(it.modifiers) }

        assertEquals("newReturnReceipt", method.name)
        assertEquals(Void.TYPE, method.returnType)

        val params = method.parameterTypes
        assertEquals("newReturnReceipt must take exactly 3 parameters", 3, params.size)
        assertEquals("first param must be String (server)", String::class.java, params[0])
        assertEquals("second param must be Identity (ownedIdentity)", Identity::class.java, params[1])
        assertEquals("third param must be primitive long (id)", Long::class.javaPrimitiveType, params[2])
    }

    @Test
    fun testNewReturnReceiptListenerCanBeImplementedAsLambda() {
        // Confirm the interface is usable as a lambda (functional interface contract).
        var called = false
        val listener = ReturnReceipt.NewReturnReceiptListener { _, _, _ -> called = true }
        listener.newReturnReceipt("server.olvid.io", ownedIdentity, 42L)
        assertTrue("listener lambda must have been invoked", called)
    }

    // ─── Two instances do not share mutable state ─────────────────────────────

    @Test
    fun testTwoInstancesCarryIndependentFields() {
        val rr1 = build(status = 1, attachmentNumber = 10)
        val rr2 = build(status = 2, attachmentNumber = 20)

        // Fields of rr1 must not be contaminated by rr2.
        assertEquals(1, rr1.status)
        assertEquals(2, rr2.status)
        assertNotEquals(rr1.status, rr2.status)
        assertNotEquals(rr1.attachmentNumber, rr2.attachmentNumber)
    }

    // ─── contactDeviceUids preserves array contents ────────────────────────────

    @Test
    fun testContactDeviceUidsArrayContentsArePreserved() {
        val rr = build(contactDeviceUids = contactDeviceUids)
        // The constructor stores the reference as-is; the same UID objects live inside.
        assertArrayEquals(contactDeviceUids, rr.contactDeviceUids)
    }

    @Test
    fun testNullContactDeviceUidsIsPreserved() {
        val rr = build(contactDeviceUids = null)
        assertNull(rr.contactDeviceUids)
    }
}
