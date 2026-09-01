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

package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [ServerSession] — the SQLite-backed entity in the engine
 * networkfetch module.
 *
 * These tests pin the two highest-value wire-format contracts that a Java→Kotlin migration
 * could silently break without touching any tests:
 *
 *  - [ServerSession.deserializeApiKeyStatus]: 9-case switch that maps server-wire integers
 *    to [ServerSession.ApiKeyStatus] enum values. The integer values are persisted to disk,
 *    so any reordering or constant rename during migration would silently corrupt stored rows.
 *  - [ServerSession.deserializePermissions]: 3-bit bitmask decoder that maps a `long` field
 *    to a `List<Permission>`. The bit positions and the iteration ORDER (CALL → WEB_CLIENT →
 *    MULTI_DEVICE) are wire contracts. A Kotlin port that reorders the `if` blocks would
 *    produce a different list order.
 *
 * Additionally pinned (without DB):
 *  - The private 2-arg constructor initial field state (via reflection).
 *  - Instance getters that delegate to `deserialize*`.
 *  - [ServerSession.create] null-guard short-circuit.
 *  - [ServerSession.wasCommitted] is a no-op.
 *  - Default reference-identity equals/hashCode (no override present).
 *
 * Database operations (insert/delete/setToken/setChallengeAndNonce/get/getAll/createTable)
 * are intentionally OUT OF SCOPE — they belong to integration tests with a real Session.
 */
class ServerSessionTest {

    private lateinit var identity: Identity

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
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
    }

    // ─── Reflection helpers ────────────────────────────────────────────────────

    /**
     * Invokes the private (FetchManagerSession, Identity) constructor without going through
     * [ServerSession.create] (which calls insert() and requires a real Session).
     */
    private fun newViaReflection(
        session: FetchManagerSession?,
        ownedIdentity: Identity?,
    ): ServerSession {
        val ctor = ServerSession::class.java.getDeclaredConstructor(
            FetchManagerSession::class.java,
            Identity::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(session, ownedIdentity)
    }

    private fun setField(obj: ServerSession, name: String, value: Any?) {
        val f = ServerSession::class.java.getDeclaredField(name)
        f.isAccessible = true
        f.set(obj, value)
    }

    private fun getField(obj: ServerSession, name: String): Any? {
        val f = ServerSession::class.java.getDeclaredField(name)
        f.isAccessible = true
        return f.get(obj)
    }

    // ─── Group 1: deserializeApiKeyStatus — 9-case wire contract ──────────────

    @Test
    fun testDeserializeApiKeyStatus_valid() {
        assertEquals(
            ServerSession.ApiKeyStatus.VALID,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_VALID),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_expired() {
        assertEquals(
            ServerSession.ApiKeyStatus.EXPIRED,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_EXPIRED),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_licensesExhausted() {
        assertEquals(
            ServerSession.ApiKeyStatus.LICENSES_EXHAUSTED,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_LICENSES_EXHAUSTED),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_openBetaKey() {
        assertEquals(
            ServerSession.ApiKeyStatus.OPEN_BETA_KEY,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_OPEN_BETA_KEY),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_freeTrialKey() {
        assertEquals(
            ServerSession.ApiKeyStatus.FREE_TRIAL_KEY,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_FREE_TRIAL_KEY),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_awaitingPaymentGracePeriod() {
        assertEquals(
            ServerSession.ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_awaitingPaymentOnHold() {
        assertEquals(
            ServerSession.ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_freeTrialKeyExpired() {
        assertEquals(
            ServerSession.ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_unknown_explicitConstant() {
        // API_KEY_STATUS_UNKNOWN is an explicit case in the switch (not just the default).
        assertEquals(
            ServerSession.ApiKeyStatus.UNKNOWN,
            ServerSession.deserializeApiKeyStatus(Constants.API_KEY_STATUS_UNKNOWN),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_defaultFallthrough_negativeOne() {
        // -1 is the sentinel written by the private constructor; it must map to UNKNOWN.
        assertEquals(
            ServerSession.ApiKeyStatus.UNKNOWN,
            ServerSession.deserializeApiKeyStatus(-1),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_defaultFallthrough_999() {
        // An arbitrary large value not present in the switch must fall through to UNKNOWN.
        assertEquals(
            ServerSession.ApiKeyStatus.UNKNOWN,
            ServerSession.deserializeApiKeyStatus(999),
        )
    }

    @Test
    fun testDeserializeApiKeyStatus_defaultFallthrough_intMaxValue() {
        // Boundary check: Int.MAX_VALUE must also fall through to UNKNOWN.
        assertEquals(
            ServerSession.ApiKeyStatus.UNKNOWN,
            ServerSession.deserializeApiKeyStatus(Int.MAX_VALUE),
        )
    }

    // Verify that every known status constant maps to a DISTINCT enum value.
    // If two constants share the same int, one case is dead code and we'd silently lose it.
    @Test
    fun testApiKeyStatusConstantsArePairwiseDistinct() {
        val constants = listOf(
            Constants.API_KEY_STATUS_VALID,
            Constants.API_KEY_STATUS_EXPIRED,
            Constants.API_KEY_STATUS_LICENSES_EXHAUSTED,
            Constants.API_KEY_STATUS_OPEN_BETA_KEY,
            Constants.API_KEY_STATUS_FREE_TRIAL_KEY,
            Constants.API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD,
            Constants.API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD,
            Constants.API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED,
            Constants.API_KEY_STATUS_UNKNOWN,
        )
        val distinct = constants.toSet()
        assertEquals(
            "All 9 API_KEY_STATUS_* constants must have distinct integer values",
            9,
            distinct.size,
        )
    }

    // ─── Group 2: deserializePermissions — 3-bit wire contract ────────────────

    @Test
    fun testDeserializePermissions_zeroBitsSet_returnsEmptyList() {
        val result = ServerSession.deserializePermissions(0L)
        assertTrue("Expected empty list for permissions=0", result.isEmpty())
    }

    @Test
    fun testDeserializePermissions_callBitOnly() {
        val result = ServerSession.deserializePermissions(Constants.API_KEY_PERMISSION_CALL)
        assertEquals(listOf(ServerSession.Permission.CALL), result)
    }

    @Test
    fun testDeserializePermissions_webClientBitOnly() {
        val result = ServerSession.deserializePermissions(Constants.API_KEY_PERMISSION_WEB_CLIENT)
        assertEquals(listOf(ServerSession.Permission.WEB_CLIENT), result)
    }

    @Test
    fun testDeserializePermissions_multiDeviceBitOnly() {
        val result = ServerSession.deserializePermissions(Constants.API_KEY_PERMISSION_MULTI_DEVICE)
        assertEquals(listOf(ServerSession.Permission.MULTI_DEVICE), result)
    }

    @Test
    fun testDeserializePermissions_allThreeBitsSet_orderIsCallWebClientMultiDevice() {
        // ORDER MATTERS: the source iterates CALL → WEB_CLIENT → MULTI_DEVICE.
        // A Kotlin port that reorders the if-blocks would produce a different list order.
        val allBits = Constants.API_KEY_PERMISSION_CALL or
            Constants.API_KEY_PERMISSION_WEB_CLIENT or
            Constants.API_KEY_PERMISSION_MULTI_DEVICE
        val result = ServerSession.deserializePermissions(allBits)
        assertEquals(
            listOf(
                ServerSession.Permission.CALL,
                ServerSession.Permission.WEB_CLIENT,
                ServerSession.Permission.MULTI_DEVICE,
            ),
            result,
        )
    }

    @Test
    fun testDeserializePermissions_callAndWebClient() {
        val bits = Constants.API_KEY_PERMISSION_CALL or Constants.API_KEY_PERMISSION_WEB_CLIENT
        val result = ServerSession.deserializePermissions(bits)
        assertEquals(
            listOf(ServerSession.Permission.CALL, ServerSession.Permission.WEB_CLIENT),
            result,
        )
    }

    @Test
    fun testDeserializePermissions_callAndMultiDevice() {
        val bits = Constants.API_KEY_PERMISSION_CALL or Constants.API_KEY_PERMISSION_MULTI_DEVICE
        val result = ServerSession.deserializePermissions(bits)
        assertEquals(
            listOf(ServerSession.Permission.CALL, ServerSession.Permission.MULTI_DEVICE),
            result,
        )
    }

    @Test
    fun testDeserializePermissions_webClientAndMultiDevice() {
        val bits = Constants.API_KEY_PERMISSION_WEB_CLIENT or Constants.API_KEY_PERMISSION_MULTI_DEVICE
        val result = ServerSession.deserializePermissions(bits)
        assertEquals(
            listOf(ServerSession.Permission.WEB_CLIENT, ServerSession.Permission.MULTI_DEVICE),
            result,
        )
    }

    @Test
    fun testDeserializePermissions_unknownBitIsIgnored() {
        // Bit 3 (0x8L) is not a defined permission bit; the decoder must ignore it.
        val result = ServerSession.deserializePermissions(0x8L)
        assertTrue("Unknown bit 0x8 must be ignored — expected empty list", result.isEmpty())
    }

    @Test
    fun testDeserializePermissions_longMaxValue_pinsCurrentBehavior() {
        // Long.MAX_VALUE has every positive bit set, including all three permission bits.
        // This pins the exact return value so a signedness regression is caught immediately.
        val result = ServerSession.deserializePermissions(Long.MAX_VALUE)
        assertEquals(
            listOf(
                ServerSession.Permission.CALL,
                ServerSession.Permission.WEB_CLIENT,
                ServerSession.Permission.MULTI_DEVICE,
            ),
            result,
        )
    }

    @Test
    fun testDeserializePermissions_negativeOne_allBitsSet_pinsCurrentBehavior() {
        // -1L has all 64 bits set (two's-complement). The three permission bits are all set,
        // so the result must include all three permissions in order. This catches any
        // signedness regression introduced during a Kotlin migration.
        val result = ServerSession.deserializePermissions(-1L)
        assertEquals(
            listOf(
                ServerSession.Permission.CALL,
                ServerSession.Permission.WEB_CLIENT,
                ServerSession.Permission.MULTI_DEVICE,
            ),
            result,
        )
    }

    // ─── Group 3: getApiKeyStatus() instance getter delegates correctly ─────────

    @Test
    fun testGetApiKeyStatus_delegatesToDeserialize_valid() {
        val session = newViaReflection(null, identity)
        // Inject the raw int value that corresponds to VALID.
        setField(session, "apiKeyStatus", Constants.API_KEY_STATUS_VALID)
        assertEquals(ServerSession.ApiKeyStatus.VALID, session.getApiKeyStatus())
    }

    // ─── Group 4: getPermissions() instance getter delegates correctly ──────────

    @Test
    fun testGetPermissions_delegatesToDeserialize_callOnly() {
        val session = newViaReflection(null, identity)
        setField(session, "permissions", Constants.API_KEY_PERMISSION_CALL)
        assertEquals(listOf(ServerSession.Permission.CALL), session.getPermissions())
    }

    // ─── Group 5: create() null-guard ─────────────────────────────────────────

    @Test
    fun testCreate_returnsNullWhenOwnedIdentityIsNull() {
        // The null-guard short-circuits before any DB call; the null session is
        // never dereferenced.
        val result = ServerSession.create(null, null)
        assertNull(result)
    }

    // ─── Group 6: private constructor field storage ────────────────────────────

    @Test
    fun testConstructor_storesOwnedIdentityByReference() {
        val session = newViaReflection(null, identity)
        // The constructor must not clone the Identity — reference-identity must be preserved.
        assertSame(identity, getField(session, "ownedIdentity"))
    }

    @Test
    fun testConstructor_nonce_defaultsToNull() {
        val session = newViaReflection(null, identity)
        assertNull(getField(session, "nonce"))
    }

    @Test
    fun testConstructor_challenge_defaultsToNull() {
        val session = newViaReflection(null, identity)
        assertNull(getField(session, "challenge"))
    }

    @Test
    fun testConstructor_response_defaultsToNull() {
        val session = newViaReflection(null, identity)
        assertNull(getField(session, "response"))
    }

    @Test
    fun testConstructor_token_defaultsToNull() {
        val session = newViaReflection(null, identity)
        assertNull(getField(session, "token"))
    }

    @Test
    fun testConstructor_apiKeyStatus_defaultsToMinusOne() {
        // -1 is the sentinel "not yet received from server"; it must map to UNKNOWN via
        // deserializeApiKeyStatus and must be preserved exactly so DB round-trips are stable.
        val session = newViaReflection(null, identity)
        assertEquals(-1, getField(session, "apiKeyStatus"))
    }

    @Test
    fun testConstructor_permissions_defaultsToZero() {
        val session = newViaReflection(null, identity)
        assertEquals(0L, getField(session, "permissions"))
    }

    @Test
    fun testConstructor_apiKeyExpirationTimestamp_defaultsToZero() {
        val session = newViaReflection(null, identity)
        assertEquals(0L, getField(session, "apiKeyExpirationTimestamp"))
    }

    // ─── Group 7: public getters ───────────────────────────────────────────────

    @Test
    fun testGetOwnedIdentity_returnsStoredIdentity() {
        val session = newViaReflection(null, identity)
        assertSame(identity, session.getOwnedIdentity())
    }

    @Test
    fun testGetNonce_returnsNullByDefault() {
        val session = newViaReflection(null, identity)
        assertNull(session.nonce)
    }

    @Test
    fun testGetChallenge_returnsNullByDefault() {
        val session = newViaReflection(null, identity)
        assertNull(session.challenge)
    }

    @Test
    fun testGetResponse_returnsNullByDefault() {
        val session = newViaReflection(null, identity)
        assertNull(session.response)
    }

    @Test
    fun testGetToken_returnsNullByDefault() {
        val session = newViaReflection(null, identity)
        assertNull(session.token)
    }

    @Test
    fun testGetApiKeyExpirationTimestamp_returnsZeroByDefault() {
        val session = newViaReflection(null, identity)
        assertEquals(0L, session.apiKeyExpirationTimestamp)
    }

    @Test
    fun testGetNonce_returnsValueAfterFieldSet() {
        val session = newViaReflection(null, identity)
        val nonce = byteArrayOf(0x01, 0x02, 0x03)
        setField(session, "nonce", nonce)
        assertSame(nonce, session.nonce)
    }

    // ─── Group 8: reference-identity equals/hashCode (no override) ────────────

    @Test
    fun testEquals_isReferenceIdentity() {
        // The Java source does NOT override equals; two instances with identical
        // constructor arguments must NOT compare equal. A migration to a Kotlin
        // data class would break this contract — this test pins the current behavior.
        val a = newViaReflection(null, identity)
        val b = newViaReflection(null, identity)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(b))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(a.equals(a))
    }

    @Test
    fun testHashCode_isStableAcrossCalls() {
        val session = newViaReflection(null, identity)
        val h1 = session.hashCode()
        val h2 = session.hashCode()
        assertEquals(h1, h2)
    }

    @Test
    fun testTwoInstancesAreDistinctObjects() {
        val a = newViaReflection(null, identity)
        val b = newViaReflection(null, identity)
        assertNotSame(a, b)
    }

    // ─── Group 9: wasCommitted() is a no-op ───────────────────────────────────

    @Test
    fun testWasCommitted_doesNotThrow() {
        // The hook is a deliberate no-op ("No hooks" comment in source);
        // it must complete cleanly even with a null FetchManagerSession.
        val session = newViaReflection(null, identity)
        session.wasCommitted() // must not throw
    }

    @Test
    fun testWasCommitted_doesNotMutateState() {
        val session = newViaReflection(null, identity)
        val identityBefore = session.getOwnedIdentity()
        val nonceBefore = session.nonce
        val statusBefore = getField(session, "apiKeyStatus")
        val permsBefore = getField(session, "permissions")

        session.wasCommitted()

        assertSame(identityBefore, session.getOwnedIdentity())
        assertSame(nonceBefore, session.nonce)
        assertEquals(statusBefore, getField(session, "apiKeyStatus"))
        assertEquals(permsBefore, getField(session, "permissions"))
    }
}
