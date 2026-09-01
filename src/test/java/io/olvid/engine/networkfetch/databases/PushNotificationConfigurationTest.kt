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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [PushNotificationConfiguration] — the SQLite-backed entity in the
 * engine networkfetch module. These tests pin observable behavior that does NOT touch a live
 * database:
 *
 *  - The [PushNotificationConfiguration.shouldReactivateCurrentDevice] bitmask contract:
 *    bit 0x1 of multiDeviceConfiguration controls the result.
 *  - [PushNotificationConfiguration.getPushNotificationTypeAndParameters] factory: returns a
 *    non-null instance whose fields match the source fields and whose reactivateCurrentDevice
 *    flag reflects the current bitmask.
 *  - [PushNotificationConfiguration.create] null-guards for each required parameter.
 *  - The private 8-arg constructor stores every parameter by reference (for objects) or by
 *    value (for primitives) — verified via getters and reflection.
 *  - All public getters delegate to the stored fields without transformation.
 *  - [PushNotificationConfiguration.wasCommitted] is safe to call with a null session
 *    (commitHookBits == 0 so the listener is never invoked).
 *  - equals / hashCode: default Object reference semantics (not overridden by the source).
 *
 * Database operations (insert, delete, get, getAll, clearKickOtherDevices, createTable,
 * upgradeTable) and notification dispatch in wasCommitted when hook bits are set are
 * intentionally out of scope — those require a live Session.
 *
 * Note on [PushNotificationConfiguration.create] bitmask construction: the bit-building
 * logic inside create() is only observable after insert() succeeds, which requires a real
 * Session. It is therefore not separately testable here; it is covered indirectly by the
 * getPushNotificationTypeAndParameters tests which exercise the same bitmask expression via
 * reflection.
 */
class PushNotificationConfigurationTest {

    private lateinit var ownedIdentity: Identity
    private lateinit var deviceUid: UID
    private lateinit var identityMaskingUid: UID
    private lateinit var deviceUidToReplace: UID
    private lateinit var token: ByteArray
    private val pushNotificationType: Byte = PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID

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

        ownedIdentity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
        deviceUid = UID(ByteArray(UID.UID_LENGTH) { 0x11 })
        identityMaskingUid = UID(ByteArray(UID.UID_LENGTH) { 0x22 })
        deviceUidToReplace = UID(ByteArray(UID.UID_LENGTH) { 0x33 })
        token = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
    }

    // ─── Reflection helpers ────────────────────────────────────────────────────

    /**
     * Instantiates a [PushNotificationConfiguration] via its private 8-arg constructor,
     * bypassing the DB-touching [PushNotificationConfiguration.create] factory.
     */
    private fun newViaReflection(
        session: FetchManagerSession? = null,
        ownedIdentity: Identity = this.ownedIdentity,
        deviceUid: UID = this.deviceUid,
        pushNotificationType: Byte = this.pushNotificationType,
        token: ByteArray? = this.token,
        identityMaskingUid: UID? = this.identityMaskingUid,
        multiDeviceConfiguration: Int = 0,
        deviceUidToReplace: UID? = this.deviceUidToReplace,
    ): PushNotificationConfiguration {
        val ctor = PushNotificationConfiguration::class.java.getDeclaredConstructor(
            FetchManagerSession::class.java,
            Identity::class.java,
            UID::class.java,
            Byte::class.javaPrimitiveType,
            ByteArray::class.java,
            UID::class.java,
            Int::class.javaPrimitiveType,
            UID::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(
            session,
            ownedIdentity,
            deviceUid,
            pushNotificationType,
            token,
            identityMaskingUid,
            multiDeviceConfiguration,
            deviceUidToReplace,
        )
    }

    private fun readField(obj: PushNotificationConfiguration, fieldName: String): Any? {
        val f = PushNotificationConfiguration::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        return f.get(obj)
    }

    private fun writeField(obj: PushNotificationConfiguration, fieldName: String, value: Any?) {
        val f = PushNotificationConfiguration::class.java.getDeclaredField(fieldName)
        f.isAccessible = true
        f.set(obj, value)
    }

    // ─── Group 1: shouldReactivateCurrentDevice() bitmask contract (5 tests) ───

    @Test
    fun testShouldReactivate_zeroBits_returnsFalse() {
        // multiDeviceConfiguration = 0 → bit 0x1 is clear → false
        val config = newViaReflection(multiDeviceConfiguration = 0)
        assertFalse(config.shouldReactivateCurrentDevice())
    }

    @Test
    fun testShouldReactivate_bit0x1Set_returnsTrue() {
        // multiDeviceConfiguration = 0x1 → exactly the reactivation bit → true
        val config = newViaReflection(multiDeviceConfiguration = 0x1)
        assertTrue(config.shouldReactivateCurrentDevice())
    }

    @Test
    fun testShouldReactivate_onlyOtherBitsSet_returnsFalse() {
        // multiDeviceConfiguration = 0x2 → bit 0x1 is NOT set → false
        // Confirms only bit 0x1 matters; adjacent bits are ignored.
        val config = newViaReflection(multiDeviceConfiguration = 0x2)
        assertFalse(config.shouldReactivateCurrentDevice())
    }

    @Test
    fun testShouldReactivate_bothBitsSet_returnsTrue() {
        // multiDeviceConfiguration = 0x3 → bit 0x1 IS set (among others) → true
        val config = newViaReflection(multiDeviceConfiguration = 0x3)
        assertTrue(config.shouldReactivateCurrentDevice())
    }

    @Test
    fun testShouldReactivate_allBitsSet_returnsTrue() {
        // multiDeviceConfiguration = -1 (0xFFFFFFFF) → bit 0x1 is definitely set → true
        val config = newViaReflection(multiDeviceConfiguration = -1)
        assertTrue(config.shouldReactivateCurrentDevice())
    }

    // ─── Group 2: getPushNotificationTypeAndParameters() factory (2 tests) ─────

    @Test
    fun testGetPushNotificationTypeAndParameters_reactivateFalse() {
        // With multiDeviceConfiguration = 0 (reactivate = false), verify the returned
        // PushNotificationTypeAndParameters carries the correct field values.
        val config = newViaReflection(multiDeviceConfiguration = 0)

        val params = config.pushNotificationTypeAndParameters

        assertNotNull(params)
        assertEquals(pushNotificationType, params.pushNotificationType)
        assertSame("token must be the same reference", token, params.token)
        assertSame("identityMaskingUid must be the same reference", identityMaskingUid, params.identityMaskingUid)
        assertFalse("reactivateCurrentDevice must be false when bit 0x1 is clear", params.reactivateCurrentDevice)
        assertSame("deviceUidToReplace must be the same reference", deviceUidToReplace, params.deviceUidToReplace)
    }

    @Test
    fun testGetPushNotificationTypeAndParameters_reactivateTrue() {
        // With multiDeviceConfiguration = 0x1 (reactivate = true), the bitmask must
        // propagate into the returned PushNotificationTypeAndParameters.reactivateCurrentDevice.
        val config = newViaReflection(multiDeviceConfiguration = 0x1)

        val params = config.pushNotificationTypeAndParameters

        assertNotNull(params)
        assertEquals(pushNotificationType, params.pushNotificationType)
        assertSame("token must be the same reference", token, params.token)
        assertSame("identityMaskingUid must be the same reference", identityMaskingUid, params.identityMaskingUid)
        assertTrue("reactivateCurrentDevice must be true when bit 0x1 is set", params.reactivateCurrentDevice)
        assertSame("deviceUidToReplace must be the same reference", deviceUidToReplace, params.deviceUidToReplace)
    }

    // ─── Group 3: create() null-guards (4 tests) ──────────────────────────────
    //
    // create() checks ownedIdentity, deviceUid, and pushNotificationTypeAndParameters
    // for null before touching the session. Passing a null session is therefore safe
    // for these null-guard branches.

    @Test
    fun testCreate_nullOwnedIdentity_returnsNull() {
        val params = PushNotificationTypeAndParameters(
            pushNotificationType, token, identityMaskingUid, false, deviceUidToReplace
        )
        val result = PushNotificationConfiguration.create(null, null, deviceUid, params)
        assertNull(result)
    }

    @Test
    fun testCreate_nullDeviceUid_returnsNull() {
        val params = PushNotificationTypeAndParameters(
            pushNotificationType, token, identityMaskingUid, false, deviceUidToReplace
        )
        val result = PushNotificationConfiguration.create(null, ownedIdentity, null, params)
        assertNull(result)
    }

    @Test
    fun testCreate_nullPushNotificationTypeAndParameters_returnsNull() {
        val result = PushNotificationConfiguration.create(null, ownedIdentity, deviceUid, null)
        assertNull(result)
    }

    @Test
    fun testCreate_allNullArgs_returnsNull() {
        val result = PushNotificationConfiguration.create(null, null, null, null)
        assertNull(result)
    }

    // ─── Group 4: private 8-arg constructor field storage (7 tests) ───────────

    @Test
    fun testConstructor_storesOwnedIdentityByReference() {
        val config = newViaReflection()
        assertSame(ownedIdentity, readField(config, "ownedIdentity"))
    }

    @Test
    fun testConstructor_storesDeviceUidByReference() {
        val config = newViaReflection()
        assertSame(deviceUid, readField(config, "deviceUid"))
    }

    @Test
    fun testConstructor_storesPushNotificationType() {
        val config = newViaReflection(pushNotificationType = 0x10.toByte())
        assertEquals(0x10.toByte(), readField(config, "pushNotificationType"))
    }

    @Test
    fun testConstructor_storesTokenByReference() {
        val config = newViaReflection()
        assertSame(token, readField(config, "token"))
    }

    @Test
    fun testConstructor_storesIdentityMaskingUidByReference() {
        val config = newViaReflection()
        assertSame(identityMaskingUid, readField(config, "identityMaskingUid"))
    }

    @Test
    fun testConstructor_storesMultiDeviceConfiguration() {
        val config = newViaReflection(multiDeviceConfiguration = 0x3)
        assertEquals(0x3, readField(config, "multiDeviceConfiguration"))
    }

    @Test
    fun testConstructor_storesDeviceUidToReplaceByReference() {
        val config = newViaReflection()
        assertSame(deviceUidToReplace, readField(config, "deviceUidToReplace"))
    }

    // ─── Group 5: getters delegate to stored fields (6 tests) ─────────────────

    @Test
    fun testGetOwnedIdentity_returnsStoredIdentity() {
        val config = newViaReflection()
        assertSame(ownedIdentity, config.getOwnedIdentity())
    }

    @Test
    fun testGetDeviceUid_returnsStoredUid() {
        val config = newViaReflection()
        assertSame(deviceUid, config.deviceUid)
    }

    @Test
    fun testGetPushNotificationType_returnsStoredByte() {
        val config = newViaReflection(pushNotificationType = 0x13.toByte())
        assertEquals(0x13.toByte(), config.pushNotificationType)
    }

    @Test
    fun testGetToken_returnsStoredTokenByReference() {
        val config = newViaReflection()
        assertSame(token, config.token)
    }

    @Test
    fun testGetIdentityMaskingUid_returnsStoredUid() {
        val config = newViaReflection()
        assertSame(identityMaskingUid, config.identityMaskingUid)
    }

    @Test
    fun testGetDeviceUidToReplace_returnsStoredUid() {
        val config = newViaReflection()
        assertSame(deviceUidToReplace, config.deviceUidToReplace)
    }

    // ─── Group 6: wasCommitted() no-op with null session (2 tests) ────────────
    //
    // When commitHookBits == 0 (the state after construction without insert()),
    // wasCommitted() must not throw and must not mutate any observable state.

    @Test
    fun testWasCommitted_doesNotThrow_withNullSession() {
        val config = newViaReflection(session = null)
        config.wasCommitted() // must complete without throwing
    }

    @Test
    fun testWasCommitted_doesNotMutateFields_withNullSession() {
        val config = newViaReflection(session = null, multiDeviceConfiguration = 0x1)

        val identityBefore = config.getOwnedIdentity()
        val deviceUidBefore = config.deviceUid
        val typeBefore = config.pushNotificationType
        val tokenBefore = config.token
        val maskUidBefore = config.identityMaskingUid
        val replaceBefore = config.deviceUidToReplace
        val reactivateBefore = config.shouldReactivateCurrentDevice()

        config.wasCommitted()

        assertSame(identityBefore, config.getOwnedIdentity())
        assertSame(deviceUidBefore, config.deviceUid)
        assertEquals(typeBefore, config.pushNotificationType)
        assertSame(tokenBefore, config.token)
        assertSame(maskUidBefore, config.identityMaskingUid)
        assertSame(replaceBefore, config.deviceUidToReplace)
        assertEquals(reactivateBefore, config.shouldReactivateCurrentDevice())
    }

    // ─── Group 7: reference identity equals / hashCode (2 tests) ──────────────
    //
    // The Java source does NOT override equals/hashCode. Two instances built with
    // identical inputs must NOT compare equal, and hashCode must be stable per
    // instance. A migration to a Kotlin data class would silently break this.

    @Test
    fun testEqualsIsReferenceIdentity() {
        val config1 = newViaReflection()
        val config2 = newViaReflection()

        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("Same reference must equal itself", config1.equals(config1))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Two distinct instances with identical fields must NOT be equal", config1.equals(config2))
    }

    @Test
    fun testHashCodeIsStableAcrossCalls() {
        val config = newViaReflection()
        val h1 = config.hashCode()
        val h2 = config.hashCode()
        assertEquals("hashCode must be stable across calls on the same instance", h1, h2)
    }

    // ─── Additional: null-optional fields accepted by constructor ──────────────

    @Test
    fun testConstructor_acceptsNullToken() {
        val config = newViaReflection(token = null)
        assertNull(config.token)
    }

    @Test
    fun testConstructor_acceptsNullIdentityMaskingUid() {
        val config = newViaReflection(identityMaskingUid = null)
        assertNull(config.identityMaskingUid)
    }

    @Test
    fun testConstructor_acceptsNullDeviceUidToReplace() {
        val config = newViaReflection(deviceUidToReplace = null)
        assertNull(config.deviceUidToReplace)
    }

    @Test
    fun testGetPushNotificationTypeAndParameters_withNullOptionalFields() {
        // Verifies the factory handles null token, identityMaskingUid, deviceUidToReplace
        // gracefully — they must flow through as-is.
        val config = newViaReflection(
            token = null,
            identityMaskingUid = null,
            deviceUidToReplace = null,
            multiDeviceConfiguration = 0,
        )
        val params = config.pushNotificationTypeAndParameters

        assertNotNull(params)
        assertNull(params.token)
        assertNull(params.identityMaskingUid)
        assertNull(params.deviceUidToReplace)
        assertFalse(params.reactivateCurrentDevice)
    }

    @Test
    fun testTwoInstancesAreIndependent() {
        // Two instances built from different inputs must not share state.
        val config1 = newViaReflection(multiDeviceConfiguration = 0)
        val config2 = newViaReflection(multiDeviceConfiguration = 0x1)

        assertNotSame(config1, config2)
        assertFalse(config1.shouldReactivateCurrentDevice())
        assertTrue(config2.shouldReactivateCurrentDevice())
    }
}
