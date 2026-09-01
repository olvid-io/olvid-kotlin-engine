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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshot
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Field

/**
 * Characterization tests for four small public DTOs:
 *  1. ObvDeviceManagementRequest  (~28 tests)
 *  2. ObvPushNotificationType     (~13 tests)
 *  3. ObvSyncSnapshot             (~16 tests)
 *  4. ObvSyncDiff                 (~13 tests)
 *
 * Wire-format constants and encode/decode contracts are pinned so that
 * a Kotlin migration cannot silently renumber or reorder them.
 */
class ObvMiscTypesTest {

    // ─── Test data ─────────────────────────────────────────────────────────────

    /** Deterministic 32-byte UID payload (UID.UID_LENGTH = 32). */
    private val uidBytes: ByteArray = ByteArray(32) { it.toByte() }

    /** A different 32-byte payload — used to verify distinct UIDs. */
    private val uidBytes2: ByteArray = ByteArray(32) { (it + 100).toByte() }

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
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvDeviceManagementRequest
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── Group 1: ACTION_* wire-format integer constant pins ──────────────────
    //
    // These ints appear as the first element of the encoded list.  Any accidental
    // renumbering (e.g., by a Kotlin migration reordering companion-object vals)
    // silently corrupts persisted or transmitted device management requests.

    @Test
    fun deviceMgmt_actionSetNickname_is0() {
        assertEquals(0, ObvDeviceManagementRequest.ACTION_SET_NICKNAME)
    }

    @Test
    fun deviceMgmt_actionDeactivateDevice_is1() {
        assertEquals(1, ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE)
    }

    @Test
    fun deviceMgmt_actionSetUnexpiringDevice_is2() {
        assertEquals(2, ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE)
    }

    // ─── Group 2: createSetNicknameRequest ────────────────────────────────────

    @Test
    fun deviceMgmt_createSetNickname_storesActionSetNickname() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Alice")
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_NICKNAME, req.action)
    }

    @Test
    fun deviceMgmt_createSetNickname_storesBytesDeviceUidByReference() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Alice")
        assertArrayEquals(uidBytes, req.bytesDeviceUid)
    }

    @Test
    fun deviceMgmt_createSetNickname_storesNickname() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Alice")
        assertEquals("Alice", req.nickname)
    }

    /**
     * Load-bearing null-coercion pin: null nickname MUST be coerced to "".
     * A Kotlin migration that keeps the field nullable would silently break
     * downstream consumers that rely on this guarantee.
     */
    @Test
    fun deviceMgmt_createSetNickname_nullNicknameCoercedToEmpty() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, null)
        assertEquals("", req.nickname)
    }

    // ─── Group 3: createDeactivateDeviceRequest ───────────────────────────────

    @Test
    fun deviceMgmt_createDeactivate_storesActionDeactivate() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        assertEquals(ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE, req.action)
    }

    @Test
    fun deviceMgmt_createDeactivate_storesNullNickname() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        assertNull(req.nickname)
    }

    // ─── Group 4: createSetUnexpiringDeviceRequest ────────────────────────────

    @Test
    fun deviceMgmt_createSetUnexpiring_storesActionSetUnexpiring() {
        val req = ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(uidBytes)
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE, req.action)
    }

    @Test
    fun deviceMgmt_createSetUnexpiring_storesNullNickname() {
        val req = ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(uidBytes)
        assertNull(req.nickname)
    }

    // ─── Group 5: getDeviceUid() ──────────────────────────────────────────────

    @Test
    fun deviceMgmt_getDeviceUid_returnsNullWhenBytesDeviceUidIsNull() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(null)
        assertNull(req.getDeviceUid())
    }

    @Test
    fun deviceMgmt_getDeviceUid_returnsUidWithMatchingBytes() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val uid = req.getDeviceUid()
        assertNotNull(uid)
        assertArrayEquals(uidBytes, uid!!.bytes)
    }

    // ─── Group 6: encode() layout per action ─────────────────────────────────
    //
    // Each action uses a different list arity.  Pin the slot count and per-slot
    // content so that a layout change (e.g., accidentally inlining nickname into
    // the same slot as the UID) is caught immediately.

    @Test
    fun deviceMgmt_encode_setNickname_produces3ElementList() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Bob")
        val elements = req.encode()!!.decodeList()
        assertEquals(3, elements.size)
    }

    @Test
    fun deviceMgmt_encode_setNickname_firstSlotIsActionId() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Bob")
        val elements = req.encode()!!.decodeList()
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_NICKNAME.toLong(), elements[0].decodeLong())
    }

    @Test
    fun deviceMgmt_encode_setNickname_secondSlotIsUidBytes() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Bob")
        val elements = req.encode()!!.decodeList()
        assertArrayEquals(uidBytes, elements[1].decodeBytes())
    }

    @Test
    fun deviceMgmt_encode_setNickname_thirdSlotIsNickname() {
        val req = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Bob")
        val elements = req.encode()!!.decodeList()
        assertEquals("Bob", elements[2].decodeString())
    }

    @Test
    fun deviceMgmt_encode_deactivate_produces2ElementList() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val elements = req.encode()!!.decodeList()
        assertEquals(2, elements.size)
    }

    @Test
    fun deviceMgmt_encode_deactivate_firstSlotIsActionId() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val elements = req.encode()!!.decodeList()
        assertEquals(ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE.toLong(), elements[0].decodeLong())
    }

    @Test
    fun deviceMgmt_encode_setUnexpiring_produces2ElementList() {
        val req = ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(uidBytes)
        val elements = req.encode()!!.decodeList()
        assertEquals(2, elements.size)
    }

    @Test
    fun deviceMgmt_encode_setUnexpiring_firstSlotIsActionId() {
        val req = ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(uidBytes)
        val elements = req.encode()!!.decodeList()
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE.toLong(), elements[0].decodeLong())
    }

    @Test
    fun deviceMgmt_encode_unknownAction_returnsNull() {
        // Force an unknown action via reflection — the private 3-arg constructor
        // is not accessible, so we mutate the `action` field on an existing instance.
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val field: Field = ObvDeviceManagementRequest::class.java.getDeclaredField("action")
        field.isAccessible = true
        field.setInt(req, 999)
        assertNull(req.encode())
    }

    // ─── Group 7: of(Encoded) round-trip per action ───────────────────────────

    @Test
    fun deviceMgmt_roundTrip_setNickname_preservesAllFields() {
        val original = ObvDeviceManagementRequest.createSetNicknameRequest(uidBytes, "Charlie")
        val decoded = ObvDeviceManagementRequest.of(original.encode()!!)
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_NICKNAME, decoded.action)
        assertArrayEquals(uidBytes, decoded.bytesDeviceUid)
        assertEquals("Charlie", decoded.nickname)
    }

    @Test
    fun deviceMgmt_roundTrip_deactivate_preservesAllFields() {
        val original = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val decoded = ObvDeviceManagementRequest.of(original.encode()!!)
        assertEquals(ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE, decoded.action)
        assertArrayEquals(uidBytes, decoded.bytesDeviceUid)
        assertNull(decoded.nickname)
    }

    @Test
    fun deviceMgmt_roundTrip_setUnexpiring_preservesAllFields() {
        val original = ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(uidBytes)
        val decoded = ObvDeviceManagementRequest.of(original.encode()!!)
        assertEquals(ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE, decoded.action)
        assertArrayEquals(uidBytes, decoded.bytesDeviceUid)
        assertNull(decoded.nickname)
    }

    // ─── Group 8: of(Encoded) error paths ────────────────────────────────────

    @Test
    fun deviceMgmt_of_setNickname_wrongArity2_throwsDecodingException() {
        // SET_NICKNAME expects 3 elements; supply 2 → DecodingException.
        val malformed = Encoded.of(arrayOf(
            Encoded.of(ObvDeviceManagementRequest.ACTION_SET_NICKNAME.toLong()),
            Encoded.of(uidBytes),
        ))
        try {
            ObvDeviceManagementRequest.of(malformed)
            fail("Expected DecodingException for SET_NICKNAME with 2 elements")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun deviceMgmt_of_deactivate_wrongArity3_throwsDecodingException() {
        // DEACTIVATE_DEVICE expects 2 elements; supply 3 → DecodingException.
        val malformed = Encoded.of(arrayOf(
            Encoded.of(ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE.toLong()),
            Encoded.of(uidBytes),
            Encoded.of("extra"),
        ))
        try {
            ObvDeviceManagementRequest.of(malformed)
            fail("Expected DecodingException for DEACTIVATE_DEVICE with 3 elements")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun deviceMgmt_of_setUnexpiring_wrongArity3_throwsDecodingException() {
        // SET_UNEXPIRING_DEVICE expects 2 elements; supply 3 → DecodingException.
        val malformed = Encoded.of(arrayOf(
            Encoded.of(ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE.toLong()),
            Encoded.of(uidBytes),
            Encoded.of("extra"),
        ))
        try {
            ObvDeviceManagementRequest.of(malformed)
            fail("Expected DecodingException for SET_UNEXPIRING_DEVICE with 3 elements")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun deviceMgmt_of_unknownAction_throwsDecodingException() {
        val malformed = Encoded.of(arrayOf(
            Encoded.of(999L),
            Encoded.of(uidBytes),
        ))
        try {
            ObvDeviceManagementRequest.of(malformed)
            fail("Expected DecodingException for unknown action 999")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // ─── Group 9: Wire-format golden-hex pin ─────────────────────────────────
    //
    // Pin the exact byte sequence for ACTION_DEACTIVATE_DEVICE with deterministic
    // UID bytes (0x00..0x1f).  Any change to Encoded's framing (BYTE_IDS_LIST,
    // length field, INT_ENCODING_LENGTH) or to the action constant will change
    // this hex and surface a clear regression.
    //
    // Layout (uidBytes = 0x00..0x1f, action = 1):
    //   Encoded.of(1L):
    //     01 00 00 00 08  00 00 00 00 00 00 00 01   (13 bytes)
    //   Encoded.of(uidBytes) — 32-byte payload:
    //     00 00 00 20  = 32 length
    //     00 01 00 00 00 20 00 01 02 ... 1f          (5 + 32 = 37 bytes)
    //   Outer list content = 13 + 37 = 50 (0x32) bytes
    //   Outer: 03 00 00 00 32 <50 bytes>

    @Test
    fun deviceMgmt_encode_deactivate_goldenHex() {
        val req = ObvDeviceManagementRequest.createDeactivateDeviceRequest(uidBytes)
        val encoded = req.encode()!!
        val hex = encoded.bytes.joinToString("") { "%02x".format(it) }

        // Build the expected hex from first principles so the anatomy is auditable:
        //   action element:   01 00 00 00 08  00 00 00 00 00 00 00 01
        val actionHex = "010000000800000000000000" + "01"
        //   uid element:      00 (BYTE_IDS_BYTE_ARRAY) 00 00 00 20 (len=32) 00..1f
        val uidPayloadHex = (0 until 32).joinToString("") { "%02x".format(it) }
        val uidElementHex = "00" + "00000020" + uidPayloadHex
        //   outer list:       03 <len as 4-byte big-endian> <content>
        val contentLen = (actionHex.length / 2) + (uidElementHex.length / 2)
        val outerHeader = "03" + "%08x".format(contentLen)
        val expected = outerHeader + actionHex + uidElementHex

        assertEquals(expected, hex)
    }

    // ─── Group 10: Public final fields accessibility ──────────────────────────
    //
    // Pin that the three public fields are declared `final` on the JVM.
    // A J2K migration that drops `val` from a companion object or turns
    // fields into `var` would change the JVM modifier bits.

    @Test
    fun deviceMgmt_publicFields_areDeclaredFinal() {
        val clazz = ObvDeviceManagementRequest::class.java
        val modifiers = java.lang.reflect.Modifier.FINAL
        for (fieldName in listOf("action", "bytesDeviceUid", "nickname")) {
            val f = clazz.getDeclaredField(fieldName)
            assertTrue(
                "Field '$fieldName' must be declared final",
                (f.modifiers and modifiers) != 0,
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvPushNotificationType
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── Group 1: Platform enum constants exist ────────────────────────────────
    //
    // Pin the set of Platform values.  Adding/removing a platform changes which
    // push-notification type the engine can represent and may break serialization.

    @Test
    fun pushNotification_platform_androidExists() {
        assertNotNull(ObvPushNotificationType.Platform.ANDROID)
    }

    @Test
    fun pushNotification_platform_windowsExists() {
        assertNotNull(ObvPushNotificationType.Platform.WINDOWS)
    }

    @Test
    fun pushNotification_platform_linuxExists() {
        assertNotNull(ObvPushNotificationType.Platform.LINUX)
    }

    @Test
    fun pushNotification_platform_daemonExists() {
        assertNotNull(ObvPushNotificationType.Platform.DAEMON)
    }

    @Test
    fun pushNotification_platform_hasExactly4Values() {
        assertEquals(
            "Platform must declare exactly 4 constants",
            4,
            ObvPushNotificationType.Platform.values().size,
        )
    }

    // ─── Group 2: createAndroid ───────────────────────────────────────────────

    @Test
    fun pushNotification_createAndroid_storesPlatformAndroid() {
        val obj = ObvPushNotificationType.createAndroid("myToken")
        assertEquals(ObvPushNotificationType.Platform.ANDROID, obj.platform)
    }

    @Test
    fun pushNotification_createAndroid_storesFirebaseToken() {
        val obj = ObvPushNotificationType.createAndroid("myToken")
        assertEquals("myToken", obj.firebaseToken)
    }

    @Test
    fun pushNotification_createAndroid_nullToken_isStoredAsNull() {
        val obj = ObvPushNotificationType.createAndroid(null)
        assertNull(obj.firebaseToken)
    }

    // ─── Group 3: createWindows / createLinux / createDaemon ─────────────────
    //
    // These non-Android platforms store null for firebaseToken because they do not
    // use Firebase push notifications.  Pin this so a migration cannot accidentally
    // default the field to an empty string.

    @Test
    fun pushNotification_createWindows_storesPlatformWindows() {
        val obj = ObvPushNotificationType.createWindows()
        assertEquals(ObvPushNotificationType.Platform.WINDOWS, obj.platform)
    }

    @Test
    fun pushNotification_createWindows_firebaseTokenIsNull() {
        val obj = ObvPushNotificationType.createWindows()
        assertNull(obj.firebaseToken)
    }

    @Test
    fun pushNotification_createLinux_storesPlatformLinux() {
        val obj = ObvPushNotificationType.createLinux()
        assertEquals(ObvPushNotificationType.Platform.LINUX, obj.platform)
    }

    @Test
    fun pushNotification_createLinux_firebaseTokenIsNull() {
        val obj = ObvPushNotificationType.createLinux()
        assertNull(obj.firebaseToken)
    }

    @Test
    fun pushNotification_createDaemon_storesPlatformDaemon() {
        val obj = ObvPushNotificationType.createDaemon()
        assertEquals(ObvPushNotificationType.Platform.DAEMON, obj.platform)
    }

    @Test
    fun pushNotification_createDaemon_firebaseTokenIsNull() {
        val obj = ObvPushNotificationType.createDaemon()
        assertNull(obj.firebaseToken)
    }

    // ─── Group 4: Fields are final ────────────────────────────────────────────

    @Test
    fun pushNotification_fields_areDeclaredFinal() {
        val clazz = ObvPushNotificationType::class.java
        val modifiers = java.lang.reflect.Modifier.FINAL
        for (fieldName in listOf("platform", "firebaseToken")) {
            val f = clazz.getDeclaredField(fieldName)
            assertTrue(
                "Field '$fieldName' must be declared final",
                (f.modifiers and modifiers) != 0,
            )
        }
    }

    // ─── Group 5: Platform ordinal stability ──────────────────────────────────
    //
    // If Platform enum values are sent over the wire via ordinal(), changing their
    // declaration order silently corrupts the protocol.  Pin the ordinal of each.

    @Test
    fun pushNotification_platform_androidOrdinal_is0() {
        assertEquals(0, ObvPushNotificationType.Platform.ANDROID.ordinal)
    }

    @Test
    fun pushNotification_platform_windowsOrdinal_is1() {
        assertEquals(1, ObvPushNotificationType.Platform.WINDOWS.ordinal)
    }

    @Test
    fun pushNotification_platform_linuxOrdinal_is2() {
        assertEquals(2, ObvPushNotificationType.Platform.LINUX.ordinal)
    }

    @Test
    fun pushNotification_platform_daemonOrdinal_is3() {
        assertEquals(3, ObvPushNotificationType.Platform.DAEMON.ordinal)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvSyncSnapshot
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // ObvSyncSnapshot is constructed via the static factory `get()`, which
    // takes ObvBackupAndSyncDelegate instances.  Tests use minimal stubs.

    /** Minimal stub that stores a pre-built snapshot node under a fixed tag. */
    private fun makeStubDelegate(delegateTag: String, node: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode): io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate {
        return object : io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate {
            override val tag: String? get() = delegateTag
            override fun getSyncSnapshot(ownedIdentity: io.olvid.engine.datatypes.Identity?): io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode = node
            override fun restoreOwnedIdentity(obvOwnedIdentity: io.olvid.engine.engine.types.identities.ObvIdentity?, node: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode?): io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback? = null
            override fun restoreSyncSnapshot(node: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode?): io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback? = null
            override fun serialize(ctx: io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.SerializationContext?, node: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode?): ByteArray = byteArrayOf()
            override fun deserialize(ctx: io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.SerializationContext?, bytes: ByteArray?): io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode = node
            override fun getDeviceSnapshot(): io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode = node
            override fun getAdditionalProfileInfo(ownedIdentity: io.olvid.engine.datatypes.Identity?): MutableMap<String?, String?>? = null
        }
    }

    /** Stub ObvSyncSnapshotNode — identical content iff same instance. */
    private fun makeNode(sameContentAs: Any? = null): io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode {
        val anchor = sameContentAs  // capture for closure
        return object : io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode {
            override fun areContentsTheSame(other: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode?): Boolean = (other === this || other === anchor)
            override fun computeDiff(other: io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? = mutableListOf()
        }
    }

    // ─── Group 1: get() stores nodes by tag ───────────────────────────────────

    @Test
    fun syncSnapshot_get_returnsNonNull() {
        val node = makeNode()
        val delegate = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegate)
        assertNotNull(snapshot)
    }

    @Test
    fun syncSnapshot_get_snapshotNodeRetrievableByTag() {
        val node = makeNode()
        val delegate = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegate)
        assertNotNull("Node should be retrievable via getSnapshotNode", snapshot.getSnapshotNode("tagA"))
    }

    @Test
    fun syncSnapshot_get_unknownTagReturnsNull() {
        val node = makeNode()
        val delegate = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegate)
        assertNull(snapshot.getSnapshotNode("unknownTag"))
    }

    @Test
    fun syncSnapshot_get_multipleDelegate_bothTagsPresent() {
        val nodeA = makeNode()
        val nodeB = makeNode()
        val delegateA = makeStubDelegate("alpha", nodeA)
        val delegateB = makeStubDelegate("beta", nodeB)
        val snapshot = ObvSyncSnapshot.get(null, delegateA, delegateB)
        assertNotNull(snapshot.getSnapshotNode("alpha"))
        assertNotNull(snapshot.getSnapshotNode("beta"))
    }

    // ─── Group 2: areContentsTheSame ──────────────────────────────────────────

    @Test
    fun syncSnapshot_areContentsTheSame_nullOtherReturnsFalse() {
        val node = makeNode()
        val delegate = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegate)
        assertFalse(snapshot.areContentsTheSame(null))
    }

    @Test
    fun syncSnapshot_areContentsTheSame_sameNodeInstanceReturnsTrue() {
        // Use the exact same node instance in both snapshots.  The stub's
        // areContentsTheSame checks `other === this`, so this is guaranteed true.
        val node = makeNode()
        val snapshotA = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        val snapshotB = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        assertTrue(snapshotA.areContentsTheSame(snapshotB))
    }

    @Test
    fun syncSnapshot_areContentsTheSame_differentTagSetReturnsFalse() {
        val nodeA = makeNode()
        val nodeB = makeNode()
        val snapshotA = ObvSyncSnapshot.get(null, makeStubDelegate("alpha", nodeA))
        val snapshotB = ObvSyncSnapshot.get(null, makeStubDelegate("beta", nodeB))
        // Different key sets → must return false.
        assertFalse(snapshotA.areContentsTheSame(snapshotB))
    }

    // ─── Group 3: computeDiff ─────────────────────────────────────────────────

    @Test
    fun syncSnapshot_computeDiff_sameTagsNoDiffs_returnsEmptyList() {
        // The stub's computeDiff always returns emptyList(); use the same node
        // for both snapshots to keep the key sets identical.
        val node = makeNode()
        val snapshotA = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        val snapshotB = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))

        val diffs = snapshotA.computeDiff(snapshotB)
        assertTrue("No diffs expected for equivalent snapshots", diffs.isEmpty())
    }

    @Test
    fun syncSnapshot_computeDiff_differentTagSets_also_throwsException() {
        val node = makeNode()
        val snapshotA = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        val snapshotB = ObvSyncSnapshot.get(null, makeStubDelegate("tagB", makeNode()))
        try {
            snapshotA.computeDiff(snapshotB)
            fail("Expected Exception for mismatched tag sets")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun syncSnapshot_computeDiff_differentTagSets_throwsException() {
        val snapshotA = ObvSyncSnapshot.get(null, makeStubDelegate("alpha", makeNode()))
        val snapshotB = ObvSyncSnapshot.get(null, makeStubDelegate("beta", makeNode()))
        try {
            snapshotA.computeDiff(snapshotB)
            fail("Expected Exception for mismatched tag sets")
        } catch (_: Exception) {
            // expected
        }
    }

    // ─── Group 4: restore / restoreOwnedIdentity error paths ──────────────────

    @Test
    fun syncSnapshot_restore_missingTag_throwsException() {
        // Snapshot was built with "tagA" but restore expects "tagB".
        val node = makeNode()
        val snapshot = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        val wrongDelegate = makeStubDelegate("tagB", node)
        try {
            snapshot.restore(wrongDelegate)
            fail("Expected Exception for missing tag in restore")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun syncSnapshot_restoreOwnedIdentity_missingTag_throwsException() {
        val node = makeNode()
        val snapshot = ObvSyncSnapshot.get(null, makeStubDelegate("tagA", node))
        val wrongDelegate = makeStubDelegate("tagB", node)
        try {
            snapshot.restoreOwnedIdentity(null, wrongDelegate)
            fail("Expected Exception for missing tag in restoreOwnedIdentity")
        } catch (_: Exception) {
            // expected
        }
    }

    // ─── Group 5: toEncodedDictionary / fromEncodedDictionary round-trip ──────

    @Test
    fun syncSnapshot_toEncodedDictionary_returnsNonNullForValidSnapshot() {
        val node = makeNode()
        val delegate = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegate)
        val dict = snapshot.toEncodedDictionary(delegate)
        // The stub's serialize() returns byteArrayOf(), so serialization succeeds.
        assertNotNull(dict)
    }

    @Test
    fun syncSnapshot_fromEncodedDictionary_missingKeyReturnsNull() {
        // Build a valid dictionary for "tagA" but then ask fromEncodedDictionary
        // using a delegate with a different tag → returns null.
        val node = makeNode()
        val delegateA = makeStubDelegate("tagA", node)
        val snapshot = ObvSyncSnapshot.get(null, delegateA)
        val dict = snapshot.toEncodedDictionary(delegateA)
        assertNotNull(dict)

        val delegateB = makeStubDelegate("tagB", node)
        val recovered = ObvSyncSnapshot.fromEncodedDictionary(dict!!, delegateB)
        assertNull("fromEncodedDictionary must return null for a missing key", recovered)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ObvSyncDiff
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── Group 1: TYPE_* wire-format integer constant pins ────────────────────

    @Test
    fun syncDiff_typeSettingAutoJoinGroups_is0() {
        assertEquals(0, ObvSyncDiff.TYPE_SETTING_AUTO_JOIN_GROUPS)
    }

    @Test
    fun syncDiff_typeSettingSendReadReceipt_is1() {
        assertEquals(1, ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT)
    }

    @Test
    fun syncDiff_typeSettingUnarchiveOnNotification_is2() {
        assertEquals(2, ObvSyncDiff.TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION)
    }

    // ─── Group 2: Constructor stores all fields ───────────────────────────────
    //
    // Fields are private; we read them via reflection.  The goal is to pin that
    // each constructor parameter ends up in the expected field without any
    // swap or truncation.

    private fun readPrivateField(obj: Any, name: String): Any? {
        val f: Field = obj.javaClass.getDeclaredField(name)
        f.isAccessible = true
        return f.get(obj)
    }

    @Test
    fun syncDiff_constructor_storesDiffType() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        assertEquals(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, readPrivateField(diff, "diffType"))
    }

    @Test
    fun syncDiff_constructor_resolutionInProgressIsFalseByDefault() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        assertEquals(false, readPrivateField(diff, "resolutionInProgress"))
    }

    @Test
    fun syncDiff_constructor_storesLocalBoolean() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        assertEquals(true, readPrivateField(diff, "localBoolean"))
    }

    @Test
    fun syncDiff_constructor_storesOtherBoolean() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        assertEquals(false, readPrivateField(diff, "otherBoolean"))
    }

    @Test
    fun syncDiff_constructor_storesLocalString() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_AUTO_JOIN_GROUPS, null, null, "everyone", "nobody")
        assertEquals("everyone", readPrivateField(diff, "localString"))
    }

    @Test
    fun syncDiff_constructor_storesOtherString() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_AUTO_JOIN_GROUPS, null, null, "everyone", "nobody")
        assertEquals("nobody", readPrivateField(diff, "otherString"))
    }

    // ─── Group 3: markResolutionInProgress ────────────────────────────────────

    @Test
    fun syncDiff_markResolutionInProgress_setsFieldToTrue() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        diff.markResolutionInProgress()
        assertEquals(true, readPrivateField(diff, "resolutionInProgress"))
    }

    @Test
    fun syncDiff_markResolutionInProgress_isIdempotent() {
        val diff = ObvSyncDiff(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, true, false, null, null)
        diff.markResolutionInProgress()
        diff.markResolutionInProgress()
        assertEquals(true, readPrivateField(diff, "resolutionInProgress"))
    }

    // ─── Group 4: Static factory methods ─────────────────────────────────────

    @Test
    fun syncDiff_createSettingAutoJoinGroups_usesBooleanNullAndStrings() {
        val diff = ObvSyncDiff.createSettingAutoJoinGroups("everyone", "nobody")
        assertEquals(ObvSyncDiff.TYPE_SETTING_AUTO_JOIN_GROUPS, readPrivateField(diff, "diffType"))
        assertNull(readPrivateField(diff, "localBoolean"))
        assertNull(readPrivateField(diff, "otherBoolean"))
        assertEquals("everyone", readPrivateField(diff, "localString"))
        assertEquals("nobody", readPrivateField(diff, "otherString"))
    }

    @Test
    fun syncDiff_createSettingSendReadReceipt_usesBooleansAndNullStrings() {
        val diff = ObvSyncDiff.createSettingSendReadReceipt(true, false)
        assertEquals(ObvSyncDiff.TYPE_SETTING_SEND_READ_RECEIPT, readPrivateField(diff, "diffType"))
        assertEquals(true, readPrivateField(diff, "localBoolean"))
        assertEquals(false, readPrivateField(diff, "otherBoolean"))
        assertNull(readPrivateField(diff, "localString"))
        assertNull(readPrivateField(diff, "otherString"))
    }

    @Test
    fun syncDiff_createUnarchiveOnNotification_usesBooleansAndNullStrings() {
        val diff = ObvSyncDiff.createUnarchiveOnNotification(false, true)
        assertEquals(ObvSyncDiff.TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION, readPrivateField(diff, "diffType"))
        assertEquals(false, readPrivateField(diff, "localBoolean"))
        assertEquals(true, readPrivateField(diff, "otherBoolean"))
        assertNull(readPrivateField(diff, "localString"))
        assertNull(readPrivateField(diff, "otherString"))
    }
}
