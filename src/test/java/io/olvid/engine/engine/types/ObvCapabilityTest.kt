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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * Characterization tests for [ObvCapability] — a Java enum with wire-format string mappings
 * and byte-array serialization, about to be migrated to Kotlin via J2K.
 *
 * These tests pin all load-bearing wire contracts:
 *  - toString()/fromString() mappings (persisted to device_capabilities column, exchanged with server)
 *  - currentCapabilities composition (which capabilities this device claims)
 *  - serializeRawDeviceCapabilities(): null-separator byte layout, sort-before-serialize invariant
 *  - deserializeDeviceCapabilities(): unknown-string dropping (future-compat)
 *  - deserializeRawDeviceCapabilities(): keeps unknowns, different null contract than the above
 */
class ObvCapabilityTest {

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

    // ─── Group 1: Wire-format toString() mappings ──────────────────────────────

    @Test
    fun testToString_webrtcContinuousIce() {
        assertEquals("webrtc_continuous_ice", ObvCapability.WEBRTC_CONTINUOUS_ICE.toString())
    }

    @Test
    fun testToString_oneToOneContacts() {
        assertEquals("one_to_one_contacts", ObvCapability.ONE_TO_ONE_CONTACTS.toString())
    }

    @Test
    fun testToString_groupsV2() {
        assertEquals("groups_v2", ObvCapability.GROUPS_V2.toString())
    }

    // ─── Group 2: Wire-format fromString() mappings ────────────────────────────

    @Test
    fun testFromString_webrtcContinuousIce() {
        assertEquals(ObvCapability.WEBRTC_CONTINUOUS_ICE, ObvCapability.fromString("webrtc_continuous_ice"))
    }

    @Test
    fun testFromString_oneToOneContacts() {
        assertEquals(ObvCapability.ONE_TO_ONE_CONTACTS, ObvCapability.fromString("one_to_one_contacts"))
    }

    @Test
    fun testFromString_groupsV2() {
        assertEquals(ObvCapability.GROUPS_V2, ObvCapability.fromString("groups_v2"))
    }

    @Test
    fun testFromString_unknownStringReturnsNull() {
        assertNull(ObvCapability.fromString("foo"))
    }

    @Test
    fun testFromString_emptyStringReturnsNull() {
        assertNull(ObvCapability.fromString(""))
    }

    @Test
    fun testFromString_caseSensitive_uppercaseReturnsNull() {
        // Mappings are case-sensitive: "GROUPS_V2" (the enum name) must NOT map to GROUPS_V2.
        // A Kotlin migration that uses enumValueOf() or name comparison would accidentally accept this.
        assertNull(ObvCapability.fromString("GROUPS_V2"))
    }

    // ─── Group 3: toString/fromString roundtrip ────────────────────────────────

    @Test
    fun testRoundtrip_webrtcContinuousIce() {
        val value = ObvCapability.WEBRTC_CONTINUOUS_ICE
        assertEquals(value, ObvCapability.fromString(value.toString()))
    }

    @Test
    fun testRoundtrip_oneToOneContacts() {
        val value = ObvCapability.ONE_TO_ONE_CONTACTS
        assertEquals(value, ObvCapability.fromString(value.toString()))
    }

    @Test
    fun testRoundtrip_groupsV2() {
        val value = ObvCapability.GROUPS_V2
        assertEquals(value, ObvCapability.fromString(value.toString()))
    }

    // ─── Group 4: currentCapabilities content ─────────────────────────────────

    @Test
    fun testCurrentCapabilities_hasSizeTwo() {
        assertEquals(
            "currentCapabilities must contain exactly 2 entries",
            2,
            ObvCapability.currentCapabilities.size,
        )
    }

    @Test
    fun testCurrentCapabilities_containsOneToOneContactsAndGroupsV2() {
        assertTrue(
            "currentCapabilities must contain ONE_TO_ONE_CONTACTS",
            ObvCapability.currentCapabilities.contains(ObvCapability.ONE_TO_ONE_CONTACTS),
        )
        assertTrue(
            "currentCapabilities must contain GROUPS_V2",
            ObvCapability.currentCapabilities.contains(ObvCapability.GROUPS_V2),
        )
    }

    @Test
    fun testCurrentCapabilities_doesNotContainWebrtcContinuousIce() {
        // The local device deliberately does not claim webrtc_continuous_ice.
        // A Kotlin migration that adds it back (e.g., by listing all values()) would be wrong.
        assertFalse(
            "currentCapabilities must NOT contain WEBRTC_CONTINUOUS_ICE",
            ObvCapability.currentCapabilities.contains(ObvCapability.WEBRTC_CONTINUOUS_ICE),
        )
    }

    // ─── Group 5: getAll() returns all 3 values in declaration order ───────────

    @Test
    fun testGetAll_returnsAllThreeInDeclarationOrder() {
        val all = ObvCapability.getAll()
        assertEquals(3, all.size)
        assertEquals(ObvCapability.WEBRTC_CONTINUOUS_ICE, all[0])
        assertEquals(ObvCapability.ONE_TO_ONE_CONTACTS, all[1])
        assertEquals(ObvCapability.GROUPS_V2, all[2])
    }

    // ─── Group 6: capabilityListToStringArray() ────────────────────────────────

    @Test
    fun testCapabilityListToStringArray_emptyList() {
        val result = ObvCapability.capabilityListToStringArray(emptyList<ObvCapability>())
        assertEquals(0, result.size)
    }

    @Test
    fun testCapabilityListToStringArray_singleElement() {
        val result = ObvCapability.capabilityListToStringArray(listOf<ObvCapability>(ObvCapability.GROUPS_V2))
        assertArrayEquals(arrayOf("groups_v2"), result)
    }

    @Test
    fun testCapabilityListToStringArray_allThreeInDeclarationOrder() {
        val result = ObvCapability.capabilityListToStringArray(
            listOf<ObvCapability>(
                ObvCapability.WEBRTC_CONTINUOUS_ICE,
                ObvCapability.ONE_TO_ONE_CONTACTS,
                ObvCapability.GROUPS_V2,
            )
        )
        assertArrayEquals(arrayOf("webrtc_continuous_ice", "one_to_one_contacts", "groups_v2"), result)
    }

    @Test
    fun testCapabilityListToStringArray_preservesInputOrder() {
        // Order in → order out; the method does NOT sort.
        val result = ObvCapability.capabilityListToStringArray(
            listOf<ObvCapability>(ObvCapability.GROUPS_V2, ObvCapability.ONE_TO_ONE_CONTACTS)
        )
        assertArrayEquals(arrayOf("groups_v2", "one_to_one_contacts"), result)
    }

    // ─── Group 7: serializeRawDeviceCapabilities() wire-format byte layout ──────

    @Test
    fun testSerializeRaw_nullInput_returnsNull() {
        assertNull(ObvCapability.serializeRawDeviceCapabilities(null))
    }

    @Test
    fun testSerializeRaw_emptyArray_returnsEmptyByteArray() {
        val result = ObvCapability.serializeRawDeviceCapabilities(emptyArray())
        assertNotNull(result)
        assertEquals(0, result!!.size)
    }

    @Test
    fun testSerializeRaw_singleElement_returnsUtf8BytesWithNoSeparator() {
        val result = ObvCapability.serializeRawDeviceCapabilities(arrayOf("foo"))
        assertArrayEquals("foo".toByteArray(StandardCharsets.UTF_8), result)
    }

    @Test
    fun testSerializeRaw_twoElements_separatedByNullByte() {
        // Two strings joined by a 0x00 byte separator.
        val result = ObvCapability.serializeRawDeviceCapabilities(arrayOf("aa", "bb"))
        val expected = byteArrayOf(*"aa".toByteArray(StandardCharsets.UTF_8), 0x00, *"bb".toByteArray(StandardCharsets.UTF_8))
        assertArrayEquals(expected, result)
    }

    @Test
    fun testSerializeRaw_threeElements_separatedByNullBytes() {
        val result = ObvCapability.serializeRawDeviceCapabilities(arrayOf("s1", "s2", "s3"))
        val expected = byteArrayOf(
            *"s1".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"s2".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"s3".toByteArray(StandardCharsets.UTF_8),
        )
        assertArrayEquals(expected, result)
    }

    @Test
    fun testSerializeRaw_sortedBeforeSerializing() {
        // The array is sorted before serialization so that two devices with the same
        // capability set always produce identical bytes regardless of insertion order.
        // A Kotlin migration that drops Arrays.sort() would break this invariant.
        val result = ObvCapability.serializeRawDeviceCapabilities(arrayOf("b", "a"))
        // After sorting: "a", "b" → a + 0x00 + b
        val expected = byteArrayOf(*"a".toByteArray(StandardCharsets.UTF_8), 0x00, *"b".toByteArray(StandardCharsets.UTF_8))
        assertArrayEquals(
            "serializeRawDeviceCapabilities must sort its input before serializing",
            expected,
            result,
        )
    }

    // ─── Group 8: deserializeDeviceCapabilities() ─────────────────────────────

    @Test
    fun testDeserializeCapabilities_nullInput_returnsNull() {
        // null → null (NOT empty list). Callers distinguish null (no data) from empty (no caps).
        assertNull(ObvCapability.deserializeDeviceCapabilities(null))
    }

    @Test
    fun testDeserializeCapabilities_emptyBytes_returnsEmptyList() {
        val result = ObvCapability.deserializeDeviceCapabilities(byteArrayOf())
        assertNotNull(result)
        assertTrue(result!!.isEmpty())
    }

    @Test
    fun testDeserializeCapabilities_singleKnownCapability() {
        val input = "groups_v2".toByteArray(StandardCharsets.UTF_8)
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(listOf(ObvCapability.GROUPS_V2), result)
    }

    @Test
    fun testDeserializeCapabilities_twoKnownCapabilities_preservesInputOrder() {
        // groups_v2 NUL one_to_one_contacts  → [GROUPS_V2, ONE_TO_ONE_CONTACTS]
        val input = byteArrayOf(
            *"groups_v2".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"one_to_one_contacts".toByteArray(StandardCharsets.UTF_8),
        )
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(listOf(ObvCapability.GROUPS_V2, ObvCapability.ONE_TO_ONE_CONTACTS), result)
    }

    @Test
    fun testDeserializeCapabilities_unknownStringsAreSilentlyDropped() {
        // "groups_v2 NUL unknown NUL one_to_one_contacts" → [GROUPS_V2, ONE_TO_ONE_CONTACTS]
        // This is the future-compat path: new server-side capabilities must not break the client.
        val input = byteArrayOf(
            *"groups_v2".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"unknown".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"one_to_one_contacts".toByteArray(StandardCharsets.UTF_8),
        )
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(
            "Unknown segments must be silently dropped",
            listOf(ObvCapability.GROUPS_V2, ObvCapability.ONE_TO_ONE_CONTACTS),
            result,
        )
    }

    @Test
    fun testDeserializeCapabilities_trailingStringWithoutNullTerminator_isDecoded() {
        // No terminating null: the final segment (after the last 0x00 — or the only segment)
        // must still be captured.
        val input = "groups_v2".toByteArray(StandardCharsets.UTF_8) // no trailing 0x00
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(listOf(ObvCapability.GROUPS_V2), result)
    }

    @Test
    fun testDeserializeCapabilities_leadingNullByte_emptyFirstSegmentIsDropped() {
        // 0x00 + "groups_v2" → first segment is "" → fromString("") == null → dropped.
        val input = byteArrayOf(0x00, *"groups_v2".toByteArray(StandardCharsets.UTF_8))
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(
            "Empty leading segment must be dropped (fromString returns null for \"\")",
            listOf(ObvCapability.GROUPS_V2),
            result,
        )
    }

    @Test
    fun testDeserializeCapabilities_consecutiveNullBytes_emptyMiddleSegmentIsDropped() {
        // "groups_v2" + 0x00 + 0x00 + "one_to_one_contacts" → empty middle segment dropped.
        val input = byteArrayOf(
            *"groups_v2".toByteArray(StandardCharsets.UTF_8), 0x00, 0x00,
            *"one_to_one_contacts".toByteArray(StandardCharsets.UTF_8),
        )
        val result = ObvCapability.deserializeDeviceCapabilities(input)
        assertEquals(
            "Empty middle segment must be dropped",
            listOf(ObvCapability.GROUPS_V2, ObvCapability.ONE_TO_ONE_CONTACTS),
            result,
        )
    }

    // ─── Group 9: deserializeRawDeviceCapabilities() ──────────────────────────

    @Test
    fun testDeserializeRaw_nullInput_returnsEmptyArray() {
        // NOTE: different contract from deserializeDeviceCapabilities which returns null for null!
        // A Kotlin migration that unifies both to return null (or both to empty) would break callers.
        val result = ObvCapability.deserializeRawDeviceCapabilities(null)
        assertNotNull(result)
        assertEquals(0, result.size)
    }

    @Test
    fun testDeserializeRaw_emptyBytes_returnsEmptyArray() {
        val result = ObvCapability.deserializeRawDeviceCapabilities(byteArrayOf())
        assertEquals(0, result.size)
    }

    @Test
    fun testDeserializeRaw_singleKnownCapability_returnsStringArray() {
        val input = "groups_v2".toByteArray(StandardCharsets.UTF_8)
        val result = ObvCapability.deserializeRawDeviceCapabilities(input)
        assertArrayEquals(arrayOf("groups_v2"), result)
    }

    @Test
    fun testDeserializeRaw_unknownStringsAreKept() {
        // deserializeRawDeviceCapabilities does NOT filter unknowns — all segments are returned.
        val input = byteArrayOf(
            *"foo".toByteArray(StandardCharsets.UTF_8), 0x00,
            *"bar".toByteArray(StandardCharsets.UTF_8),
        )
        val result = ObvCapability.deserializeRawDeviceCapabilities(input)
        assertArrayEquals(arrayOf("foo", "bar"), result)
    }

    // ─── Group 10: Roundtrip serialize → deserializeRaw (sort is stable) ───────

    @Test
    fun testSerializeRaw_deserializeRaw_roundtrip_sortIsStable() {
        // Input is unsorted; after serialize (sorts internally) → deserializeRaw,
        // the result should be in sorted order, not the original order.
        val input = arrayOf("b", "a", "c")
        val serialized = ObvCapability.serializeRawDeviceCapabilities(input)
        val result = ObvCapability.deserializeRawDeviceCapabilities(serialized)
        assertArrayEquals(
            "Roundtrip must yield alphabetically sorted strings due to sort in serialize",
            arrayOf("a", "b", "c"),
            result,
        )
    }

    // ─── Group 11: Full roundtrip currentCapabilities → bytes → capabilities ───

    @Test
    fun testCurrentCapabilities_fullRoundtrip() {
        // currentCapabilities → capabilityListToStringArray → serializeRawDeviceCapabilities
        // → deserializeDeviceCapabilities must yield the same set of capabilities.
        val stringArray = ObvCapability.capabilityListToStringArray(ObvCapability.currentCapabilities)
        val serialized = ObvCapability.serializeRawDeviceCapabilities(stringArray)
        val deserialized = ObvCapability.deserializeDeviceCapabilities(serialized)

        assertNotNull(deserialized)
        assertEquals(
            "Roundtripped capability set must have the same size as currentCapabilities",
            ObvCapability.currentCapabilities.size,
            deserialized!!.size,
        )
        assertTrue(
            "Roundtripped capabilities must contain all of currentCapabilities",
            deserialized.containsAll(ObvCapability.currentCapabilities),
        )
    }
}
