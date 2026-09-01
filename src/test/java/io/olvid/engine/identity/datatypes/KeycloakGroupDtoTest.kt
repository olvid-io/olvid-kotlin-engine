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

package io.olvid.engine.identity.datatypes

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [KeycloakGroupMemberKickedData] and [KeycloakGroupDeletionData].
 *
 * Both are plain Jackson DTOs with public no-arg + all-args constructors,
 * JavaBean-style getters/setters, and @JsonIgnoreProperties(ignoreUnknown = true).
 * No @JsonProperty overrides are present, so wire names equal Java field names.
 *
 * These tests pin the contracts a Kotlin migration (especially via J2K → data class)
 * could break:
 *   - no-arg constructor must survive (Jackson requires it for deserialization);
 *   - all-args constructor must store references without cloning;
 *   - wire field names must stay as-is;
 *   - equals must remain reference-identity (not value-based);
 *   - setters must mutate (fields must not become immutable `val`s).
 */
class KeycloakGroupDtoTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // KeycloakGroupMemberKickedData
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── No-arg constructor ───────────────────────────────────────────────────

    @Test
    fun kicked_noArgConstructor_producesNullGroupUid() {
        val obj = KeycloakGroupMemberKickedData()
        assertNull(obj.groupUid)
    }

    @Test
    fun kicked_noArgConstructor_producesNullIdentity() {
        val obj = KeycloakGroupMemberKickedData()
        assertNull(obj.identity)
    }

    @Test
    fun kicked_noArgConstructor_producesZeroTimestamp() {
        val obj = KeycloakGroupMemberKickedData()
        assertEquals(0L, obj.timestamp)
    }

    // ─── All-args constructor stores fields by reference ──────────────────────

    @Test
    fun kicked_allArgsConstructor_storesGroupUidByReference() {
        val groupUid = byteArrayOf(1, 2, 3)
        val obj = KeycloakGroupMemberKickedData(groupUid, byteArrayOf(4, 5, 6), 1234567890L)
        assertSame(groupUid, obj.groupUid)
    }

    @Test
    fun kicked_allArgsConstructor_storesIdentityByReference() {
        val identity = byteArrayOf(4, 5, 6)
        val obj = KeycloakGroupMemberKickedData(byteArrayOf(1, 2, 3), identity, 1234567890L)
        assertSame(identity, obj.identity)
    }

    @Test
    fun kicked_allArgsConstructor_storesTimestampExactly() {
        val obj = KeycloakGroupMemberKickedData(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6), 1234567890L)
        assertEquals(1234567890L, obj.timestamp)
    }

    // ─── Setters mutate state ─────────────────────────────────────────────────

    @Test
    fun kicked_setGroupUid_updatesFieldViaGetter() {
        val obj = KeycloakGroupMemberKickedData()
        val newUid = byteArrayOf(10, 20, 30)
        obj.groupUid = newUid
        assertSame(newUid, obj.groupUid)
    }

    @Test
    fun kicked_setIdentity_updatesFieldViaGetter() {
        val obj = KeycloakGroupMemberKickedData()
        val newId = byteArrayOf(40, 50, 60)
        obj.identity = newId
        assertSame(newId, obj.identity)
    }

    @Test
    fun kicked_setTimestamp_updatesFieldViaGetter() {
        val obj = KeycloakGroupMemberKickedData()
        obj.timestamp = 9876543210L
        assertEquals(9876543210L, obj.timestamp)
    }

    // ─── Jackson round-trip ───────────────────────────────────────────────────

    @Test
    fun kicked_jacksonRoundTrip_preservesAllFields() {
        val original = KeycloakGroupMemberKickedData(
            byteArrayOf(1, 2, 3),
            byteArrayOf(4, 5, 6),
            1234567890L
        )
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, KeycloakGroupMemberKickedData::class.java)

        assertArrayEquals(original.groupUid, deserialized.groupUid)
        assertArrayEquals(original.identity, deserialized.identity)
        assertEquals(original.timestamp, deserialized.timestamp)
    }

    @Test
    fun kicked_jacksonRoundTrip_wireNamesAreGroupUidIdentityTimestamp() {
        val original = KeycloakGroupMemberKickedData(
            byteArrayOf(1, 2, 3),
            byteArrayOf(4, 5, 6),
            1234567890L
        )
        val json = mapper.writeValueAsString(original)

        // Wire names must equal the Java field names; no @JsonProperty renames.
        assertTrue("JSON must contain \"groupUid\"", json.contains("\"groupUid\""))
        assertTrue("JSON must contain \"identity\"", json.contains("\"identity\""))
        assertTrue("JSON must contain \"timestamp\"", json.contains("\"timestamp\""))
    }

    @Test
    fun kicked_jacksonDeserialize_ignoresUnknownFields() {
        // @JsonIgnoreProperties(ignoreUnknown = true) must survive migration.
        val json = """{"groupUid":"AQID","identity":"BAUG","timestamp":1234567890,"unknownField":"surprise"}"""
        // Must not throw
        val obj = mapper.readValue(json, KeycloakGroupMemberKickedData::class.java)
        assertEquals(1234567890L, obj.timestamp)
    }

    // ─── No-arg constructor required by Jackson ────────────────────────────────

    @Test
    fun kicked_jacksonDeserializeFromMinimalJson_usesNoArgConstructor() {
        // Jackson uses the no-arg constructor when it populates fields via setters.
        // If the no-arg constructor is missing after migration, this throws.
        val json = """{"groupUid":"AQID","identity":"BAUG","timestamp":42}"""
        val obj = mapper.readValue(json, KeycloakGroupMemberKickedData::class.java)
        assertEquals(42L, obj.timestamp)
    }

    // ─── equals / hashCode (reference identity — not overridden) ─────────────

    @Test
    fun kicked_equalsIsReferenceIdentity() {
        val obj1 = KeycloakGroupMemberKickedData(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6), 1L)
        val obj2 = KeycloakGroupMemberKickedData(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6), 1L)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj1.equals(obj1))
    }

    @Test
    fun kicked_hashCodeIsStableAcrossCalls() {
        val obj = KeycloakGroupMemberKickedData(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6), 1L)
        assertEquals(obj.hashCode(), obj.hashCode())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // KeycloakGroupDeletionData
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── No-arg constructor ───────────────────────────────────────────────────

    @Test
    fun deletion_noArgConstructor_producesNullGroupUid() {
        val obj = KeycloakGroupDeletionData()
        assertNull(obj.groupUid)
    }

    @Test
    fun deletion_noArgConstructor_producesZeroTimestamp() {
        val obj = KeycloakGroupDeletionData()
        assertEquals(0L, obj.timestamp)
    }

    // ─── All-args constructor stores fields by reference ──────────────────────

    @Test
    fun deletion_allArgsConstructor_storesGroupUidByReference() {
        val groupUid = byteArrayOf(7, 8, 9)
        val obj = KeycloakGroupDeletionData(groupUid, 9999999999L)
        assertSame(groupUid, obj.groupUid)
    }

    @Test
    fun deletion_allArgsConstructor_storesTimestampExactly() {
        val obj = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 9999999999L)
        assertEquals(9999999999L, obj.timestamp)
    }

    // ─── Setters mutate state ─────────────────────────────────────────────────

    @Test
    fun deletion_setGroupUid_updatesFieldViaGetter() {
        val obj = KeycloakGroupDeletionData()
        val newUid = byteArrayOf(11, 22, 33)
        obj.groupUid = newUid
        assertSame(newUid, obj.groupUid)
    }

    @Test
    fun deletion_setTimestamp_updatesFieldViaGetter() {
        val obj = KeycloakGroupDeletionData()
        obj.timestamp = 5555555555L
        assertEquals(5555555555L, obj.timestamp)
    }

    // ─── Jackson round-trip ───────────────────────────────────────────────────

    @Test
    fun deletion_jacksonRoundTrip_preservesAllFields() {
        val original = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 9999999999L)
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, KeycloakGroupDeletionData::class.java)

        assertArrayEquals(original.groupUid, deserialized.groupUid)
        assertEquals(original.timestamp, deserialized.timestamp)
    }

    @Test
    fun deletion_jacksonRoundTrip_wireNamesAreGroupUidTimestamp() {
        val original = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 9999999999L)
        val json = mapper.writeValueAsString(original)

        // Wire names must equal Java field names; no @JsonProperty renames.
        assertTrue("JSON must contain \"groupUid\"", json.contains("\"groupUid\""))
        assertTrue("JSON must contain \"timestamp\"", json.contains("\"timestamp\""))
    }

    @Test
    fun deletion_jacksonDeserialize_ignoresUnknownFields() {
        // @JsonIgnoreProperties(ignoreUnknown = true) must survive migration.
        val json = """{"groupUid":"BwgJ","timestamp":9999999999,"extraKey":"ignored"}"""
        // Must not throw
        val obj = mapper.readValue(json, KeycloakGroupDeletionData::class.java)
        assertEquals(9999999999L, obj.timestamp)
    }

    // ─── No-arg constructor required by Jackson ────────────────────────────────

    @Test
    fun deletion_jacksonDeserializeFromMinimalJson_usesNoArgConstructor() {
        // Jackson uses the no-arg constructor when it populates fields via setters.
        // If the no-arg constructor is missing after migration, this throws.
        val json = """{"groupUid":"BwgJ","timestamp":99}"""
        val obj = mapper.readValue(json, KeycloakGroupDeletionData::class.java)
        assertEquals(99L, obj.timestamp)
    }

    // ─── equals / hashCode (reference identity — not overridden) ─────────────

    @Test
    fun deletion_equalsIsReferenceIdentity() {
        val obj1 = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 1L)
        val obj2 = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 1L)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj1.equals(obj2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj1.equals(obj1))
    }

    @Test
    fun deletion_hashCodeIsStableAcrossCalls() {
        val obj = KeycloakGroupDeletionData(byteArrayOf(7, 8, 9), 1L)
        assertEquals(obj.hashCode(), obj.hashCode())
    }
}
