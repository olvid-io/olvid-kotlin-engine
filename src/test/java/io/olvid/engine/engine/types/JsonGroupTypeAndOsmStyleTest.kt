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

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [JsonGroupType] and [JsonOsmStyle].
 *
 * These tests pin wire-format contracts that a Java→Kotlin migration must not silently break:
 *   - String constant values stored in the groups DB
 *   - Short @JsonProperty wire names ("type", "ro", "del") for JsonGroupType
 *   - Deserialization via no-arg constructor
 *   - Static factory validation / sanitization logic
 *   - Custom equals contract for JsonGroupType
 *   - Public field wire names for JsonOsmStyle (no @JsonProperty renames)
 */
class JsonGroupTypeAndOsmStyleTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonGroupType
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── Wire-format CONSTANTS ────────────────────────────────────────────────
    // These strings are stored in the groups DB. A rename silently corrupts stored data.

    @Test
    fun groupType_typeSimpleConstant_isExactString() {
        assertEquals("simple", JsonGroupType.TYPE_SIMPLE)
    }

    @Test
    fun groupType_typePrivateConstant_isExactString() {
        assertEquals("private", JsonGroupType.TYPE_PRIVATE)
    }

    @Test
    fun groupType_typeReadOnlyConstant_isExactString() {
        assertEquals("read_only", JsonGroupType.TYPE_READ_ONLY)
    }

    @Test
    fun groupType_typeCustomConstant_isExactString() {
        assertEquals("custom", JsonGroupType.TYPE_CUSTOM)
    }

    @Test
    fun groupType_remoteDeleteNobodyConstant_isExactString() {
        assertEquals("nobody", JsonGroupType.REMOTE_DELETE_NOBODY)
    }

    @Test
    fun groupType_remoteDeleteAdminsConstant_isExactString() {
        assertEquals("admins", JsonGroupType.REMOTE_DELETE_ADMINS)
    }

    @Test
    fun groupType_remoteDeleteEveryoneConstant_isExactString() {
        assertEquals("everyone", JsonGroupType.REMOTE_DELETE_EVERYONE)
    }

    // ─── Wire-format @JsonProperty mappings ──────────────────────────────────
    // Serialized JSON must use the short names, never the long Java field names.

    @Test
    fun groupType_serialize_usesShortWireNameType() {
        val obj = JsonGroupType.createSimple()
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"type\"", json.contains("\"type\""))
    }

    @Test
    fun groupType_serialize_doesNotUseLongNameForType() {
        val obj = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_ADMINS)
        val json = mapper.writeValueAsString(obj)
        // The Java field name is "type" which is the same as the @JsonProperty value here,
        // but readOnly → "ro" and remoteDelete → "del" must use short names.
        assertTrue("JSON must contain short wire name \"ro\"", json.contains("\"ro\""))
    }

    @Test
    fun groupType_serialize_usesShortWireNameRo() {
        val obj = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_NOBODY)
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"ro\"", json.contains("\"ro\""))
        assertFalse("JSON must NOT contain \"readOnly\"", json.contains("\"readOnly\""))
    }

    @Test
    fun groupType_serialize_usesShortWireNameDel() {
        val obj = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_EVERYONE)
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"del\"", json.contains("\"del\""))
        assertFalse("JSON must NOT contain \"remoteDelete\"", json.contains("\"remoteDelete\""))
    }

    @Test
    fun groupType_deserialize_readsShortWireNames() {
        val json = """{"type":"custom","ro":true,"del":"admins"}"""
        val obj = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals("custom", obj.type)
        assertEquals(true, obj.readOnly)
        assertEquals("admins", obj.remoteDelete)
    }

    // ─── @JsonIgnoreProperties(ignoreUnknown = true) ─────────────────────────

    @Test
    fun groupType_deserialize_ignoresUnknownFields() {
        val json = """{"type":"simple","ro":null,"del":null,"unknownField":"surprise","anotherUnknown":42}"""
        // Must not throw; unknown fields are silently discarded.
        val obj = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals("simple", obj.type)
    }

    // ─── No-arg constructor ───────────────────────────────────────────────────

    @Test
    fun groupType_noArgConstructor_producesNullType() {
        val obj = JsonGroupType()
        assertNull(obj.type)
    }

    @Test
    fun groupType_noArgConstructor_producesNullReadOnly() {
        val obj = JsonGroupType()
        assertNull(obj.readOnly)
    }

    @Test
    fun groupType_noArgConstructor_producesNullRemoteDelete() {
        val obj = JsonGroupType()
        assertNull(obj.remoteDelete)
    }

    // ─── Static factories — basic field storage ───────────────────────────────

    @Test
    fun groupType_createSimple_setsTypeSimpleReadOnlyNullRemoteDeleteNull() {
        val obj = JsonGroupType.createSimple()
        assertEquals(JsonGroupType.TYPE_SIMPLE, obj.type)
        assertNull(obj.readOnly)
        assertNull(obj.remoteDelete)
    }

    @Test
    fun groupType_createPrivate_setsTypePrivateReadOnlyNullRemoteDeleteNull() {
        val obj = JsonGroupType.createPrivate()
        assertEquals(JsonGroupType.TYPE_PRIVATE, obj.type)
        assertNull(obj.readOnly)
        assertNull(obj.remoteDelete)
    }

    @Test
    fun groupType_createReadOnly_setsTypeReadOnlyReadOnlyNullRemoteDeleteNull() {
        val obj = JsonGroupType.createReadOnly()
        assertEquals(JsonGroupType.TYPE_READ_ONLY, obj.type)
        assertNull(obj.readOnly)
        assertNull(obj.remoteDelete)
    }

    // ─── createCustom — valid remoteDelete values ─────────────────────────────

    @Test
    fun groupType_createCustom_validRemoteDeleteNobody_storesNobody() {
        val obj = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_NOBODY)
        assertEquals(JsonGroupType.REMOTE_DELETE_NOBODY, obj.remoteDelete)
    }

    @Test
    fun groupType_createCustom_validRemoteDeleteAdmins_storesAdmins() {
        val obj = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_ADMINS)
        assertEquals(JsonGroupType.REMOTE_DELETE_ADMINS, obj.remoteDelete)
    }

    @Test
    fun groupType_createCustom_validRemoteDeleteEveryone_storesEveryone() {
        val obj = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_EVERYONE)
        assertEquals(JsonGroupType.REMOTE_DELETE_EVERYONE, obj.remoteDelete)
    }

    // ─── createCustom — invalid remoteDelete falls back to NOBODY (load-bearing) ─

    @Test
    fun groupType_createCustom_nullRemoteDelete_fallsBackToNobody() {
        val obj = JsonGroupType.createCustom(false, null)
        assertEquals(JsonGroupType.REMOTE_DELETE_NOBODY, obj.remoteDelete)
    }

    @Test
    fun groupType_createCustom_unknownRemoteDelete_fallsBackToNobody() {
        val obj = JsonGroupType.createCustom(false, "foo")
        assertEquals(JsonGroupType.REMOTE_DELETE_NOBODY, obj.remoteDelete)
    }

    @Test
    fun groupType_createCustom_emptyRemoteDelete_fallsBackToNobody() {
        val obj = JsonGroupType.createCustom(false, "")
        assertEquals(JsonGroupType.REMOTE_DELETE_NOBODY, obj.remoteDelete)
    }

    // ─── createCustom — readOnly stored as boxed Boolean ─────────────────────

    @Test
    fun groupType_createCustom_readOnlyTrue_storedAsBoxedTrue() {
        val obj = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_NOBODY)
        assertEquals(java.lang.Boolean.TRUE, obj.readOnly)
    }

    @Test
    fun groupType_createCustom_readOnlyFalse_storedAsBoxedFalse() {
        val obj = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_NOBODY)
        assertEquals(java.lang.Boolean.FALSE, obj.readOnly)
    }

    // ─── isEmpty() ───────────────────────────────────────────────────────────

    @Test
    fun groupType_isEmpty_trueWhenTypeIsNull() {
        val obj = JsonGroupType()
        assertTrue(obj.isEmpty())
    }

    @Test
    fun groupType_isEmpty_falseAfterCreateSimple() {
        val obj = JsonGroupType.createSimple()
        assertFalse(obj.isEmpty())
    }

    // ─── Custom equals ────────────────────────────────────────────────────────

    @Test
    fun groupType_equals_twoCreateSimpleInstances_areEqual() {
        val a = JsonGroupType.createSimple()
        val b = JsonGroupType.createSimple()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(a.equals(b))
    }

    @Test
    fun groupType_equals_simpleVsPrivate_notEqual() {
        val a = JsonGroupType.createSimple()
        val b = JsonGroupType.createPrivate()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(b))
    }

    @Test
    fun groupType_equals_customDifferentReadOnly_notEqual() {
        val a = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_ADMINS)
        val b = JsonGroupType.createCustom(false, JsonGroupType.REMOTE_DELETE_ADMINS)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(b))
    }

    @Test
    fun groupType_equals_null_returnsFalse() {
        val obj = JsonGroupType.createSimple()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals(null))
    }

    @Test
    fun groupType_equals_differentType_returnsFalse() {
        val obj = JsonGroupType.createSimple()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(obj.equals("simple"))
    }

    @Test
    fun groupType_equals_reflexive() {
        val obj = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_EVERYONE)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(obj.equals(obj))
    }

    // ─── Jackson round-trips ──────────────────────────────────────────────────

    @Test
    fun groupType_roundTrip_createSimple_fieldsPreserved() {
        val original = JsonGroupType.createSimple()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals(original, deserialized)
    }

    @Test
    fun groupType_roundTrip_createPrivate_fieldsPreserved() {
        val original = JsonGroupType.createPrivate()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals(original, deserialized)
    }

    @Test
    fun groupType_roundTrip_createReadOnly_fieldsPreserved() {
        val original = JsonGroupType.createReadOnly()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals(original, deserialized)
    }

    @Test
    fun groupType_roundTrip_createCustom_fieldsPreserved() {
        val original = JsonGroupType.createCustom(true, JsonGroupType.REMOTE_DELETE_ADMINS)
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupType::class.java)
        assertEquals(original.type, deserialized.type)
        assertEquals(original.readOnly, deserialized.readOnly)
        assertEquals(original.remoteDelete, deserialized.remoteDelete)
    }

    @Test
    fun groupType_roundTrip_readOnlyNull_preservesNull() {
        // readOnly is a BOXED Boolean; null must survive the round-trip as JSON null,
        // not be serialized as false or omitted entirely.
        val original = JsonGroupType.createSimple()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupType::class.java)
        assertNull("readOnly must round-trip as null for createSimple()", deserialized.readOnly)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonOsmStyle
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── No-arg constructor ───────────────────────────────────────────────────

    @Test
    fun osmStyle_noArgConstructor_producesNullId() {
        val obj = JsonOsmStyle()
        assertNull(obj.id)
    }

    @Test
    fun osmStyle_noArgConstructor_producesNullName() {
        val obj = JsonOsmStyle()
        assertNull(obj.name)
    }

    @Test
    fun osmStyle_noArgConstructor_producesNullUrl() {
        val obj = JsonOsmStyle()
        assertNull(obj.url)
    }

    // ─── Two-arg constructor ──────────────────────────────────────────────────

    @Test
    fun osmStyle_twoArgConstructor_storesId() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles/{z}/{x}/{y}.png")
        assertEquals("streets", obj.id)
    }

    @Test
    fun osmStyle_twoArgConstructor_storesUrl() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles/{z}/{x}/{y}.png")
        assertEquals("https://example.com/tiles/{z}/{x}/{y}.png", obj.url)
    }

    @Test
    fun osmStyle_twoArgConstructor_initializesNameToEmptyMap() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles/{z}/{x}/{y}.png")
        assertNotNull(obj.name)
        assertTrue("name map must be empty", obj.name?.isEmpty() == true)
    }

    // ─── Public field mutation ────────────────────────────────────────────────

    @Test
    fun osmStyle_fieldMutation_idCanBeSet() {
        val obj = JsonOsmStyle()
        obj.id = "satellite"
        assertEquals("satellite", obj.id)
    }

    @Test
    fun osmStyle_fieldMutation_urlCanBeSet() {
        val obj = JsonOsmStyle()
        obj.url = "https://tiles.example.com/{z}/{x}/{y}.png"
        assertEquals("https://tiles.example.com/{z}/{x}/{y}.png", obj.url)
    }

    @Test
    fun osmStyle_fieldMutation_nameCanBeSet() {
        val obj = JsonOsmStyle()
        val nameMap = HashMap<String?, String?>().also { it["en"] = "Streets"; it["fr"] = "Rues" }
        obj.name = nameMap
        assertEquals(nameMap, obj.name)
    }

    // ─── Wire-format names (no @JsonProperty — must match public field names) ──

    @Test
    fun osmStyle_serialize_usesWireNameId() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles")
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"id\"", json.contains("\"id\""))
    }

    @Test
    fun osmStyle_serialize_usesWireNameName() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles")
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"name\"", json.contains("\"name\""))
    }

    @Test
    fun osmStyle_serialize_usesWireNameUrl() {
        val obj = JsonOsmStyle("streets", "https://example.com/tiles")
        val json = mapper.writeValueAsString(obj)
        assertTrue("JSON must contain \"url\"", json.contains("\"url\""))
    }

    // ─── @JsonIgnoreProperties(ignoreUnknown = true) ─────────────────────────

    @Test
    fun osmStyle_deserialize_ignoresUnknownFields() {
        val json = """{"id":"satellite","name":{"en":"Satellite"},"url":"https://tiles.example.com","unknownField":99}"""
        // Must not throw; unknown fields are silently discarded.
        val obj = mapper.readValue(json, JsonOsmStyle::class.java)
        assertEquals("satellite", obj.id)
    }

    // ─── Jackson round-trip ───────────────────────────────────────────────────

    @Test
    fun osmStyle_roundTrip_allFieldsPreserved() {
        val original = JsonOsmStyle()
        original.id = "outdoors"
        original.name = HashMap<String?, String?>().also { it["en"] = "Outdoors"; it["de"] = "Draußen" }
        original.url = "https://example.com/{z}/{x}/{y}.png"

        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonOsmStyle::class.java)

        assertEquals(original.id, deserialized.id)
        assertEquals(original.url, deserialized.url)
        assertEquals(original.name, deserialized.name)
    }

    @Test
    fun osmStyle_roundTrip_twoArgConstructorOutput_preservesFields() {
        val original = JsonOsmStyle("streets", "https://example.com/tiles/{z}/{x}/{y}.png")
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonOsmStyle::class.java)

        assertEquals(original.id, deserialized.id)
        assertEquals(original.url, deserialized.url)
        assertEquals(original.name, deserialized.name)
    }
}
