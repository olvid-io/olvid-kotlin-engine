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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [JsonGroupDetails] and [JsonGroupDetailsWithVersionAndPhoto].
 *
 * Both are Jackson JSON DTOs. The contracts pinned here are those most at risk from a
 * Java → Kotlin migration (especially J2K → data class):
 *
 *   JsonGroupDetails
 *     - Wire names are the bare field names "name" and "description" (no @JsonProperty).
 *     - The 2-arg constructor and setters apply nullOrTrim (empty/whitespace → null, trim).
 *     - isEmpty() checks only name, not description.
 *     - equals() is value-based (name + description), NOT reference identity.
 *     - @JsonIgnoreProperties(ignoreUnknown = true) prevents deserialization failure on
 *       unknown keys.
 *
 *   JsonGroupDetailsWithVersionAndPhoto
 *     - "details" wire name maps to the groupDetails field (@JsonProperty).
 *     - "photo_label" and "photo_key" wire names map to photoServerLabel / photoServerKey.
 *     - "version" has no @JsonProperty — wire name equals the field name.
 *     - photoUrl is @JsonIgnore — must never appear in the serialized output.
 *     - No-arg constructor produces zero version and null references.
 *     - equals/hashCode are not overridden — reference identity only; pinned so a
 *       migration to a value-equality data class does not go unnoticed.
 *     - DUMMY_GROUP_DETAILS constant is stable (it is used in production code as a
 *       sentinel value).
 */
class JsonGroupDetailsTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonGroupDetails
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── 1. Wire-format: field names must appear as-is (no @JsonProperty) ─────

    @Test
    fun groupDetails_wireFormat_nameKeyIsExactlyName() {
        val details = JsonGroupDetails("Alpha", "Beta")
        val json = mapper.writeValueAsString(details)
        assertTrue(
            "Expected wire key \"name\" in serialized JSON but got: $json",
            json.contains("\"name\"")
        )
    }

    @Test
    fun groupDetails_wireFormat_descriptionKeyIsExactlyDescription() {
        val details = JsonGroupDetails("Alpha", "Beta")
        val json = mapper.writeValueAsString(details)
        assertTrue(
            "Expected wire key \"description\" in serialized JSON but got: $json",
            json.contains("\"description\"")
        )
    }

    // ─── 2. @JsonIgnoreProperties(ignoreUnknown = true) ──────────────────────

    @Test
    fun groupDetails_deserialize_ignoresUnknownFields() {
        val json = """{"name":"Gamma","description":"Delta","unknownFuture":"surprise","extra":42}"""
        // Must not throw
        val details = mapper.readValue(json, JsonGroupDetails::class.java)
        assertEquals("name must still be mapped despite extra fields", "Gamma", details.name)
        assertEquals("description must still be mapped despite extra fields", "Delta", details.description)
    }

    // ─── 3. Default no-arg constructor ───────────────────────────────────────

    @Test
    fun groupDetails_noArgConstructor_nameIsNull() {
        val details = JsonGroupDetails()
        assertNull("name must be null on a freshly constructed instance", details.name)
    }

    @Test
    fun groupDetails_noArgConstructor_descriptionIsNull() {
        val details = JsonGroupDetails()
        assertNull("description must be null on a freshly constructed instance", details.description)
    }

    // ─── 4. 2-arg constructor applies nullOrTrim ──────────────────────────────

    @Test
    fun groupDetails_twoArgConstructor_emptyStringBecomesNull() {
        val details = JsonGroupDetails("", "")
        assertNull("empty name must be converted to null by constructor", details.name)
        assertNull("empty description must be converted to null by constructor", details.description)
    }

    @Test
    fun groupDetails_twoArgConstructor_whitespaceOnlyBecomesNull() {
        val details = JsonGroupDetails("   ", "\t\n")
        assertNull("whitespace-only name must be converted to null by constructor", details.name)
        assertNull("whitespace-only description must be converted to null by constructor", details.description)
    }

    @Test
    fun groupDetails_twoArgConstructor_paddedStringIsTrimmed() {
        val details = JsonGroupDetails("  hello  ", "  world  ")
        assertEquals("name must be trimmed by constructor", "hello", details.name)
        assertEquals("description must be trimmed by constructor", "world", details.description)
    }

    @Test
    fun groupDetails_twoArgConstructor_singleCharIsPreservedAsIs() {
        val details = JsonGroupDetails("x", "y")
        assertEquals("single-char name must be preserved unchanged", "x", details.name)
        assertEquals("single-char description must be preserved unchanged", "y", details.description)
    }

    @Test
    fun groupDetails_twoArgConstructor_nullRemainsNull() {
        val details = JsonGroupDetails(null, null)
        assertNull("null name must stay null in constructor", details.name)
        assertNull("null description must stay null in constructor", details.description)
    }

    // ─── 5. setName / setDescription apply nullOrTrim ────────────────────────

    @Test
    fun groupDetails_setName_emptyStringBecomesNull() {
        val details = JsonGroupDetails("original", "desc")
        details.setName("")
        assertNull("setName(\"\") must convert to null", details.name)
    }

    @Test
    fun groupDetails_setName_paddedStringIsTrimmed() {
        val details = JsonGroupDetails()
        details.setName("  trimmed  ")
        assertEquals("setName must trim surrounding whitespace", "trimmed", details.name)
    }

    @Test
    fun groupDetails_setDescription_emptyStringBecomesNull() {
        val details = JsonGroupDetails("name", "original")
        details.setDescription("")
        assertNull("setDescription(\"\") must convert to null", details.description)
    }

    @Test
    fun groupDetails_setDescription_paddedStringIsTrimmed() {
        val details = JsonGroupDetails()
        details.setDescription("  trimmed  ")
        assertEquals("setDescription must trim surrounding whitespace", "trimmed", details.description)
    }

    // ─── 6. isEmpty() depends only on name, not description ──────────────────

    @Test
    fun groupDetails_isEmpty_allNullReturnsTrue() {
        val details = JsonGroupDetails()
        assertTrue("isEmpty() must return true when name is null", details.isEmpty())
    }

    @Test
    fun groupDetails_isEmpty_onlyDescriptionSetStillReturnsTrue() {
        val details = JsonGroupDetails(null, "some description")
        assertTrue("isEmpty() must return true even when description is set, if name is null", details.isEmpty())
    }

    @Test
    fun groupDetails_isEmpty_namePresentReturnsFalse() {
        val details = JsonGroupDetails("Group Name", null)
        assertFalse("isEmpty() must return false when name is set", details.isEmpty())
    }

    // ─── 7. Custom equals ────────────────────────────────────────────────────

    @Test
    fun groupDetails_equals_sameNameAndDescriptionAreEqual() {
        val a = JsonGroupDetails("Name", "Desc")
        val b = JsonGroupDetails("Name", "Desc")
        assertEquals("Two instances with same name+description must be equal", a, b)
    }

    @Test
    fun groupDetails_equals_differentNameAreNotEqual() {
        val a = JsonGroupDetails("Name A", "Desc")
        val b = JsonGroupDetails("Name B", "Desc")
        assertFalse("Instances with different names must not be equal", a == b)
    }

    @Test
    fun groupDetails_equals_differentDescriptionAreNotEqual() {
        val a = JsonGroupDetails("Name", "Desc A")
        val b = JsonGroupDetails("Name", "Desc B")
        assertFalse("Instances with different descriptions must not be equal", a == b)
    }

    @Test
    fun groupDetails_equals_nullReturnsFalse() {
        val a = JsonGroupDetails("Name", "Desc")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(null) must return false", a.equals(null))
    }

    @Test
    fun groupDetails_equals_differentTypeReturnsFalse() {
        val a = JsonGroupDetails("Name", "Desc")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(String) must return false", a.equals("Name"))
    }

    @Test
    fun groupDetails_equals_reflexiveReturnsTrueForSelf() {
        val a = JsonGroupDetails("Name", "Desc")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals(self) must return true", a.equals(a))
    }

    // ─── 8. Jackson round-trip preserves both fields ──────────────────────────

    @Test
    fun groupDetails_jacksonRoundTrip_preservesNameAndDescription() {
        val original = JsonGroupDetails("Round Trip Group", "A detailed description")
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetails::class.java)
        assertEquals("name must survive Jackson round-trip", original.name, deserialized.name)
        assertEquals("description must survive Jackson round-trip", original.description, deserialized.description)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonGroupDetailsWithVersionAndPhoto
    // ═══════════════════════════════════════════════════════════════════════════

    // ─── 1. Wire-format: @JsonProperty renames ────────────────────────────────

    @Test
    fun withVersionAndPhoto_wireFormat_groupDetailsSerializesAsDetails() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertTrue(
            "groupDetails must serialize with wire key \"details\" but got: $json",
            json.contains("\"details\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_groupDetailsDoesNotSerializeAsGroupDetails() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertFalse(
            "Java field name \"groupDetails\" must not appear in serialized JSON; got: $json",
            json.contains("\"groupDetails\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_photoServerLabelSerializesAsPhotoLabel() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertTrue(
            "photoServerLabel must serialize with wire key \"photo_label\" but got: $json",
            json.contains("\"photo_label\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_photoServerLabelDoesNotUseJavaName() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertFalse(
            "Java field name \"photoServerLabel\" must not appear in serialized JSON; got: $json",
            json.contains("\"photoServerLabel\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_photoServerKeySerializesAsPhotoKey() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertTrue(
            "photoServerKey must serialize with wire key \"photo_key\" but got: $json",
            json.contains("\"photo_key\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_photoServerKeyDoesNotUseJavaName() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        assertFalse(
            "Java field name \"photoServerKey\" must not appear in serialized JSON; got: $json",
            json.contains("\"photoServerKey\"")
        )
    }

    @Test
    fun withVersionAndPhoto_wireFormat_versionSerializesAsVersion() {
        val obj = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(obj)
        // version has no @JsonProperty, so it uses the field/getter name
        assertTrue(
            "version must serialize with wire key \"version\" but got: $json",
            json.contains("\"version\"")
        )
    }

    // ─── 2. photoUrl is @JsonIgnore — must not appear in serialized output ────

    @Test
    fun withVersionAndPhoto_photoUrl_isNeverSerialized() {
        val obj = buildFullWithVersionAndPhoto()
        obj.setPhotoUrl("file:///some/local/path.jpg")
        val json = mapper.writeValueAsString(obj)
        assertFalse(
            "photoUrl is @JsonIgnore and must not appear in serialized JSON; got: $json",
            json.contains("photoUrl")
        )
        assertFalse(
            "photoUrl value must not appear in serialized JSON; got: $json",
            json.contains("local/path.jpg")
        )
    }

    // ─── 3. Default no-arg constructor ───────────────────────────────────────

    @Test
    fun withVersionAndPhoto_noArgConstructor_versionIsZero() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        assertEquals("version must default to 0", 0, obj.version)
    }

    @Test
    fun withVersionAndPhoto_noArgConstructor_groupDetailsIsNull() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        assertNull("groupDetails must be null on a freshly constructed instance", obj.groupDetails)
    }

    @Test
    fun withVersionAndPhoto_noArgConstructor_photoServerLabelIsNull() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        assertNull("photoServerLabel must be null on a freshly constructed instance", obj.photoServerLabel)
    }

    @Test
    fun withVersionAndPhoto_noArgConstructor_photoServerKeyIsNull() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        assertNull("photoServerKey must be null on a freshly constructed instance", obj.photoServerKey)
    }

    @Test
    fun withVersionAndPhoto_noArgConstructor_photoUrlIsNull() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        assertNull("photoUrl must be null on a freshly constructed instance", obj.photoUrl)
    }

    // ─── 4. Getters delegate correctly ───────────────────────────────────────

    @Test
    fun withVersionAndPhoto_setters_versionRoundTripsViaGetter() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        obj.version = 42
        assertEquals("version getter must return value set by setter", 42, obj.version)
    }

    @Test
    fun withVersionAndPhoto_setters_groupDetailsRoundTripsViaGetter() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        val details = JsonGroupDetails("My Group", "A description")
        obj.setGroupDetails(details)
        assertNotNull("groupDetails must not be null after setGroupDetails", obj.groupDetails)
        assertEquals("groupDetails name must round-trip via getter", "My Group", obj.groupDetails!!.getName())
    }

    @Test
    fun withVersionAndPhoto_setters_photoUrlRoundTripsViaGetter() {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        obj.setPhotoUrl("file:///local/photo.jpg")
        assertEquals(
            "photoUrl getter must return value set by setter",
            "file:///local/photo.jpg",
            obj.photoUrl
        )
    }

    // ─── 5. Jackson round-trip ────────────────────────────────────────────────

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_preservesVersion() {
        val original = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertEquals("version must survive Jackson round-trip", original.version, deserialized.version)
    }

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_preservesGroupDetailsName() {
        val original = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertNotNull("groupDetails must not be null after round-trip", deserialized.groupDetails)
        assertEquals(
            "groupDetails.name must survive Jackson round-trip",
            original.groupDetails!!.getName(),
            deserialized.groupDetails!!.getName()
        )
    }

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_preservesGroupDetailsDescription() {
        val original = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertEquals(
            "groupDetails.description must survive Jackson round-trip",
            original.groupDetails!!.getDescription(),
            deserialized.groupDetails!!.getDescription()
        )
    }

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_preservesPhotoServerLabel() {
        val original = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertArrayEquals(
            "photoServerLabel must survive Jackson round-trip",
            original.photoServerLabel,
            deserialized.photoServerLabel
        )
    }

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_preservesPhotoServerKey() {
        val original = buildFullWithVersionAndPhoto()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertArrayEquals(
            "photoServerKey must survive Jackson round-trip",
            original.photoServerKey,
            deserialized.photoServerKey
        )
    }

    @Test
    fun withVersionAndPhoto_jacksonRoundTrip_photoUrlIsNotRestored() {
        // photoUrl is @JsonIgnore on both getter and setter, so it must be null after
        // deserializing a round-tripped JSON (it was never written into JSON).
        val original = buildFullWithVersionAndPhoto()
        original.setPhotoUrl("file:///some/path.jpg")
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertNull(
            "photoUrl must be null after round-trip because it is @JsonIgnore",
            deserialized.photoUrl
        )
    }

    // ─── 6. @JsonIgnoreProperties(ignoreUnknown = true) ──────────────────────

    @Test
    fun withVersionAndPhoto_deserialize_ignoresUnknownFields() {
        val json = """{"version":7,"details":{"name":"Grp"},"unknownNew":"ignored","extra":123}"""
        // Must not throw
        val obj = mapper.readValue(json, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertEquals("version must be mapped despite extra fields", 7, obj.version)
        assertNotNull("groupDetails must be mapped despite extra fields", obj.groupDetails)
    }

    // ─── 7. Deserialize from hardcoded wire JSON (as sent by a peer device) ───

    @Test
    fun withVersionAndPhoto_deserializeFromHardcodedWireJson_usesShortWireNames() {
        // This JSON uses the wire-format names (as a peer device would send).
        // Confirms that setter annotations @JsonProperty("details") etc. are live.
        val wireJson = """{"version":3,"details":{"name":"Wire Group","description":"Sent by peer"}}"""
        val obj = mapper.readValue(wireJson, JsonGroupDetailsWithVersionAndPhoto::class.java)
        assertEquals("version must be parsed from wire JSON", 3, obj.version)
        assertNotNull("groupDetails must be populated from \"details\" wire key", obj.groupDetails)
        assertEquals("name must be parsed from nested details", "Wire Group", obj.groupDetails!!.getName())
        assertEquals("description must be parsed from nested details", "Sent by peer", obj.groupDetails!!.getDescription())
    }

    // ─── 8. DUMMY_GROUP_DETAILS constant is stable and parseable ─────────────

    @Test
    fun withVersionAndPhoto_dummyGroupDetails_constantIsParseableByJackson() {
        // The constant is used in production code as a sentinel. If it changes wire format
        // or becomes unparseable, callers break silently.
        val obj = mapper.readValue(
            JsonGroupDetailsWithVersionAndPhoto.DUMMY_GROUP_DETAILS,
            JsonGroupDetailsWithVersionAndPhoto::class.java
        )
        assertNotNull("DUMMY_GROUP_DETAILS must deserialize to a non-null object", obj)
        assertEquals("DUMMY_GROUP_DETAILS version must be 0", 0, obj.version)
        assertNotNull("DUMMY_GROUP_DETAILS must contain non-null groupDetails", obj.groupDetails)
        assertEquals(
            "DUMMY_GROUP_DETAILS groupDetails name must be \"dummy\"",
            "dummy",
            obj.groupDetails!!.getName()
        )
    }

    @Test
    fun withVersionAndPhoto_dummyGroupDetails_constantValue() {
        // Pin the exact string so a refactor that changes the sentinel value is caught.
        assertEquals(
            "DUMMY_GROUP_DETAILS constant value must not change",
            "{\"details\":{\"name\":\"dummy\"}, \"version\": 0}",
            JsonGroupDetailsWithVersionAndPhoto.DUMMY_GROUP_DETAILS
        )
    }

    // ─── 9. equals/hashCode: reference identity (not overridden) ─────────────

    @Test
    fun withVersionAndPhoto_equals_isReferenceIdentityNotValueEquality() {
        val obj1 = buildFullWithVersionAndPhoto()
        val obj2 = buildFullWithVersionAndPhoto()
        // Two distinct instances with identical field values must NOT be equal
        // because equals is not overridden. A migration to a data class would flip this.
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two separate instances must not be equal (equals not overridden)",
            obj1.equals(obj2)
        )
    }

    @Test
    fun withVersionAndPhoto_equals_reflexiveReturnsTrueForSelf() {
        val obj = buildFullWithVersionAndPhoto()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals(self) must return true", obj.equals(obj))
    }

    @Test
    fun withVersionAndPhoto_hashCode_isStableAcrossCalls() {
        val obj = buildFullWithVersionAndPhoto()
        assertEquals(
            "hashCode must return the same value on repeated calls",
            obj.hashCode(),
            obj.hashCode()
        )
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private fun buildFullWithVersionAndPhoto(): JsonGroupDetailsWithVersionAndPhoto {
        val obj = JsonGroupDetailsWithVersionAndPhoto()
        obj.version = 5
        obj.setGroupDetails(JsonGroupDetails("Full Group", "Full description"))
        obj.photoServerLabel = ByteArray(16) { it.toByte() }
        obj.photoServerKey = ByteArray(32) { (it * 3).toByte() }
        return obj
    }
}
