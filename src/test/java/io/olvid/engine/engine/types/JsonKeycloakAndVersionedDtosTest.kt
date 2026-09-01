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
 * Characterization tests for three Jackson DTOs used in Keycloak-facing wire formats:
 *
 *   JsonKeycloakUserDetails — user identity payload from Keycloak; firstName/lastName
 *     use hyphenated wire names ("first-name", "last-name"); other fields use Java names.
 *
 *   JsonKeycloakRevocation — revocation record; ALL three Java field names are renamed:
 *     bytesRevokedIdentity → "identity", revocationTimestamp → "timestamp",
 *     revocationType → "type".
 *
 *   JsonIdentityDetailsWithVersionAndPhoto — version + photo wrapper around JsonIdentityDetails;
 *     identityDetails → "details", photoServerLabel → "photo_label", photoServerKey → "photo_key";
 *     photoUrl is @JsonIgnore (never serialized); version uses its Java name "version".
 *
 * None of the three DTOs override equals/hashCode, so equality is reference identity throughout.
 */
class JsonKeycloakAndVersionedDtosTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonKeycloakUserDetails
    // ═══════════════════════════════════════════════════════════════════════════

    private val sampleIdentityBytes = ByteArray(16) { it.toByte() }

    private fun buildFullUserDetails(): JsonKeycloakUserDetails {
        val d = JsonKeycloakUserDetails()
        d.id = "user-123"
        d.identity = sampleIdentityBytes
        d.firstName = "Alice"
        d.lastName = "Smith"
        d.position = "Engineer"
        d.company = "Olvid SAS"
        d.timestamp = 1700000000000L
        return d
    }

    // ─── Wire-format pin: @JsonProperty produces hyphenated keys ──────────────

    @Test
    fun userDetails_serializes_firstName_as_first_name() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertTrue(
            "firstName must serialize as \"first-name\" but got: $json",
            json.contains("\"first-name\"")
        )
    }

    @Test
    fun userDetails_serializes_lastName_as_last_name() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertTrue(
            "lastName must serialize as \"last-name\" but got: $json",
            json.contains("\"last-name\"")
        )
    }

    @Test
    fun userDetails_does_not_serialize_java_name_firstName() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertFalse(
            "Java field name \"firstName\" must not appear in JSON; got: $json",
            json.contains("\"firstName\"")
        )
    }

    @Test
    fun userDetails_does_not_serialize_java_name_lastName() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertFalse(
            "Java field name \"lastName\" must not appear in JSON; got: $json",
            json.contains("\"lastName\"")
        )
    }

    // ─── Fields without @JsonProperty use their Java field names ──────────────

    @Test
    fun userDetails_fields_without_annotation_use_java_names() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertTrue("\"id\" must appear as wire key; got: $json", json.contains("\"id\""))
        assertTrue("\"identity\" must appear as wire key; got: $json", json.contains("\"identity\""))
        assertTrue("\"position\" must appear as wire key; got: $json", json.contains("\"position\""))
        assertTrue("\"company\" must appear as wire key; got: $json", json.contains("\"company\""))
        assertTrue("\"timestamp\" must appear as wire key; got: $json", json.contains("\"timestamp\""))
    }

    // ─── Deserialization from hand-built wire JSON with hyphenated keys ────────

    @Test
    fun userDetails_deserializes_first_name_from_hyphenated_wire_key() {
        val wireJson = """{"first-name":"Bob","last-name":"Jones","position":"CTO","company":"ACME","timestamp":42}"""
        val d = mapper.readValue(wireJson, JsonKeycloakUserDetails::class.java)
        assertEquals("first-name wire key must map to firstName field", "Bob", d.firstName)
    }

    @Test
    fun userDetails_deserializes_last_name_from_hyphenated_wire_key() {
        val wireJson = """{"first-name":"Bob","last-name":"Jones","position":"CTO","company":"ACME","timestamp":42}"""
        val d = mapper.readValue(wireJson, JsonKeycloakUserDetails::class.java)
        assertEquals("last-name wire key must map to lastName field", "Jones", d.lastName)
    }

    @Test
    fun userDetails_deserializes_remaining_fields_from_wire_json() {
        val wireJson = """{"first-name":"Bob","last-name":"Jones","position":"CTO","company":"ACME","timestamp":9999}"""
        val d = mapper.readValue(wireJson, JsonKeycloakUserDetails::class.java)
        assertEquals("CTO", d.position)
        assertEquals("ACME", d.company)
        assertEquals(9999L, d.timestamp)
    }

    // ─── @JsonIgnoreProperties(ignoreUnknown = true) ──────────────────────────

    @Test
    fun userDetails_ignores_unknown_fields_during_deserialization() {
        val wireJson = """{"first-name":"Alice","last-name":"Smith","unknownField":"surprise","newFeature":42}"""
        // Must not throw
        val d = mapper.readValue(wireJson, JsonKeycloakUserDetails::class.java)
        assertEquals("known fields still populated despite unknown keys", "Alice", d.firstName)
        assertEquals("Smith", d.lastName)
    }

    // ─── Default no-arg constructor ────────────────────────────────────────────

    @Test
    fun userDetails_defaultConstructor_allNullFields() {
        val d = JsonKeycloakUserDetails()
        assertNull(d.id)
        assertNull(d.identity)
        assertNull(d.firstName)
        assertNull(d.lastName)
        assertNull(d.position)
        assertNull(d.company)
        assertNull(d.timestamp)
    }

    // ─── Setters / getters delegate correctly ─────────────────────────────────

    @Test
    fun userDetails_setters_store_values_retrievable_via_getters() {
        val d = JsonKeycloakUserDetails()
        val idBytes = byteArrayOf(1, 2, 3)
        d.id = "abc"
        d.identity = idBytes
        d.firstName = "Charlie"
        d.lastName = "Brown"
        d.position = "Dev"
        d.company = "Corp"
        d.timestamp = 12345L

        assertEquals("abc", d.id)
        assertArrayEquals(idBytes, d.identity)
        assertEquals("Charlie", d.firstName)
        assertEquals("Brown", d.lastName)
        assertEquals("Dev", d.position)
        assertEquals("Corp", d.company)
        assertEquals(12345L, d.timestamp)
    }

    // ─── @JsonIgnore getIdentityDetails() is excluded from JSON ───────────────

    @Test
    fun userDetails_getIdentityDetails_is_not_serialized() {
        val json = mapper.writeValueAsString(buildFullUserDetails())
        assertFalse(
            "getIdentityDetails() is @JsonIgnore so 'identityDetails' must not appear in JSON; got: $json",
            json.contains("\"identityDetails\"")
        )
    }

    @Test
    fun userDetails_getIdentityDetails_returns_firstName_and_lastName() {
        val d = buildFullUserDetails()
        val details = d.getIdentityDetails(null)
        assertNotNull(details)
        assertEquals("Alice", details.firstName)
        assertEquals("Smith", details.lastName)
        assertEquals("Engineer", details.position)
        assertEquals("Olvid SAS", details.company)
        assertNull("no signedUserDetails when null passed", details.signedUserDetails)
    }

    @Test
    fun userDetails_getIdentityDetails_propagates_signedUserDetails_when_provided() {
        val d = buildFullUserDetails()
        val details = d.getIdentityDetails("signed.jwt.token")
        assertEquals("signed.jwt.token", details.signedUserDetails)
    }

    // ─── Reference identity (no equals override) ──────────────────────────────

    @Test
    fun userDetails_equalityIsReferenceIdentity_differentInstances() {
        val d1 = buildFullUserDetails()
        val d2 = buildFullUserDetails()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("two different instances must not be equal even with same fields", d1.equals(d2))
    }

    @Test
    fun userDetails_equalityIsReferenceIdentity_sameInstance() {
        val d = buildFullUserDetails()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("instance must equal itself", d.equals(d))
    }

    @Test
    fun userDetails_hashCode_stableAcrossCalls() {
        val d = buildFullUserDetails()
        assertEquals("hashCode must be stable across multiple calls", d.hashCode(), d.hashCode())
    }

    // ─── Round-trip stability ─────────────────────────────────────────────────

    @Test
    fun userDetails_roundTrip_fieldEquivalence() {
        val original = buildFullUserDetails()
        val json1 = mapper.writeValueAsString(original)
        val hop1 = mapper.readValue(json1, JsonKeycloakUserDetails::class.java)
        val json2 = mapper.writeValueAsString(hop1)
        val hop2 = mapper.readValue(json2, JsonKeycloakUserDetails::class.java)

        assertEquals("firstName stable after two round-trips", "Alice", hop2.firstName)
        assertEquals("lastName stable after two round-trips", "Smith", hop2.lastName)
        assertEquals("position stable after two round-trips", "Engineer", hop2.position)
        assertEquals("company stable after two round-trips", "Olvid SAS", hop2.company)
        assertEquals("timestamp stable after two round-trips", 1700000000000L, hop2.timestamp)
        assertArrayEquals("identity bytes stable after two round-trips", sampleIdentityBytes, hop2.identity)
    }

    @Test
    fun userDetails_serialization_idempotent_json_string() {
        val original = buildFullUserDetails()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, JsonKeycloakUserDetails::class.java)
        val json2 = mapper.writeValueAsString(intermediate)
        assertEquals("serialize→deserialize→serialize must produce identical JSON", json1, json2)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonKeycloakRevocation
    // ═══════════════════════════════════════════════════════════════════════════

    private val sampleRevokedIdentity = ByteArray(20) { (it + 50).toByte() }

    private fun buildFullRevocation(): JsonKeycloakRevocation {
        val r = JsonKeycloakRevocation()
        r.bytesRevokedIdentity = sampleRevokedIdentity
        r.revocationTimestamp = 1700000000000L
        r.revocationType = 2
        return r
    }

    // ─── Wire-format pin: ALL fields are renamed via @JsonProperty ─────────────

    @Test
    fun revocation_serializes_bytesRevokedIdentity_as_identity() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertTrue(
            "bytesRevokedIdentity must serialize as \"identity\"; got: $json",
            json.contains("\"identity\"")
        )
    }

    @Test
    fun revocation_does_not_serialize_java_name_bytesRevokedIdentity() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertFalse(
            "Java field name \"bytesRevokedIdentity\" must not appear in JSON; got: $json",
            json.contains("\"bytesRevokedIdentity\"")
        )
    }

    @Test
    fun revocation_serializes_revocationTimestamp_as_timestamp() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertTrue(
            "revocationTimestamp must serialize as \"timestamp\"; got: $json",
            json.contains("\"timestamp\"")
        )
    }

    @Test
    fun revocation_does_not_serialize_java_name_revocationTimestamp() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertFalse(
            "Java field name \"revocationTimestamp\" must not appear in JSON; got: $json",
            json.contains("\"revocationTimestamp\"")
        )
    }

    @Test
    fun revocation_serializes_revocationType_as_type() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertTrue(
            "revocationType must serialize as \"type\"; got: $json",
            json.contains("\"type\"")
        )
    }

    @Test
    fun revocation_does_not_serialize_java_name_revocationType() {
        val json = mapper.writeValueAsString(buildFullRevocation())
        assertFalse(
            "Java field name \"revocationType\" must not appear in JSON; got: $json",
            json.contains("\"revocationType\"")
        )
    }

    // ─── Deserialization from hand-built wire JSON ─────────────────────────────

    @Test
    fun revocation_deserializes_all_fields_from_wire_json() {
        // "identity" → bytesRevokedIdentity, "timestamp" → revocationTimestamp, "type" → revocationType
        val wireJson = """{"identity":"AQID","timestamp":1234567890,"type":1}"""
        val r = mapper.readValue(wireJson, JsonKeycloakRevocation::class.java)
        assertNotNull("bytesRevokedIdentity must be populated from wire key 'identity'", r.bytesRevokedIdentity)
        assertEquals("revocationTimestamp must be populated from wire key 'timestamp'", 1234567890L, r.revocationTimestamp)
        assertEquals("revocationType must be populated from wire key 'type'", 1, r.revocationType)
    }

    // ─── @JsonIgnoreProperties(ignoreUnknown = true) ──────────────────────────

    @Test
    fun revocation_ignores_unknown_fields_during_deserialization() {
        val wireJson = """{"identity":"AQID","timestamp":99,"type":0,"unknownFuture":"value"}"""
        // Must not throw
        val r = mapper.readValue(wireJson, JsonKeycloakRevocation::class.java)
        assertEquals("known fields still populated", 99L, r.revocationTimestamp)
        assertEquals(0, r.revocationType)
    }

    // ─── Default no-arg constructor ────────────────────────────────────────────

    @Test
    fun revocation_defaultConstructor_nullIdentityAndZeroPrimitives() {
        val r = JsonKeycloakRevocation()
        assertNull("bytesRevokedIdentity must be null on fresh instance", r.bytesRevokedIdentity)
        assertEquals("revocationTimestamp must default to 0L", 0L, r.revocationTimestamp)
        assertEquals("revocationType must default to 0", 0, r.revocationType)
    }

    // ─── Setters / getters delegate correctly ─────────────────────────────────

    @Test
    fun revocation_setters_store_values_retrievable_via_getters() {
        val r = JsonKeycloakRevocation()
        val idBytes = byteArrayOf(10, 20, 30)
        r.bytesRevokedIdentity = idBytes
        r.revocationTimestamp = 5555555555L
        r.revocationType = 3

        assertArrayEquals(idBytes, r.bytesRevokedIdentity)
        assertEquals(5555555555L, r.revocationTimestamp)
        assertEquals(3, r.revocationType)
    }

    // ─── Reference identity (no equals override) ──────────────────────────────

    @Test
    fun revocation_equalityIsReferenceIdentity_differentInstances() {
        val r1 = buildFullRevocation()
        val r2 = buildFullRevocation()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("two different instances with same fields must not be equal", r1.equals(r2))
    }

    @Test
    fun revocation_equalityIsReferenceIdentity_sameInstance() {
        val r = buildFullRevocation()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("instance must equal itself", r.equals(r))
    }

    @Test
    fun revocation_hashCode_stableAcrossCalls() {
        val r = buildFullRevocation()
        assertEquals(r.hashCode(), r.hashCode())
    }

    // ─── Round-trip stability ─────────────────────────────────────────────────

    @Test
    fun revocation_roundTrip_allFieldsPreserved() {
        val original = buildFullRevocation()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonKeycloakRevocation::class.java)

        assertArrayEquals(sampleRevokedIdentity, deserialized.bytesRevokedIdentity)
        assertEquals(1700000000000L, deserialized.revocationTimestamp)
        assertEquals(2, deserialized.revocationType)
    }

    @Test
    fun revocation_serialization_idempotent_json_string() {
        val original = buildFullRevocation()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, JsonKeycloakRevocation::class.java)
        val json2 = mapper.writeValueAsString(intermediate)
        assertEquals("serialize→deserialize→serialize must produce identical JSON", json1, json2)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // JsonIdentityDetailsWithVersionAndPhoto
    // ═══════════════════════════════════════════════════════════════════════════

    private val samplePhotoLabel = ByteArray(32) { (it + 1).toByte() }
    private val samplePhotoKey = ByteArray(16) { (it * 3).toByte() }

    private fun buildFullVersionedDetails(): JsonIdentityDetailsWithVersionAndPhoto {
        val w = JsonIdentityDetailsWithVersionAndPhoto()
        w.version = 7
        val inner = JsonIdentityDetails()
        inner.firstName = "Dana"
        inner.lastName = "Lee"
        inner.company = "Olvid"
        inner.position = "PM"
        w.identityDetails = inner
        w.photoServerLabel = samplePhotoLabel
        w.photoServerKey = samplePhotoKey
        w.photoUrl = "https://example.com/photo.jpg"
        return w
    }

    // ─── Wire-format pin: renamed fields ──────────────────────────────────────

    @Test
    fun versioned_serializes_identityDetails_as_details() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "identityDetails must serialize as \"details\"; got: $json",
            json.contains("\"details\"")
        )
    }

    @Test
    fun versioned_does_not_serialize_java_name_identityDetails() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertFalse(
            "Java field name \"identityDetails\" must not appear in JSON; got: $json",
            json.contains("\"identityDetails\"")
        )
    }

    @Test
    fun versioned_serializes_photoServerLabel_as_photo_label() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "photoServerLabel must serialize as \"photo_label\"; got: $json",
            json.contains("\"photo_label\"")
        )
    }

    @Test
    fun versioned_does_not_serialize_java_name_photoServerLabel() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertFalse(
            "Java field name \"photoServerLabel\" must not appear in JSON; got: $json",
            json.contains("\"photoServerLabel\"")
        )
    }

    @Test
    fun versioned_serializes_photoServerKey_as_photo_key() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "photoServerKey must serialize as \"photo_key\"; got: $json",
            json.contains("\"photo_key\"")
        )
    }

    @Test
    fun versioned_does_not_serialize_java_name_photoServerKey() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertFalse(
            "Java field name \"photoServerKey\" must not appear in JSON; got: $json",
            json.contains("\"photoServerKey\"")
        )
    }

    // ─── version field uses Java name "version" (no @JsonProperty) ────────────

    @Test
    fun versioned_serializes_version_using_java_field_name() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "version field must appear as \"version\" in JSON; got: $json",
            json.contains("\"version\"")
        )
    }

    // ─── photoUrl is @JsonIgnore — never appears in serialized JSON ─────────────

    @Test
    fun versioned_photoUrl_is_not_serialized() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertFalse(
            "photoUrl is @JsonIgnore and must NOT appear in JSON; got: $json",
            json.contains("\"photoUrl\"")
        )
        assertFalse(
            "photoUrl value 'photo.jpg' must not leak into JSON; got: $json",
            json.contains("photo.jpg")
        )
    }

    @Test
    fun versioned_photoUrl_is_not_deserialized_from_json() {
        // Even if a JSON payload includes "photoUrl", it should be ignored
        val wireJson = """{"version":3,"details":{"first_name":"X"},"photoUrl":"https://hacker.example/img.png"}"""
        val w = mapper.readValue(wireJson, JsonIdentityDetailsWithVersionAndPhoto::class.java)
        assertNull("photoUrl must remain null even when present in JSON (it is @JsonIgnore)", w.photoUrl)
    }

    // ─── @JsonIgnoreProperties(ignoreUnknown = true) ──────────────────────────

    @Test
    fun versioned_ignores_unknown_fields_during_deserialization() {
        val wireJson = """{"version":5,"details":{"first_name":"Eve"},"unknownKey":"value","future_flag":true}"""
        // Must not throw
        val w = mapper.readValue(wireJson, JsonIdentityDetailsWithVersionAndPhoto::class.java)
        assertEquals("known version field still populated despite unknowns", 5, w.version)
        assertNotNull(w.identityDetails)
    }

    // ─── Default no-arg constructor ────────────────────────────────────────────

    @Test
    fun versioned_defaultConstructor_zeroVersionAndNullFields() {
        val w = JsonIdentityDetailsWithVersionAndPhoto()
        assertEquals("version must default to 0", 0, w.version)
        assertNull("identityDetails must be null on fresh instance", w.identityDetails)
        assertNull("photoServerLabel must be null on fresh instance", w.photoServerLabel)
        assertNull("photoServerKey must be null on fresh instance", w.photoServerKey)
        assertNull("photoUrl must be null on fresh instance", w.photoUrl)
    }

    // ─── Setters / getters delegate correctly ─────────────────────────────────

    @Test
    fun versioned_setters_store_values_retrievable_via_getters() {
        val w = JsonIdentityDetailsWithVersionAndPhoto()
        val inner = JsonIdentityDetails()
        inner.firstName = "Zara"
        val label = byteArrayOf(11, 22)
        val key = byteArrayOf(33, 44)

        w.version = 3
        w.identityDetails = inner
        w.photoServerLabel = label
        w.photoServerKey = key
        w.photoUrl = "local://path/photo.png"

        assertEquals(3, w.version)
        assertNotNull(w.identityDetails)
        assertEquals("Zara", w.identityDetails!!.firstName)
        assertArrayEquals(label, w.photoServerLabel)
        assertArrayEquals(key, w.photoServerKey)
        assertEquals("local://path/photo.png", w.photoUrl)
    }

    // ─── Inner JsonIdentityDetails serializes with its own @JsonProperty names ──

    @Test
    fun versioned_innerDetails_firstName_serializes_as_first_name() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "inner JsonIdentityDetails firstName must serialize as \"first_name\" (underscore); got: $json",
            json.contains("\"first_name\"")
        )
    }

    @Test
    fun versioned_innerDetails_lastName_serializes_as_last_name() {
        val json = mapper.writeValueAsString(buildFullVersionedDetails())
        assertTrue(
            "inner JsonIdentityDetails lastName must serialize as \"last_name\" (underscore); got: $json",
            json.contains("\"last_name\"")
        )
    }

    // ─── Reference identity (no equals override) ──────────────────────────────

    @Test
    fun versioned_equalityIsReferenceIdentity_differentInstances() {
        val w1 = buildFullVersionedDetails()
        val w2 = buildFullVersionedDetails()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("two different instances with same fields must not be equal", w1.equals(w2))
    }

    @Test
    fun versioned_equalityIsReferenceIdentity_sameInstance() {
        val w = buildFullVersionedDetails()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("instance must equal itself", w.equals(w))
    }

    @Test
    fun versioned_hashCode_stableAcrossCalls() {
        val w = buildFullVersionedDetails()
        assertEquals(w.hashCode(), w.hashCode())
    }

    // ─── Round-trip stability ─────────────────────────────────────────────────

    @Test
    fun versioned_roundTrip_allFieldsPreserved() {
        val original = buildFullVersionedDetails()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonIdentityDetailsWithVersionAndPhoto::class.java)

        assertEquals("version must survive round-trip", 7, deserialized.version)
        assertNotNull("identityDetails must survive round-trip", deserialized.identityDetails)
        assertEquals("Dana", deserialized.identityDetails!!.firstName)
        assertEquals("Lee", deserialized.identityDetails!!.lastName)
        assertEquals("Olvid", deserialized.identityDetails!!.company)
        assertEquals("PM", deserialized.identityDetails!!.position)
        assertArrayEquals("photoServerLabel must survive round-trip", samplePhotoLabel, deserialized.photoServerLabel)
        assertArrayEquals("photoServerKey must survive round-trip", samplePhotoKey, deserialized.photoServerKey)
        // photoUrl is @JsonIgnore — it must NOT have been restored from JSON
        assertNull("photoUrl must be null after round-trip (it is @JsonIgnore)", deserialized.photoUrl)
    }

    @Test
    fun versioned_serialization_idempotent_json_string() {
        val original = buildFullVersionedDetails()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, JsonIdentityDetailsWithVersionAndPhoto::class.java)
        val json2 = mapper.writeValueAsString(intermediate)
        assertEquals("serialize→deserialize→serialize must produce identical JSON", json1, json2)
    }

    @Test
    fun versioned_deserialization_from_hardcoded_wire_json() {
        // Uses all short wire keys exactly as a server would send them.
        val wireJson = """{"version":2,"details":{"first_name":"Nora","last_name":"Vance","company":"TestCo","position":"VP"},"photo_label":null,"photo_key":null}"""
        val w = mapper.readValue(wireJson, JsonIdentityDetailsWithVersionAndPhoto::class.java)

        assertEquals(2, w.version)
        assertNotNull(w.identityDetails)
        assertEquals("Nora", w.identityDetails!!.firstName)
        assertEquals("Vance", w.identityDetails!!.lastName)
        assertEquals("TestCo", w.identityDetails!!.company)
        assertEquals("VP", w.identityDetails!!.position)
    }
}
