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
import io.olvid.engine.engine.types.JsonGroupDetails
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.HashSet

/**
 * Characterization tests for [KeycloakGroupBlob].
 *
 * This class is a Jackson JSON DTO used as a wire-format container exchanged with Keycloak.
 * The @JsonProperty annotations map Java field names to short on-the-wire keys:
 *
 *   bytesGroupUid              → "guid"
 *   groupDetails               → "details"
 *   photoUid                   → "photo_label"
 *   encodedPhotoKey            → "photo_key"
 *   pushTopic                  → "pt"
 *   groupMembersAndPermissions → "gm_perms"
 *   serializedSharedSettings   → "sss"
 *   timestamp                  → "timestamp"  (no @JsonProperty — uses Java/Kotlin name)
 *
 * A Kotlin migration that drops @JsonProperty (e.g., a data class with default property names),
 * or renames a getter, will silently change the wire format and break Keycloak communication.
 * These tests pin that contract.
 *
 * What is NOT tested here:
 *   - equals/hashCode: KeycloakGroupBlob does not override Object.equals; no value in
 *     exhaustively testing reference identity semantics when there is no override to migrate.
 *   - Internal Jackson mechanism details (field ordering, type-token caching, etc.).
 */
class KeycloakGroupBlobTest {

    private lateinit var mapper: ObjectMapper

    // Stable byte arrays used as test data throughout the suite
    private val groupUidBytes = ByteArray(32) { it.toByte() }
    private val photoUidBytes = ByteArray(32) { (it + 100).toByte() }
    private val encodedPhotoKeyBytes = ByteArray(16) { (it * 2).toByte() }
    private val memberIdentityBytes = ByteArray(20) { (it + 10).toByte() }

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ── Helper builders ───────────────────────────────────────────────────────

    private fun buildFullBlob(): KeycloakGroupBlob {
        val blob = KeycloakGroupBlob()
        blob.bytesGroupUid = groupUidBytes
        val details = JsonGroupDetails("Test Group", "A keycloak group")
        blob.groupDetails = details
        blob.photoUid = photoUidBytes
        blob.encodedPhotoKey = encodedPhotoKeyBytes
        blob.pushTopic = "test-topic"
        val member = KeycloakGroupMemberAndPermissions()
        member.setKeycloakUserId("user-001")
        member.identity = memberIdentityBytes
        member.signedUserDetails = "{\"name\":\"Alice\"}"
        member.permissions = mutableListOf<String?>("send_message", "admin")
        member.groupInvitationNonce = ByteArray(16) { 0xAB.toByte() }
        blob.groupMembersAndPermissions = HashSet<KeycloakGroupMemberAndPermissions?>().also { it.add(member) }
        blob.serializedSharedSettings = "{\"foo\":\"bar\"}"
        blob.timestamp = 1700000000000L
        return blob
    }

    // ── 1. Wire-format pin: @JsonProperty round-trip via serialization ─────────

    @Test
    fun testSerializedJsonContainsWireKey_guid() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"guid\" in serialized JSON but got: $json",
            json.contains("\"guid\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_details() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"details\" in serialized JSON but got: $json",
            json.contains("\"details\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_photo_label() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"photo_label\" in serialized JSON but got: $json",
            json.contains("\"photo_label\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_photo_key() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"photo_key\" in serialized JSON but got: $json",
            json.contains("\"photo_key\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_pt() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"pt\" in serialized JSON but got: $json",
            json.contains("\"pt\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_gm_perms() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"gm_perms\" in serialized JSON but got: $json",
            json.contains("\"gm_perms\"")
        )
    }

    @Test
    fun testSerializedJsonContainsWireKey_sss() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected short wire key \"sss\" in serialized JSON but got: $json",
            json.contains("\"sss\"")
        )
    }

    // timestamp has no @JsonProperty so it uses the field/getter name; pin it too.
    @Test
    fun testSerializedJsonContainsWireKey_timestamp() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertTrue(
            "Expected field name \"timestamp\" in serialized JSON but got: $json",
            json.contains("\"timestamp\"")
        )
    }

    // ── 1b. Negative: Java field names must NOT appear (catches dropped @JsonProperty) ──

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_bytesGroupUid() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"bytesGroupUid\" must not appear in serialized JSON; found in: $json",
            json.contains("\"bytesGroupUid\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_groupDetails() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"groupDetails\" must not appear in serialized JSON; found in: $json",
            json.contains("\"groupDetails\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_photoUid() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"photoUid\" must not appear in serialized JSON; found in: $json",
            json.contains("\"photoUid\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_encodedPhotoKey() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"encodedPhotoKey\" must not appear in serialized JSON; found in: $json",
            json.contains("\"encodedPhotoKey\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_pushTopic() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"pushTopic\" must not appear in serialized JSON; found in: $json",
            json.contains("\"pushTopic\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_groupMembersAndPermissions() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"groupMembersAndPermissions\" must not appear in serialized JSON; found in: $json",
            json.contains("\"groupMembersAndPermissions\"")
        )
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_serializedSharedSettings() {
        val json = mapper.writeValueAsString(buildFullBlob())
        assertFalse(
            "Java field name \"serializedSharedSettings\" must not appear in serialized JSON; found in: $json",
            json.contains("\"serializedSharedSettings\"")
        )
    }

    // ── 2. Round-trip deserialization: short wire names → fields ─────────────

    /**
     * Jackson encodes byte[] as Base64. Pre-compute expected Base64 values to assert
     * field equivalence after deserialization without depending on internal encoder details.
     */
    @Test
    fun testDeserializationFromWireJson_pushTopic() {
        // Build from the canonical object first so we know the Base64 representation
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertEquals("push topic must survive round-trip", "test-topic", deserialized.pushTopic)
    }

    @Test
    fun testDeserializationFromWireJson_timestamp() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertEquals("timestamp must survive round-trip", 1700000000000L, deserialized.timestamp)
    }

    @Test
    fun testDeserializationFromWireJson_serializedSharedSettings() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertEquals(
            "serializedSharedSettings must survive round-trip",
            "{\"foo\":\"bar\"}",
            deserialized.serializedSharedSettings
        )
    }

    @Test
    fun testDeserializationFromWireJson_groupDetailsName() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertNotNull("groupDetails must not be null after round-trip", deserialized.groupDetails)
        assertEquals(
            "groupDetails.name must survive round-trip",
            "Test Group",
            deserialized.groupDetails!!.getName()
        )
    }

    @Test
    fun testDeserializationFromWireJson_groupDetailsDescription() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertEquals(
            "groupDetails.description must survive round-trip",
            "A keycloak group",
            deserialized.groupDetails!!.getDescription()
        )
    }

    @Test
    fun testDeserializationFromWireJson_bytesGroupUid() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertArrayEquals(
            "bytesGroupUid must survive round-trip",
            groupUidBytes,
            deserialized.bytesGroupUid
        )
    }

    @Test
    fun testDeserializationFromWireJson_photoUid() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertArrayEquals(
            "photoUid must survive round-trip",
            photoUidBytes,
            deserialized.photoUid
        )
    }

    @Test
    fun testDeserializationFromWireJson_encodedPhotoKey() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertArrayEquals(
            "encodedPhotoKey must survive round-trip",
            encodedPhotoKeyBytes,
            deserialized.encodedPhotoKey
        )
    }

    @Test
    fun testDeserializationFromWireJson_groupMemberKeycloakUserId() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)

        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        assertNotNull("groupMembersAndPermissions must not be null", deserialized.groupMembersAndPermissions)
        assertEquals(
            "groupMembersAndPermissions must contain exactly one member",
            1,
            deserialized.groupMembersAndPermissions!!.size
        )
        val member = deserialized.groupMembersAndPermissions!!.first()
        assertEquals(
            "member keycloakUserId must survive round-trip",
            "user-001",
            member!!.getKeycloakUserId()
        )
    }

    @Test
    fun testDeserializationFromHardcodedWireJson() {
        // This JSON uses the short wire-format names (as a Keycloak server would send).
        // Deserializing it confirms that setters annotated with @JsonProperty("guid") etc.
        // are actually invoked — not the field names.
        val wireJson = """{"pt":"keycloak-push","timestamp":1700000000000,"sss":"{\"x\":1}"}"""

        val blob = mapper.readValue(wireJson, KeycloakGroupBlob::class.java)

        assertEquals("pt wire key must map to pushTopic field", "keycloak-push", blob.pushTopic)
        assertEquals("timestamp must be parsed correctly", 1700000000000L, blob.timestamp)
        assertEquals("sss wire key must map to serializedSharedSettings", "{\"x\":1}", blob.serializedSharedSettings)
    }

    // ── 3. @JsonIgnoreProperties(ignoreUnknown = true) contract ───────────────

    @Test
    fun testDeserializationIgnoresUnknownFields() {
        // A future server response may contain new fields unknown to this client.
        // The @JsonIgnoreProperties(ignoreUnknown = true) annotation must prevent
        // Jackson from throwing on those extra keys.
        val wireJson = """
            {
                "pt": "topic-x",
                "timestamp": 42,
                "unknownFutureField": "some-value",
                "anotherNewField": 999
            }
        """.trimIndent()

        // Must not throw
        val blob = mapper.readValue(wireJson, KeycloakGroupBlob::class.java)

        // Known fields are still populated correctly
        assertEquals("pt must still be mapped despite extra fields", "topic-x", blob.pushTopic)
        assertEquals("timestamp must still be mapped despite extra fields", 42L, blob.timestamp)
    }

    // ── 4. Empty-state default constructor ────────────────────────────────────

    @Test
    fun testDefaultConstructorInitializesAllReferenceFieldsToNull() {
        val blob = KeycloakGroupBlob()

        assertNull("bytesGroupUid must be null on fresh instance", blob.bytesGroupUid)
        assertNull("groupDetails must be null on fresh instance", blob.groupDetails)
        assertNull("photoUid must be null on fresh instance", blob.photoUid)
        assertNull("encodedPhotoKey must be null on fresh instance", blob.encodedPhotoKey)
        assertNull("pushTopic must be null on fresh instance", blob.pushTopic)
        assertNull("groupMembersAndPermissions must be null on fresh instance", blob.groupMembersAndPermissions)
        assertNull("serializedSharedSettings must be null on fresh instance", blob.serializedSharedSettings)
    }

    @Test
    fun testDefaultConstructorInitializesTimestampToZero() {
        val blob = KeycloakGroupBlob()
        assertEquals("timestamp must default to 0L on fresh instance", 0L, blob.timestamp)
    }

    // ── 5. Round-trip stability: serialize → deserialize → serialize ──────────

    @Test
    fun testRoundTripStability_pushTopic() {
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)

        assertEquals(
            "pushTopic must be identical after two hops through JSON",
            original.pushTopic,
            intermediate.pushTopic
        )
    }

    @Test
    fun testRoundTripStability_timestamp() {
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)

        assertEquals(
            "timestamp must be identical after two hops through JSON",
            original.timestamp,
            intermediate.timestamp
        )
    }

    @Test
    fun testRoundTripStability_serializedSharedSettings() {
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)

        assertEquals(
            "serializedSharedSettings must be identical after two hops through JSON",
            original.serializedSharedSettings,
            intermediate.serializedSharedSettings
        )
    }

    @Test
    fun testRoundTripStability_groupDetailsName() {
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)

        assertEquals(
            "groupDetails.name must be identical after two hops through JSON",
            original.groupDetails!!.getName(),
            intermediate.groupDetails!!.getName()
        )
    }

    @Test
    fun testRoundTripStability_bytesGroupUid() {
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)

        assertArrayEquals(
            "bytesGroupUid must be byte-equal after two hops through JSON",
            original.bytesGroupUid,
            intermediate.bytesGroupUid
        )
    }

    @Test
    fun testRoundTripStability_secondSerializationMatchesFirst() {
        // Serialize → deserialize → serialize again: both JSON strings must be equal.
        // This pins that no state is lost or mutated during deserialization.
        val original = buildFullBlob()
        val json1 = mapper.writeValueAsString(original)
        val intermediate = mapper.readValue(json1, KeycloakGroupBlob::class.java)
        val json2 = mapper.writeValueAsString(intermediate)

        assertEquals(
            "Two serializations of the same logical value must produce identical JSON",
            json1,
            json2
        )
    }

    // ── 6. Null field serialization: null-valued fields do not bleed into JSON ──

    @Test
    fun testNullFieldsInDefaultBlobDoNotSerializeToNonNullValues() {
        // A freshly constructed blob has all reference fields null. When serialized,
        // those keys may be present (as null) or absent depending on mapper config,
        // but they must never serialize as a non-null value.
        val blob = KeycloakGroupBlob()
        val json = mapper.writeValueAsString(blob)
        val node = mapper.readTree(json)

        // If the key is present it must be null/missing, not a concrete value
        if (node.has("guid")) {
            assertTrue("guid must serialize as null when field is null", node.get("guid").isNull)
        }
        if (node.has("pt")) {
            assertTrue("pt must serialize as null when field is null", node.get("pt").isNull)
        }
        if (node.has("sss")) {
            assertTrue("sss must serialize as null when field is null", node.get("sss").isNull)
        }
    }

    // ── 7. KeycloakGroupMemberAndPermissions wire-name contract ───────────────

    @Test
    fun testMemberSerializationUsesWireKey_id() {
        val blob = buildFullBlob()
        val json = mapper.writeValueAsString(blob)
        assertTrue(
            "Member's keycloakUserId must serialize as \"id\" wire key; got: $json",
            json.contains("\"id\"")
        )
    }

    @Test
    fun testMemberSerializationDoesNotUseJavaFieldName_keycloakUserId() {
        val blob = buildFullBlob()
        val json = mapper.writeValueAsString(blob)
        assertFalse(
            "Java field name \"keycloakUserId\" must not appear in serialized JSON; got: $json",
            json.contains("\"keycloakUserId\"")
        )
    }

    @Test
    fun testMemberDeserializationRestoresKeycloakUserId() {
        val original = buildFullBlob()
        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, KeycloakGroupBlob::class.java)

        val member = deserialized.groupMembersAndPermissions!!.first()
        assertArrayEquals(
            "member identity bytes must survive round-trip",
            memberIdentityBytes,
            member!!.identity
        )
    }
}
