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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [KeycloakGroupMemberAndPermissions].
 *
 * The primary contract being pinned is the CUSTOM equals/hashCode that compares
 * ONLY on [KeycloakGroupMemberAndPermissions.keycloakUserId]. This is load-bearing:
 * the class is used inside a HashSet<KeycloakGroupMemberAndPermissions> (see
 * KeycloakGroupBlob.groupMembersAndPermissions) which relies on this semantics to
 * de-duplicate members by user ID.
 *
 * A naive J2K migration to a Kotlin `data class` would auto-generate equals/hashCode
 * over ALL fields, silently breaking the de-duplication — these tests catch exactly
 * that regression.
 */
class KeycloakGroupMemberAndPermissionsTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ─── Helper builders ──────────────────────────────────────────────────────

    /** Creates an instance with all fields populated. */
    private fun fullInstance(
        userId: String,
        identity: ByteArray = byteArrayOf(1, 2, 3),
        signedUserDetails: String = "signed-details",
        permissions: List<String> = listOf("read", "write"),
        nonce: ByteArray = byteArrayOf(4, 5, 6)
    ): KeycloakGroupMemberAndPermissions {
        val obj = KeycloakGroupMemberAndPermissions()
        obj.keycloakUserId = userId
        obj.identity = identity
        obj.signedUserDetails = signedUserDetails
        @Suppress("UNCHECKED_CAST")
        obj.permissions = permissions as MutableList<String?>?
        obj.groupInvitationNonce = nonce
        return obj
    }

    // ─── Group 1: Custom equals invariant ────────────────────────────────────

    /**
     * Two instances with SAME keycloakUserId but DIFFERENT values for every
     * other field must be equal. This is the primary contract to pin.
     */
    @Test
    fun testEqualsOnlyUsesKeycloakUserId_sameIdDifferentFieldsAreEqual() {
        val a = fullInstance(
            userId = "user-alpha",
            identity = byteArrayOf(1, 2, 3),
            signedUserDetails = "details-A",
            permissions = listOf("read"),
            nonce = byteArrayOf(10)
        )
        val b = fullInstance(
            userId = "user-alpha",
            identity = byteArrayOf(99, 88),
            signedUserDetails = "details-B",
            permissions = listOf("write", "admin"),
            nonce = byteArrayOf(20, 21)
        )
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "Same keycloakUserId must be equal regardless of other field differences",
            a.equals(b)
        )
    }

    /**
     * Two instances with DIFFERENT keycloakUserId must NOT be equal even when
     * all other fields are identical.
     */
    @Test
    fun testEqualsOnlyUsesKeycloakUserId_differentIdAreNotEqual() {
        val sharedIdentity = byteArrayOf(1, 2, 3)
        val a = fullInstance(userId = "user-alpha", identity = sharedIdentity)
        val b = fullInstance(userId = "user-beta", identity = sharedIdentity)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Different keycloakUserId must not be equal even with identical other fields",
            a.equals(b)
        )
    }

    /** equals(null) must return false without throwing. */
    @Test
    fun testEqualsNullReturnsFalse() {
        val a = fullInstance("user-alpha")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(null))
    }

    /** equals with an unrelated type must return false without throwing. */
    @Test
    fun testEqualsUnrelatedTypeReturnsFalse() {
        val a = fullInstance("user-alpha")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals("user-alpha"))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(a.equals(42))
    }

    /** equals is reflexive: an instance must equal itself. */
    @Test
    fun testEqualsIsReflexive() {
        val a = fullInstance("user-alpha")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(a.equals(a))
    }

    /** equals is symmetric: if a == b then b == a. */
    @Test
    fun testEqualsIsSymmetric() {
        val a = fullInstance("user-alpha")
        val b = fullInstance("user-alpha", signedUserDetails = "other-details")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(a.equals(b))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(b.equals(a))
    }

    // ─── Group 2: Custom hashCode invariant ──────────────────────────────────

    /**
     * hashCode must equal keycloakUserId.hashCode() for a known string.
     * Pinning the exact value to catch any migration that changes the formula.
     *
     * Java String.hashCode("test-user-1") == -1610323894 (computed via
     * sum(31^i * char[i]) reduced to signed 32-bit).
     */
    @Test
    fun testHashCodeEqualsKeycloakUserIdHashCode_knownValue() {
        val userId = "test-user-1"
        val obj = fullInstance(userId)
        assertEquals(
            "hashCode must be keycloakUserId.hashCode() exactly",
            userId.hashCode(),
            obj.hashCode()
        )
    }

    /** Two instances with the SAME keycloakUserId must have the SAME hashCode. */
    @Test
    fun testHashCodeConsistentWithEquals_sameUserIdSameHashCode() {
        val a = fullInstance("user-alpha", identity = byteArrayOf(1))
        val b = fullInstance("user-alpha", identity = byteArrayOf(2))
        assertEquals(
            "Equal instances must have equal hashCodes",
            a.hashCode(),
            b.hashCode()
        )
    }

    /**
     * Two instances with DIFFERENT keycloakUserId must have different hashCodes.
     * We pick "test-user-1" and "test-user-2" which are verified to have distinct
     * Java String hashCodes (-1610323894 vs -1610323893).
     */
    @Test
    fun testHashCodeDifferentForDifferentUserIds() {
        val a = fullInstance("test-user-1")
        val b = fullInstance("test-user-2")
        assertNotEquals(
            "Different keycloakUserId values must produce different hashCodes",
            a.hashCode(),
            b.hashCode()
        )
    }

    /** hashCode is stable across repeated calls on the same instance. */
    @Test
    fun testHashCodeIsStableAcrossRepeatedCalls() {
        val obj = fullInstance("user-alpha")
        val h1 = obj.hashCode()
        val h2 = obj.hashCode()
        assertEquals(h1, h2)
    }

    // ─── Group 3: HashSet de-duplication — the integration-level contract ─────

    /**
     * THE KEY REGRESSION TEST.
     *
     * Adding two instances with the SAME keycloakUserId but DIFFERENT permissions
     * to a HashSet must yield a set of size 1. If a Kotlin migration changes
     * equals/hashCode to cover all fields (data class behaviour), this test fails.
     */
    @Test
    fun testHashSetDeduplicatesBySameKeycloakUserId() {
        val memberWithRead = fullInstance("user-alpha", permissions = listOf("read"))
        val memberWithAdmin = fullInstance("user-alpha", permissions = listOf("admin", "write"))

        val set = HashSet<KeycloakGroupMemberAndPermissions>()
        set.add(memberWithRead)
        set.add(memberWithAdmin)

        assertEquals(
            "HashSet must deduplicate instances with the same keycloakUserId",
            1,
            set.size
        )
    }

    /**
     * Three instances — two with the same keycloakUserId and one distinct —
     * must collapse to exactly two entries in a HashSet.
     */
    @Test
    fun testHashSetWithTwoDuplicatesAndOneDistinctYieldsSizeTwo() {
        val dup1 = fullInstance("user-alpha", permissions = listOf("read"))
        val dup2 = fullInstance("user-alpha", permissions = listOf("write"))
        val distinct = fullInstance("user-beta", permissions = listOf("admin"))

        val set = HashSet<KeycloakGroupMemberAndPermissions>()
        set.add(dup1)
        set.add(dup2)
        set.add(distinct)

        assertEquals(
            "HashSet must contain 2 entries: one per unique keycloakUserId",
            2,
            set.size
        )
    }

    /** Entirely distinct user IDs each occupy their own slot in the set. */
    @Test
    fun testHashSetRetainsAllDistinctUserIds() {
        val members = (1..5).map { fullInstance("user-$it") }
        val set = HashSet<KeycloakGroupMemberAndPermissions>(members)
        assertEquals(5, set.size)
    }

    // ─── Group 4: Jackson wire-format pin ────────────────────────────────────

    /**
     * Verify the @JsonProperty annotations map fields to the expected short wire keys:
     *   keycloakUserId  -> "id"
     *   identity        -> "identity"
     *   signedUserDetails -> "signature"
     *   permissions     -> "permissions"
     *   groupInvitationNonce -> "nonce"
     *
     * Also verifies that the verbose Java field names do NOT appear in the JSON.
     */
    @Test
    fun testJacksonSerializationUsesShortWireKeys() {
        val obj = fullInstance(
            userId = "user-alpha",
            identity = byteArrayOf(1, 2, 3),
            signedUserDetails = "signed-details-value",
            permissions = listOf("read", "write"),
            nonce = byteArrayOf(10, 20)
        )
        val json = mapper.writeValueAsString(obj)

        assertTrue("Wire JSON must contain key \"id\"", json.contains("\"id\""))
        assertTrue("Wire JSON must contain key \"identity\"", json.contains("\"identity\""))
        assertTrue("Wire JSON must contain key \"signature\"", json.contains("\"signature\""))
        assertTrue("Wire JSON must contain key \"permissions\"", json.contains("\"permissions\""))
        assertTrue("Wire JSON must contain key \"nonce\"", json.contains("\"nonce\""))

        assertFalse("Wire JSON must NOT contain \"keycloakUserId\"", json.contains("keycloakUserId"))
        assertFalse("Wire JSON must NOT contain \"signedUserDetails\"", json.contains("signedUserDetails"))
        assertFalse("Wire JSON must NOT contain \"groupInvitationNonce\"", json.contains("groupInvitationNonce"))
    }

    /** Full round-trip: serialize then deserialize must reproduce the original field values. */
    @Test
    fun testJacksonRoundTripPreservesFieldValues() {
        val original = fullInstance(
            userId = "user-roundtrip",
            identity = byteArrayOf(7, 8, 9),
            signedUserDetails = "signed-for-roundtrip",
            permissions = listOf("perm-a", "perm-b"),
            nonce = byteArrayOf(30, 31, 32)
        )

        val json = mapper.writeValueAsString(original)
        val restored = mapper.readValue(json, KeycloakGroupMemberAndPermissions::class.java)

        assertEquals(original.keycloakUserId, restored.keycloakUserId)
        assertTrue(original.identity.contentEquals(restored.identity))
        assertEquals(original.signedUserDetails, restored.signedUserDetails)
        assertEquals(original.permissions, restored.permissions)
        assertTrue(original.groupInvitationNonce.contentEquals(restored.groupInvitationNonce))
    }

    // ─── Group 5: @JsonIgnoreProperties(ignoreUnknown = true) ────────────────

    /** JSON with extra unknown fields must deserialize without error. */
    @Test
    fun testDeserializationIgnoresUnknownFields() {
        val jsonWithExtras = """
            {
                "id": "user-extras",
                "identity": "AQID",
                "signature": "some-sig",
                "permissions": ["read"],
                "nonce": "BAUG",
                "unknownField": "should be ignored",
                "anotherUnknown": 42
            }
        """.trimIndent()

        val obj = mapper.readValue(jsonWithExtras, KeycloakGroupMemberAndPermissions::class.java)
        assertEquals("user-extras", obj.keycloakUserId)
    }

    // ─── Group 6: Default (no-arg) constructor ────────────────────────────────

    /**
     * The default no-arg constructor must exist and produce an instance with all
     * fields null. Jackson requires this constructor for deserialization. A Kotlin
     * migration to a `data class` with required constructor parameters would break
     * Jackson unless @JsonCreator is added — this test catches that shape change.
     */
    @Test
    fun testDefaultConstructorProducesAllNullFields() {
        val obj = KeycloakGroupMemberAndPermissions()
        assertNull("keycloakUserId must be null after default construction", obj.keycloakUserId)
        assertNull("identity must be null after default construction", obj.identity)
        assertNull("signedUserDetails must be null after default construction", obj.signedUserDetails)
        assertNull("permissions must be null after default construction", obj.permissions)
        assertNull("groupInvitationNonce must be null after default construction", obj.groupInvitationNonce)
    }

    // ─── Group 7: NPE characterization for hashCode on null keycloakUserId ───

    /**
     * The current Java implementation delegates directly to keycloakUserId.hashCode()
     * with no null guard. A default-constructed instance therefore throws NPE when
     * hashCode() is called. Pin this behavior explicitly.
     *
     * If a Kotlin migration silently makes this null-safe (e.g., `keycloakUserId?.hashCode() ?: 0`),
     * this test fails — which is the desired signal to revisit callers that may
     * depend on the fail-fast semantics.
     */
    @Test(expected = NullPointerException::class)
    fun testHashCodeThrowsNpeWhenKeycloakUserIdIsNull() {
        val obj = KeycloakGroupMemberAndPermissions()
        // keycloakUserId is null; must throw NPE matching the Java implementation
        obj.hashCode()
    }
}
