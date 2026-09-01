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

package io.olvid.engine.engine.types.identities

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetails
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Arrays
import java.util.TreeSet

/**
 * Characterization tests for [ObvIdentity].
 *
 * Contracts pinned here:
 *
 * 1. **Custom equals** — compares ONLY the `identity` field using `getClass().equals()` (NOT
 *    `instanceof`). The other three fields (`identityDetails`, `keycloakManaged`, `active`) are
 *    entirely ignored. A Kotlin migration that generates a data-class equals over all fields, or
 *    switches from `getClass()` to `instanceof`, would silently break these invariants.
 *
 * 2. **Custom hashCode** — delegates to `Arrays.hashCode(identity.getBytes())`. Consistent with
 *    equals per contract.
 *
 * 3. **Custom compareTo** — delegates to `identity.computeUniqueUid().compareTo(...)`. Consistent
 *    with equals: when equals returns true, compareTo returns 0.
 *
 * 4. **Comparable integration** — TreeSet collapses instances with the same identity.
 *
 * 5. **Constructor field storage** — all 4 constructor arguments are stored exactly as passed.
 *
 * 6. **Getter delegation** — `getIdentity()`, `getBytesIdentity()`, `getServer()`.
 *
 * 7. **`encode()` / `of()` round-trip** — wire-format contract. The encoded format holds only
 *    `identity` + `identityDetails`; `keycloakManaged` and `active` are NOT encoded, and `of()`
 *    hard-codes them to `false` / `true` respectively.
 *
 * 8. **`of()` error path** — wrong-arity encoded lists throw [DecodingException].
 *
 * 9. **`encode()` layout** — a 2-element list: [0]=identity bytes, [1]=JSON string of details.
 */
class ObvIdentityTest {

    private lateinit var mapper: ObjectMapper

    // Two fully independent Identity instances (different key material).
    private lateinit var identityA: Identity
    private lateinit var identityB: Identity

    // A fully-populated JsonIdentityDetails instance reused across tests.
    private lateinit var detailsFull: JsonIdentityDetails
    private lateinit var detailsAlt: JsonIdentityDetails

    // ── Private subclass used to test getClass()-based equality ──────────────

    /**
     * A minimal subclass of ObvIdentity used to pin that the Java implementation calls
     * `getClass().equals(other.getClass())` — NOT `instanceof`. An ObvIdentity instance and an
     * ObvIdentitySubclass instance wrapping the SAME identity must therefore NOT be equal.
     *
     * If a Kotlin migration switches to `is ObvIdentity` (instanceof), this test will fail and
     * surface the semantic change.
     */
    private inner class ObvIdentitySubclass(
        identity: Identity,
        details: JsonIdentityDetails,
        keycloakManaged: Boolean,
        active: Boolean,
    ) : ObvIdentity(identity, details, keycloakManaged, active) {
        // Empty subclass — just needs a different runtime class from ObvIdentity.
    }

    // ── @Before setup ─────────────────────────────────────────────────────────

    @Before
    fun setUp() {
        // Silence engine logger so test output is clean.
        Logger.setOutputLogLevel(Logger.NONE)

        mapper = ObjectMapper()

        // Deterministic PRNG seeded with all-zeros produces reproducible key material.
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPairA = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairA = EncryptionEciesCurve25519KeyPair.generate(prng)
        identityA = Identity(
            "server-a.olvid.io",
            serverAuthKeyPairA.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairA.publicKey as EncryptionPublicKey,
        )

        // A second PRNG seed shift produces a genuinely different identity.
        prng.reseed(Seed(ByteArray(32) { 1 }))
        val serverAuthKeyPairB = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairB = EncryptionEciesCurve25519KeyPair.generate(prng)
        identityB = Identity(
            "server-b.olvid.io",
            serverAuthKeyPairB.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairB.publicKey as EncryptionPublicKey,
        )

        detailsFull = JsonIdentityDetails("Alice", "Wonderland", "Acme Corp", "Engineer")
        detailsAlt = JsonIdentityDetails("Bob", "Builder", "Builders Inc", "Architect")
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 1: Custom equals — compares ONLY the `identity` field
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Same `identity`, DIFFERENT `identityDetails` → must be equal.
     * Details are explicitly ignored by the implementation.
     */
    @Test
    fun equals_sameIdentityDifferentDetails_isEqual() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsAlt, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "ObvIdentity with same identity but different identityDetails must be equal",
            a.equals(b),
        )
    }

    /**
     * Same `identity`, DIFFERENT `keycloakManaged` → must be equal.
     */
    @Test
    fun equals_sameIdentityDifferentKeycloakManaged_isEqual() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsFull, true, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "ObvIdentity with same identity but different keycloakManaged must be equal",
            a.equals(b),
        )
    }

    /**
     * Same `identity`, DIFFERENT `active` → must be equal.
     */
    @Test
    fun equals_sameIdentityDifferentActive_isEqual() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsFull, false, false)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "ObvIdentity with same identity but different active must be equal",
            a.equals(b),
        )
    }

    /**
     * DIFFERENT `identity` (all other fields identical) → must NOT be equal.
     */
    @Test
    fun equals_differentIdentity_isNotEqual() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityB, detailsFull, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "ObvIdentity instances with different identity must not be equal",
            a.equals(b),
        )
    }

    /**
     * equals(null) returns false.
     *
     * The Kotlin implementation checks `other == null` before calling getClass(),
     * so passing null returns false rather than throwing NPE (which the Java implementation did).
     */
    @Test
    fun equals_null_returnsFalse() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(null) must return false in Kotlin", a.equals(null))
    }

    /** equals with an unrelated type (String) must return false. */
    @Test
    fun equals_unrelatedType_returnsFalse() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(String) must return false", a.equals("some-string"))
    }

    /** Reflexive: an instance must equal itself. */
    @Test
    fun equals_self_returnsTrue() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals(self) must return true", a.equals(a))
    }

    /**
     * SUBCLASS TEST — pins the `getClass().equals()` (NOT `instanceof`) behaviour.
     *
     * An [ObvIdentity] and an [ObvIdentitySubclass] wrapping the SAME underlying identity must
     * NOT be equal, because their runtime classes differ. A Kotlin migration that uses `is
     * ObvIdentity` (instanceof) would silently start returning true here, breaking this contract.
     */
    @Test
    fun equals_subclassInstanceWithSameIdentity_isNotEqual() {
        val base = ObvIdentity(identityA, detailsFull, false, true)
        val sub = ObvIdentitySubclass(identityA, detailsFull, false, true)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "An ObvIdentity must NOT equal an ObvIdentitySubclass even when the underlying " +
                "identity bytes are identical — getClass() differs from instanceof",
            base.equals(sub),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 2: Custom hashCode — Arrays.hashCode(identity.getBytes())
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two equal ObvIdentity instances (same identity, different other fields) must produce the
     * same hashCode. This is the minimum contract: hashCode is consistent with equals.
     */
    @Test
    fun hashCode_equalInstances_sameHashCode() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsAlt, true, false)
        assertEquals(
            "Equal ObvIdentity instances must have the same hashCode",
            a.hashCode(),
            b.hashCode(),
        )
    }

    /** hashCode is stable: repeated calls on the same instance return the same value. */
    @Test
    fun hashCode_stableAcrossRepeatedCalls() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val h1 = a.hashCode()
        val h2 = a.hashCode()
        assertEquals("hashCode must return the same value on repeated calls", h1, h2)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 3: Custom compareTo — consistent with equals
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * compareTo must return 0 when equals returns true (same identity, different other fields).
     * This pins the consistency contract between equals and compareTo.
     */
    @Test
    fun compareTo_equalByEquals_returnsZero() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsAlt, true, false)
        assertEquals(
            "compareTo must return 0 when equals returns true (same identity, different details/flags)",
            0,
            a.compareTo(b),
        )
    }

    /** Two distinct identities → compareTo returns non-zero. */
    @Test
    fun compareTo_differentIdentities_returnsNonZero() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityB, detailsFull, false, true)
        assertTrue(
            "compareTo of ObvIdentity instances with different identities must return non-zero",
            a.compareTo(b) != 0,
        )
    }

    /** Reflexive: compareTo(self) == 0. */
    @Test
    fun compareTo_self_returnsZero() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        assertEquals("compareTo(self) must return 0", 0, a.compareTo(a))
    }

    /** Anti-symmetry: sign(a.compareTo(b)) == -sign(b.compareTo(a)) for different identities. */
    @Test
    fun compareTo_antiSymmetric_differentIdentities() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityB, detailsFull, false, true)
        val ab = a.compareTo(b)
        val ba = b.compareTo(a)
        assertTrue(
            "compareTo must be anti-symmetric: if a < b then b > a",
            (ab < 0 && ba > 0) || (ab > 0 && ba < 0),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 4: Comparable integration in TreeSet
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Adding two ObvIdentity instances with the SAME identity (but different other fields) to a
     * TreeSet must collapse to a single entry — compareTo returns 0 so TreeSet treats them as
     * duplicates.
     */
    @Test
    fun treeSet_sameIdentityDifferentDetails_collapsesToOneEntry() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityA, detailsAlt, true, false)

        val set = TreeSet<ObvIdentity>()
        set.add(a)
        set.add(b)

        assertEquals(
            "TreeSet must collapse two ObvIdentity instances with the same identity to one entry",
            1,
            set.size,
        )
    }

    /**
     * Two ObvIdentity instances with DISTINCT identities both occupy their own slot in a TreeSet.
     */
    @Test
    fun treeSet_distinctIdentities_twoEntries() {
        val a = ObvIdentity(identityA, detailsFull, false, true)
        val b = ObvIdentity(identityB, detailsFull, false, true)

        val set = TreeSet<ObvIdentity>()
        set.add(a)
        set.add(b)

        assertEquals(
            "TreeSet must retain two entries for two ObvIdentity instances with distinct identities",
            2,
            set.size,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 5: 4-arg constructor stores all 4 fields exactly
    // ═══════════════════════════════════════════════════════════════════════════

    /** `getIdentity()` returns the SAME reference that was passed to the constructor. */
    @Test
    fun constructor_storesIdentityByReference() {
        val obj = ObvIdentity(identityA, detailsFull, true, false)
        assertSame(
            "getIdentity() must return the exact Identity reference passed to the constructor",
            identityA,
            obj.getIdentity(),
        )
    }

    /** `getIdentityDetails()` returns the SAME reference that was passed to the constructor. */
    @Test
    fun constructor_storesIdentityDetailsByReference() {
        val obj = ObvIdentity(identityA, detailsFull, true, false)
        assertSame(
            "getIdentityDetails() must return the exact JsonIdentityDetails reference passed to the constructor",
            detailsFull,
            obj.getIdentityDetails(),
        )
    }

    /** `isKeycloakManaged()` returns the boolean value passed to the constructor. */
    @Test
    fun constructor_storesKeycloakManagedBoolean() {
        val objTrue = ObvIdentity(identityA, detailsFull, true, false)
        val objFalse = ObvIdentity(identityA, detailsFull, false, true)
        assertTrue("keycloakManaged=true must be stored as true", objTrue.isKeycloakManaged())
        assertFalse("keycloakManaged=false must be stored as false", objFalse.isKeycloakManaged())
    }

    /** `isActive()` returns the boolean value passed to the constructor. */
    @Test
    fun constructor_storesActiveBoolean() {
        val objTrue = ObvIdentity(identityA, detailsFull, false, true)
        val objFalse = ObvIdentity(identityA, detailsFull, false, false)
        assertTrue("active=true must be stored as true", objTrue.isActive())
        assertFalse("active=false must be stored as false", objFalse.isActive())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 6 & 7 & 8: Getter delegation
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * `getIdentity()`, `getBytesIdentity()`, and `getServer()` must all delegate correctly to
     * the underlying [Identity].
     */
    @Test
    fun getters_delegateToUnderlyingIdentity() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)

        assertSame(
            "getIdentity() must return the stored Identity reference",
            identityA,
            obj.getIdentity(),
        )
        assertArrayEquals(
            "getBytesIdentity() must return identity.getBytes() byte-for-byte",
            identityA.getBytes(),
            obj.getBytesIdentity(),
        )
        assertEquals(
            "getServer() must return identity.server",
            identityA.server,
            obj.getServer(),
        )
    }

    /** `getBytesIdentity()` returns `identity.getBytes()` byte-for-byte. */
    @Test
    fun getBytesIdentity_matchesIdentityGetBytes() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)
        assertArrayEquals(
            "getBytesIdentity() must return the same bytes as identity.getBytes()",
            identityA.getBytes(),
            obj.getBytesIdentity(),
        )
    }

    /** `server` property (from Java `getServer()`) delegates to `identity.server`. */
    @Test
    fun getServer_matchesIdentityGetServer() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)
        assertEquals(
            "server property must return the same server string as identity.server",
            identityA.server,
            obj.getServer(),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 9: encode() / of() round-trip (wire-format pin)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * encode() → of() round-trip must reproduce the same identity bytes.
     *
     * This is the primary wire-format contract: an encoded ObvIdentity can be reconstructed on
     * the other end of a network connection.
     */
    @Test
    fun encodeOf_roundTrip_identityBytesMatch() {
        val original = ObvIdentity(identityA, detailsFull, false, true)

        val encoded = original.encode(mapper)
        val restored = ObvIdentity.of(encoded, mapper)

        assertArrayEquals(
            "encode→of round-trip must reproduce the same identity bytes",
            original.getBytesIdentity(),
            restored.getBytesIdentity(),
        )
    }

    /**
     * encode() → of() round-trip must reproduce all `identityDetails` fields.
     *
     * We use `fieldsAreTheSame()` rather than relying on the custom `equals()` (which ignores
     * `identityDetails`). This is a per-field assertion that catches any field-level regression.
     */
    @Test
    fun encodeOf_roundTrip_identityDetailsFieldsMatch() {
        val original = ObvIdentity(identityA, detailsFull, false, true)

        val encoded = original.encode(mapper)
        val restored = ObvIdentity.of(encoded, mapper)

        val restoredDetails = restored.getIdentityDetails()!!
        assertEquals(
            "round-tripped firstName must match",
            detailsFull.getFirstName(),
            restoredDetails.getFirstName(),
        )
        assertEquals(
            "round-tripped lastName must match",
            detailsFull.getLastName(),
            restoredDetails.getLastName(),
        )
        assertEquals(
            "round-tripped company must match",
            detailsFull.getCompany(),
            restoredDetails.getCompany(),
        )
        assertEquals(
            "round-tripped position must match",
            detailsFull.getPosition(),
            restoredDetails.getPosition(),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 10: of() LOSES keycloakManaged and active flags (wire-format pin)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * THE WIRE-FORMAT FLAGS PIN.
     *
     * The encoded format only stores `identity` + `identityDetails`; `keycloakManaged` and
     * `active` are NOT encoded. The `of()` factory hard-codes them to `false` and `true`
     * respectively on reconstruction.
     *
     * A Kotlin migration that tries to round-trip those flags (e.g. by adding them to the
     * encoded list) would change the wire format and break interoperability with peers running
     * the original code — this test catches exactly that regression.
     */
    @Test
    fun encodeOf_roundTrip_losesKeycloakManagedAndActiveFlags() {
        // Start with keycloakManaged=true, active=false — the opposite of the hard-coded defaults.
        val original = ObvIdentity(identityA, detailsFull, true, false)

        val encoded = original.encode(mapper)
        val restored = ObvIdentity.of(encoded, mapper)

        assertFalse(
            "of() must hard-code keycloakManaged=false regardless of original value",
            restored.isKeycloakManaged(),
        )
        assertTrue(
            "of() must hard-code active=true regardless of original value",
            restored.isActive(),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 11: of() error path — wrong-arity encoded lists
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * An Encoded that decodes to a list of length 1 must throw [DecodingException].
     * `of()` requires exactly 2 elements: [identity, detailsJsonString].
     */
    @Test(expected = DecodingException::class)
    fun of_encodedListLengthOne_throwsDecodingException() {
        // Build a list with exactly 1 element (a byte-array stub).
        val oneElementList = Encoded.of(arrayOf(Encoded.of(byteArrayOf(1, 2, 3))))
        ObvIdentity.of(oneElementList, mapper)
    }

    /**
     * An Encoded that decodes to a list of length 3 must throw [DecodingException].
     */
    @Test(expected = DecodingException::class)
    fun of_encodedListLengthThree_throwsDecodingException() {
        val threeElementList = Encoded.of(
            arrayOf(
                Encoded.of(byteArrayOf(1)),
                Encoded.of(byteArrayOf(2)),
                Encoded.of(byteArrayOf(3)),
            )
        )
        ObvIdentity.of(threeElementList, mapper)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 12: encode() layout pin
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * encode() must produce a 2-element list where:
     *   - element [0] decodes to the identity bytes (decodeIdentity() matches).
     *   - element [1] decodes to the JSON string of identityDetails.
     *
     * This pins the binary layout so any migration that reorders or extends the list is caught.
     */
    @Test
    fun encode_layoutPin_element0IsIdentity() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)
        val encoded = obj.encode(mapper)

        val list = encoded.decodeList()
        assertEquals("encode() must produce a 2-element list", 2, list.size)

        val recoveredIdentity = list[0].decodeIdentity()
        assertArrayEquals(
            "Encoded[0] must decode back to the identity bytes",
            identityA.getBytes(),
            recoveredIdentity.getBytes(),
        )
    }

    @Test
    fun encode_layoutPin_element1IsDetailsJsonString() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)
        val encoded = obj.encode(mapper)

        val list = encoded.decodeList()
        assertEquals("encode() must produce a 2-element list", 2, list.size)

        val expectedJson = mapper.writeValueAsString(detailsFull)
        val actualJson = list[1].decodeString()
        assertEquals(
            "Encoded[1] must decode to the JSON string of identityDetails",
            expectedJson,
            actualJson,
        )
    }

    @Test
    fun encode_layoutPin_encodedListHasExactlyTwoElements() {
        val obj = ObvIdentity(identityA, detailsFull, false, true)
        val encoded = obj.encode(mapper)

        val list = encoded.decodeList()
        assertEquals(
            "encode() must produce a list of exactly 2 elements (identity + detailsJson)",
            2,
            list.size,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 13: Session/IdentityDelegate constructors — DB-DEPENDENT, SKIP
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // The two 3-argument constructors:
    //   ObvIdentity(Session, IdentityDelegate, Identity)
    //   ObvIdentity(Session, IdentityDelegate, Identity, Identity)
    // require live DB sessions and a fully wired IdentityDelegate, which are unavailable in
    // plain JVM unit tests. They are intentionally excluded from this test class. Integration
    // tests that boot the engine would cover these paths.
}
