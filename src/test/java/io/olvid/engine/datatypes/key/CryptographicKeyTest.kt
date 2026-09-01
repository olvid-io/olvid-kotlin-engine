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

package io.olvid.engine.datatypes.key

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.asymmetric.SignaturePublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.datatypes.key.symmetric.SymEncKey
import io.olvid.engine.encoder.Encoded
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.HashMap

/**
 * Characterization tests for [CryptographicKey].
 *
 * Contracts pinned here:
 *
 * 1. **6 ALGO_CLASS_* wire-format byte constants** — exact byte values are part of the
 *    on-wire protocol; a migration must not renumber them.
 *
 * 2. **Gap between symmetric (0x00–0x02) and asymmetric (0x11–0x14) classes** — the gap
 *    is intentional. Any insertion that shifts the asymmetric constants up will be caught.
 *
 * 3. **Custom equals** — compares algorithmClass + algorithmImplementation + key map.
 *    A Kotlin data class migration would break this by including superclass fields differently,
 *    or by using a different equality strategy.
 *
 * 4. **Custom hashCode formula** — `key.hashCode() + 31 * algorithmClass + 631 * algorithmImplementation`.
 *    The multipliers 31 and 631 are load-bearing. A migration that switches to Objects.hash()
 *    or data class auto-generation would silently produce a different formula.
 *
 * 5. **Constructor field storage** and **getters** — each field is stored and returned as-is.
 *
 * 6. **Subclass ALGO_IMPL_* wire-format byte constants** — pinned from EncryptionPublicKey,
 *    ServerAuthenticationPublicKey, SignaturePublicKey, AuthEncKey, MACKey, and SymEncKey.
 */
class CryptographicKeyTest {

    // ─── Minimal concrete subclass for testing the abstract base ─────────────

    private class TestKey(
        algorithmClass: Byte,
        algorithmImplementation: Byte,
        key: HashMap<DictionaryKey, Encoded>
    ) : CryptographicKey(algorithmClass, algorithmImplementation, key)

    // ─── Helper builders ──────────────────────────────────────────────────────

    /** Returns a deterministic non-empty key map with a single entry. */
    private fun buildKeyMap(keyName: String = "k", value: Int = 42): HashMap<DictionaryKey, Encoded> {
        val map = HashMap<DictionaryKey, Encoded>()
        map[DictionaryKey(keyName)] = Encoded.of(value.toLong())
        return map
    }

    /** Returns a deterministic key map with a different content. */
    private fun buildAlternateKeyMap(): HashMap<DictionaryKey, Encoded> {
        val map = HashMap<DictionaryKey, Encoded>()
        map[DictionaryKey("other")] = Encoded.of(99L)
        return map
    }

    private lateinit var defaultKey: TestKey
    private lateinit var defaultKeyMap: HashMap<DictionaryKey, Encoded>

    @Before
    fun setUp() {
        defaultKeyMap = buildKeyMap()
        defaultKey = TestKey(
            algorithmClass = 0x11.toByte(),
            algorithmImplementation = 0x01.toByte(),
            key = defaultKeyMap
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 1: ALGO_CLASS_* wire-format byte constants
    // ═══════════════════════════════════════════════════════════════════════════

    /** ALGO_CLASS_SYMMETRIC_ENCRYPTION must be the wire byte 0x00. */
    @Test
    fun algoClass_symmetricEncryption_is0x00() {
        assertEquals(
            "ALGO_CLASS_SYMMETRIC_ENCRYPTION must be wire byte 0x00",
            0x00.toByte(),
            CryptographicKey.ALGO_CLASS_SYMMETRIC_ENCRYPTION
        )
    }

    /** ALGO_CLASS_MAC must be the wire byte 0x01. */
    @Test
    fun algoClass_mac_is0x01() {
        assertEquals(
            "ALGO_CLASS_MAC must be wire byte 0x01",
            0x01.toByte(),
            CryptographicKey.ALGO_CLASS_MAC
        )
    }

    /** ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION must be the wire byte 0x02. */
    @Test
    fun algoClass_authenticatedSymmetricEncryption_is0x02() {
        assertEquals(
            "ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION must be wire byte 0x02",
            0x02.toByte(),
            CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION
        )
    }

    /** ALGO_CLASS_SIGNATURE must be the wire byte 0x11. */
    @Test
    fun algoClass_signature_is0x11() {
        assertEquals(
            "ALGO_CLASS_SIGNATURE must be wire byte 0x11",
            0x11.toByte(),
            CryptographicKey.ALGO_CLASS_SIGNATURE
        )
    }

    /** ALGO_CLASS_PUBLIC_KEY_ENCRYPTION must be the wire byte 0x12. */
    @Test
    fun algoClass_publicKeyEncryption_is0x12() {
        assertEquals(
            "ALGO_CLASS_PUBLIC_KEY_ENCRYPTION must be wire byte 0x12",
            0x12.toByte(),
            CryptographicKey.ALGO_CLASS_PUBLIC_KEY_ENCRYPTION
        )
    }

    /** ALGO_CLASS_SERVER_AUTHENTICATION must be the wire byte 0x14. */
    @Test
    fun algoClass_serverAuthentication_is0x14() {
        assertEquals(
            "ALGO_CLASS_SERVER_AUTHENTICATION must be wire byte 0x14",
            0x14.toByte(),
            CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION
        )
    }

    /**
     * THE GAP PIN TEST.
     *
     * The symmetric classes span 0x00–0x02 and the asymmetric classes start at 0x11.
     * Values 0x03–0x10 are intentionally unused, separating the two groups.
     *
     * If a future reorganization inserts a new class into the gap (shifting 0x11 upward),
     * this test will catch the regression by asserting the asymmetric base is exactly
     * 0x11 (decimal 17) while the symmetric ceiling is exactly 0x02 (decimal 2),
     * leaving a gap of 14 unused values.
     */
    @Test
    fun algoClass_gapBetweenSymmetricAndAsymmetric_is14UnusedValues() {
        val symmetricCeiling = CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION.toInt() and 0xff
        val asymmetricBase = CryptographicKey.ALGO_CLASS_SIGNATURE.toInt() and 0xff
        val gap = asymmetricBase - symmetricCeiling - 1
        assertEquals(
            "There must be exactly 14 unused wire values (0x03..0x10) between the " +
                    "symmetric ceiling (0x02) and the asymmetric base (0x11). " +
                    "A reorganization that shifts these constants must be flagged.",
            14,
            gap
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 2: Custom equals
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two instances with the SAME algorithmClass + algorithmImplementation + key map
     * (different map object, same content) must be equal.
     */
    @Test
    fun equals_sameAllThreeFields_areEqual() {
        val mapA = buildKeyMap()
        val mapB = buildKeyMap()
        val a = TestKey(0x11.toByte(), 0x01.toByte(), mapA)
        val b = TestKey(0x11.toByte(), 0x01.toByte(), mapB)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "Two TestKey instances with identical algorithmClass, algorithmImplementation, and key map content must be equal",
            a.equals(b)
        )
    }

    /**
     * Same (algorithmClass, algorithmImplementation) but DIFFERENT key map content → not equal.
     */
    @Test
    fun equals_sameClassAndImplButDifferentKeyMap_areNotEqual() {
        val a = TestKey(0x11.toByte(), 0x01.toByte(), buildKeyMap())
        val b = TestKey(0x11.toByte(), 0x01.toByte(), buildAlternateKeyMap())
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two TestKey instances with the same class/impl but different key map content must not be equal",
            a.equals(b)
        )
    }

    /**
     * Different algorithmClass (same impl + key) → not equal.
     */
    @Test
    fun equals_differentAlgorithmClass_areNotEqual() {
        val map = buildKeyMap()
        val a = TestKey(0x11.toByte(), 0x01.toByte(), map)
        val b = TestKey(0x12.toByte(), 0x01.toByte(), map)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two TestKey instances with different algorithmClass must not be equal",
            a.equals(b)
        )
    }

    /**
     * Different algorithmImplementation (same class + key) → not equal.
     */
    @Test
    fun equals_differentAlgorithmImplementation_areNotEqual() {
        val map = buildKeyMap()
        val a = TestKey(0x11.toByte(), 0x00.toByte(), map)
        val b = TestKey(0x11.toByte(), 0x01.toByte(), map)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two TestKey instances with different algorithmImplementation must not be equal",
            a.equals(b)
        )
    }

    /** equals(null) must return false per the `instanceof CryptographicKey` guard. */
    @Test
    fun equals_null_returnsFalse() {
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(null) must return false", defaultKey.equals(null))
    }

    /** equals(String) must return false without throwing. */
    @Test
    fun equals_unrelatedType_returnsFalse() {
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(String) must return false", defaultKey.equals("not-a-key"))
    }

    /** Reflexive: an instance must equal itself. */
    @Test
    fun equals_self_returnsTrue() {
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals(self) must return true", defaultKey.equals(defaultKey))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 3: Custom hashCode formula
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Pin the exact formula: `key.hashCode() + 31 * algorithmClass + 631 * algorithmImplementation`.
     *
     * Multipliers 31 and 631 are load-bearing — a Kotlin migration that replaces this with
     * Objects.hash() or data class auto-generation would silently produce a different hash.
     */
    @Test
    fun hashCode_exactFormula_matchesManualComputation() {
        val algoClass: Byte = 0x11
        val algoImpl: Byte = 0x02
        val map = buildKeyMap("test", 7)
        val key = TestKey(algoClass, algoImpl, map)

        val expectedHash = map.hashCode() + 31 * algoClass + 631 * algoImpl
        assertEquals(
            "hashCode must equal key.hashCode() + 31 * algorithmClass + 631 * algorithmImplementation",
            expectedHash,
            key.hashCode()
        )
    }

    /**
     * Two instances wrapping THE SAME key map object must produce the same hashCode.
     *
     * Note: [Encoded] does not override hashCode(), so it uses identity-based hashing.
     * This means two separate HashMap instances with logically equal content will produce
     * different hashCodes (since each Encoded entry will hash differently). The hashCode
     * formula is therefore only consistent when both instances share the exact same map
     * reference — which is why we use a shared map here.
     */
    @Test
    fun hashCode_instancesWithSameMapReference_haveSameHashCode() {
        val sharedMap = buildKeyMap()
        val a = TestKey(0x12.toByte(), 0x00.toByte(), sharedMap)
        val b = TestKey(0x12.toByte(), 0x00.toByte(), sharedMap)
        assertEquals(
            "Two CryptographicKey instances sharing the exact same key map reference must have the same hashCode",
            a.hashCode(),
            b.hashCode()
        )
    }

    /** hashCode is stable: repeated calls must return the same value. */
    @Test
    fun hashCode_stableAcrossRepeatedCalls() {
        val h1 = defaultKey.hashCode()
        val h2 = defaultKey.hashCode()
        assertEquals("hashCode must be stable across repeated calls", h1, h2)
    }

    /**
     * Pin that the formula uses the multiplier 631 (not 31 alone).
     *
     * If the formula were `key.hashCode() + 31 * class + 31 * impl`, results would differ
     * from the actual formula when class != impl. This test pins a case where the two
     * multipliers produce measurably different results.
     *
     * For algoClass=0x00, algoImpl=0x01, and the standard key map:
     *   correct:   map.hashCode() + 31*0 + 631*1 = map.hashCode() + 631
     *   incorrect: map.hashCode() + 31*0 + 31*1  = map.hashCode() + 31
     * They differ by 600.
     */
    @Test
    fun hashCode_uses631MultiplierForImpl_notJust31() {
        val algoClass: Byte = 0x00
        val algoImpl: Byte = 0x01
        val map = buildKeyMap("x", 1)
        val key = TestKey(algoClass, algoImpl, map)

        val correctFormula = map.hashCode() + 31 * algoClass + 631 * algoImpl
        val wrongFormula = map.hashCode() + 31 * algoClass + 31 * algoImpl

        assertEquals(
            "hashCode must use multiplier 631 for algorithmImplementation",
            correctFormula,
            key.hashCode()
        )
        // Confirm the two formulas actually differ for this input (test guard)
        assertTrue(
            "The 631 and 31 multipliers must produce distinct results for algoImpl=1, algoClass=0",
            correctFormula != wrongFormula
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 4: Constructor field storage
    // ═══════════════════════════════════════════════════════════════════════════

    /** The constructor must store algorithmClass exactly. */
    @Test
    fun constructor_storesAlgorithmClass() {
        val key = TestKey(0x14.toByte(), 0x01.toByte(), buildKeyMap())
        assertEquals(
            "Constructor must store algorithmClass as-is",
            0x14.toByte(),
            key.algorithmClass
        )
    }

    /** The constructor must store algorithmImplementation exactly. */
    @Test
    fun constructor_storesAlgorithmImplementation() {
        val key = TestKey(0x12.toByte(), 0x02.toByte(), buildKeyMap())
        assertEquals(
            "Constructor must store algorithmImplementation as-is",
            0x02.toByte(),
            key.algorithmImplementation
        )
    }

    /** The constructor must store the key map by reference (no defensive copy). */
    @Test
    fun constructor_storesKeyMapByReference() {
        val map = buildKeyMap()
        val key = TestKey(0x11.toByte(), 0x00.toByte(), map)
        assertSame(
            "Constructor must store the key HashMap by reference, not by copy",
            map,
            key.key
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 5: Getters
    // ═══════════════════════════════════════════════════════════════════════════

    /** getAlgorithmClass() must return the stored algorithmClass. */
    @Test
    fun getAlgorithmClass_returnsStoredValue() {
        val key = TestKey(0x02.toByte(), 0x00.toByte(), buildKeyMap())
        assertEquals(
            "getAlgorithmClass() must return the value passed to the constructor",
            0x02.toByte(),
            key.algorithmClass
        )
    }

    /** getAlgorithmImplementation() must return the stored algorithmImplementation. */
    @Test
    fun getAlgorithmImplementation_returnsStoredValue() {
        val key = TestKey(0x00.toByte(), 0x01.toByte(), buildKeyMap())
        assertEquals(
            "getAlgorithmImplementation() must return the value passed to the constructor",
            0x01.toByte(),
            key.algorithmImplementation
        )
    }

    /** getKey() must return the stored HashMap reference. */
    @Test
    fun getKey_returnsStoredHashMap() {
        val map = buildKeyMap()
        val key = TestKey(0x01.toByte(), 0x00.toByte(), map)
        assertNotNull("getKey() must not return null", key.key)
        assertSame(
            "getKey() must return the exact HashMap reference passed to the constructor",
            map,
            key.key
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 6: EncryptionPublicKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 must be wire byte 0x00.
     * This is the MDC curve ECIES implementation.
     */
    @Test
    fun encryptionPublicKey_algoImplKemEciesMDC_is0x00() {
        assertEquals(
            "EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 must be 0x00",
            0x00.toByte(),
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_MDC_AND_DEM_CTR_AES256_THEN_HMAC_SHA256
        )
    }

    /**
     * ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 must be wire byte 0x01.
     * This is the Curve25519 ECIES implementation.
     */
    @Test
    fun encryptionPublicKey_algoImplKemEciesCurve25519_is0x01() {
        assertEquals(
            "EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256 must be 0x01",
            0x01.toByte(),
            EncryptionPublicKey.ALGO_IMPL_KEM_ECIES_CURVE25519_AND_DEM_CTR_AES256_THEN_HMAC_SHA256
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 7: ServerAuthenticationPublicKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC must be wire byte 0x00.
     * This is the MDC curve EC-SDSA server authentication implementation.
     */
    @Test
    fun serverAuthPublicKey_algoImplECSdsaMDC_is0x00() {
        assertEquals(
            "ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC must be 0x00",
            0x00.toByte(),
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_MDC
        )
    }

    /**
     * ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 must be wire byte 0x01.
     * This is the Curve25519 EC-SDSA server authentication implementation.
     */
    @Test
    fun serverAuthPublicKey_algoImplECSdsaCurve25519_is0x01() {
        assertEquals(
            "ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519 must be 0x01",
            0x01.toByte(),
            ServerAuthenticationPublicKey.ALGO_IMPL_SIGN_CHALLENGE_EC_SDSA_CURVE25519
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 8: SignaturePublicKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_EC_SDSA_MDC must be wire byte 0x00.
     * This is the MDC curve EC-SDSA signature implementation.
     */
    @Test
    fun signaturePublicKey_algoImplECSdsaMDC_is0x00() {
        assertEquals(
            "SignaturePublicKey.ALGO_IMPL_EC_SDSA_MDC must be 0x00",
            0x00.toByte(),
            SignaturePublicKey.ALGO_IMPL_EC_SDSA_MDC
        )
    }

    /**
     * ALGO_IMPL_EC_SDSA_CURVE25519 must be wire byte 0x01.
     * This is the Curve25519 EC-SDSA signature implementation.
     */
    @Test
    fun signaturePublicKey_algoImplECSdsaCurve25519_is0x01() {
        assertEquals(
            "SignaturePublicKey.ALGO_IMPL_EC_SDSA_CURVE25519 must be 0x01",
            0x01.toByte(),
            SignaturePublicKey.ALGO_IMPL_EC_SDSA_CURVE25519
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 9: AuthEncKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_AES256_THEN_SHA256 must be wire byte 0x00.
     * This is the sole authenticated encryption implementation: AES-256 + HMAC-SHA256.
     */
    @Test
    fun authEncKey_algoImplAES256ThenSHA256_is0x00() {
        assertEquals(
            "AuthEncKey.ALGO_IMPL_AES256_THEN_SHA256 must be 0x00",
            0x00.toByte(),
            AuthEncKey.ALGO_IMPL_AES256_THEN_SHA256
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 10: MACKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_HMAC_SHA256 must be wire byte 0x00.
     * This is the sole MAC implementation: HMAC-SHA256.
     */
    @Test
    fun macKey_algoImplHmacSha256_is0x00() {
        assertEquals(
            "MACKey.ALGO_IMPL_HMAC_SHA256 must be 0x00",
            0x00.toByte(),
            MACKey.ALGO_IMPL_HMAC_SHA256
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 11: SymEncKey ALGO_IMPL_* constants
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * ALGO_IMPL_CTR_AES256 must be wire byte 0x00.
     * This is the sole symmetric encryption implementation: CTR mode AES-256.
     */
    @Test
    fun symEncKey_algoImplCtrAES256_is0x00() {
        assertEquals(
            "SymEncKey.ALGO_IMPL_CTR_AES256 must be 0x00",
            0x00.toByte(),
            SymEncKey.ALGO_IMPL_CTR_AES256
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 12: ALGO_CLASS_* values are correctly propagated by subclasses
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * All 6 ALGO_CLASS constants are distinct from each other.
     * This sanity-checks that no two classes share the same wire byte.
     */
    @Test
    fun algoClass_allSixValuesAreDistinct() {
        val values = setOf(
            CryptographicKey.ALGO_CLASS_SYMMETRIC_ENCRYPTION,
            CryptographicKey.ALGO_CLASS_MAC,
            CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION,
            CryptographicKey.ALGO_CLASS_SIGNATURE,
            CryptographicKey.ALGO_CLASS_PUBLIC_KEY_ENCRYPTION,
            CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION
        )
        assertEquals(
            "All 6 ALGO_CLASS_* constants must have distinct wire byte values",
            6,
            values.size
        )
    }

    /**
     * The 3 symmetric ALGO_CLASS constants are all <= 0x0F (low nibble).
     * The 3 asymmetric ALGO_CLASS constants are all >= 0x10 (high nibble set).
     * This mirrors the structural grouping in the source.
     */
    @Test
    fun algoClass_symmetricClassesAreInLowRange_asymmetricInHighRange() {
        // Symmetric: 0x00, 0x01, 0x02
        assertTrue(
            "ALGO_CLASS_SYMMETRIC_ENCRYPTION must be in the symmetric range (< 0x10)",
            (CryptographicKey.ALGO_CLASS_SYMMETRIC_ENCRYPTION.toInt() and 0xff) < 0x10
        )
        assertTrue(
            "ALGO_CLASS_MAC must be in the symmetric range (< 0x10)",
            (CryptographicKey.ALGO_CLASS_MAC.toInt() and 0xff) < 0x10
        )
        assertTrue(
            "ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION must be in the symmetric range (< 0x10)",
            (CryptographicKey.ALGO_CLASS_AUTHENTICATED_SYMMETRIC_ENCRYPTION.toInt() and 0xff) < 0x10
        )
        // Asymmetric: 0x11, 0x12, 0x14
        assertTrue(
            "ALGO_CLASS_SIGNATURE must be in the asymmetric range (>= 0x10)",
            (CryptographicKey.ALGO_CLASS_SIGNATURE.toInt() and 0xff) >= 0x10
        )
        assertTrue(
            "ALGO_CLASS_PUBLIC_KEY_ENCRYPTION must be in the asymmetric range (>= 0x10)",
            (CryptographicKey.ALGO_CLASS_PUBLIC_KEY_ENCRYPTION.toInt() and 0xff) >= 0x10
        )
        assertTrue(
            "ALGO_CLASS_SERVER_AUTHENTICATION must be in the asymmetric range (>= 0x10)",
            (CryptographicKey.ALGO_CLASS_SERVER_AUTHENTICATION.toInt() and 0xff) >= 0x10
        )
    }
}
