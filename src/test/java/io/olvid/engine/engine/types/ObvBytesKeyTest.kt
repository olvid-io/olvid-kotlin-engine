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

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.module.SimpleModule
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Arrays
import java.util.TreeSet

/**
 * Characterization tests for [ObvBytesKey].
 *
 * [ObvBytesKey] is a value object whose byte array content determines equality, hash,
 * and ordering. It is also used as a HashMap key and value in Jackson-serialized data,
 * via four inner serializer/deserializer classes.
 *
 * Contracts pinned here:
 *
 * 1. **equals** — content-based, not reference-based (uses Arrays.equals on the `bytes` field).
 *    A J2K migration must not inadvertently switch to reference identity.
 *
 * 2. **hashCode** — delegates to Arrays.hashCode(bytes). Consistent with equals.
 *
 * 3. **compareTo** — length-first, then byte-by-byte UNSIGNED comparison (bytes[i] & 0xff).
 *    The unsigned mask is load-bearing: a Kotlin migration that drops it silently reverses
 *    the order of bytes with the high bit set.
 *
 * 4. **Comparable integration** — TreeSet ordering follows compareTo; compareTo==0 collapses
 *    same-content keys as in a TreeSet.
 *
 * 5. **Reference semantics** — the constructor stores the byte[] BY REFERENCE (no defensive
 *    copy). Mutations to the source array reflect in getBytes().
 *
 * 6. **Jackson KeySerializer / KeyDeserializer** — encode/decode map keys as Base64 field names.
 *
 * 7. **Jackson Serializer / Deserializer** — encode/decode a single ObvBytesKey value as a
 *    Base64 string.
 *
 * 8. **Full round-trip** — HashMap<ObvBytesKey, ObvBytesKey> survives serialize → deserialize.
 */
class ObvBytesKeyTest {

    private lateinit var mapper: ObjectMapper

    // ── Wrapper DTOs used to exercise the @JsonSerialize/@JsonDeserialize annotations ──

    /**
     * Wrapper for testing KeySerializer/KeyDeserializer (map key variant).
     * Mirrors the real production usage (e.g. GroupV2SyncSnapshot.members).
     */
    private class MapKeyWrapper {
        @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
        @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
        @JsonProperty("data")
        var data: HashMap<ObvBytesKey, String> = HashMap()
    }

    /**
     * Wrapper for testing KeySerializer/KeyDeserializer with ObvBytesKey as both key and value.
     * Mirrors real usage in round-trip integration test.
     */
    private class MapKeyValueWrapper {
        @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
        @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
        @JsonProperty("data")
        var data: HashMap<ObvBytesKey, ObvBytesKey> = HashMap()
    }

    @Before
    fun setUp() {
        // Register the value Serializer/Deserializer via a SimpleModule so we can test
        // ObvBytesKey as a top-level JSON value without needing a wrapping DTO.
        val module = SimpleModule()
        module.addSerializer(ObvBytesKey::class.java, ObvBytesKey.Serializer())
        module.addDeserializer(ObvBytesKey::class.java, ObvBytesKey.Deserializer())
        mapper = ObjectMapper().registerModule(module)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 1: Custom equals — content-based on byte[]
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two instances constructed from DIFFERENT array objects with THE SAME content
     * must be equal. This is the core contract: equals is content-based, not reference-based.
     */
    @Test
    fun equals_sameContentDifferentArrayReferences_areEqual() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        val b = ObvBytesKey(byteArrayOf(1, 2, 3))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "Two ObvBytesKey instances with the same byte content must be equal",
            a.equals(b)
        )
    }

    /** Two instances with DIFFERENT byte content must not be equal. */
    @Test
    fun equals_differentContent_areNotEqual() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        val b = ObvBytesKey(byteArrayOf(1, 2, 4))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "Two ObvBytesKey instances with different byte content must not be equal",
            a.equals(b)
        )
    }

    /** Two instances wrapping empty byte arrays must be equal. */
    @Test
    fun equals_twoEmptyByteArrays_areEqual() {
        val a = ObvBytesKey(byteArrayOf())
        val b = ObvBytesKey(byteArrayOf())
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue(
            "Two ObvBytesKey instances wrapping empty arrays must be equal",
            a.equals(b)
        )
    }

    /** Instances with different array lengths must not be equal, even if one is a prefix. */
    @Test
    fun equals_differentLengths_areNotEqual() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        val b = ObvBytesKey(byteArrayOf(1, 2))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse(
            "ObvBytesKey instances with different array lengths must not be equal",
            a.equals(b)
        )
    }

    /** equals(null) must return false. */
    @Test
    fun equals_null_returnsFalse() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(null) must return false", a.equals(null))
    }

    /** equals with an unrelated type (String) must return false without throwing. */
    @Test
    fun equals_unrelatedType_returnsFalse() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(String) must return false", a.equals("hello"))
    }

    /** Reflexive: an instance must equal itself. */
    @Test
    fun equals_self_returnsTrue() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals(self) must return true", a.equals(a))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 2: Custom hashCode — consistent with equals
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two equal instances (same content) must produce the same hashCode.
     */
    @Test
    fun hashCode_equalInstances_haveSameHashCode() {
        val a = ObvBytesKey(byteArrayOf(10, 20, 30))
        val b = ObvBytesKey(byteArrayOf(10, 20, 30))
        assertEquals(
            "Equal ObvBytesKey instances must have the same hashCode",
            a.hashCode(),
            b.hashCode()
        )
    }

    /**
     * The hashCode implementation must delegate to Arrays.hashCode(bytes).
     * Pin the exact formula so a Kotlin migration can't silently switch to a different one.
     * byteArrayOf(1, 2, 3) → Arrays.hashCode is 30817 (JDK deterministic value).
     */
    @Test
    fun hashCode_delegatesToArraysHashCode() {
        val src = byteArrayOf(1, 2, 3)
        val key = ObvBytesKey(src)
        assertEquals(
            "hashCode must equal Arrays.hashCode(bytes)",
            Arrays.hashCode(src),
            key.hashCode()
        )
    }

    /** hashCode is stable: repeated calls on the same instance return the same value. */
    @Test
    fun hashCode_stableAcrossRepeatedCalls() {
        val key = ObvBytesKey(byteArrayOf(7, 8, 9))
        val h1 = key.hashCode()
        val h2 = key.hashCode()
        assertEquals("hashCode must return the same value on repeated calls", h1, h2)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 3: compareTo — length-first, then unsigned byte-by-byte
    // ═══════════════════════════════════════════════════════════════════════════

    /** Equal arrays → compareTo returns 0. */
    @Test
    fun compareTo_equalArrays_returnsZero() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        val b = ObvBytesKey(byteArrayOf(1, 2, 3))
        assertEquals("compareTo of equal content must return 0", 0, a.compareTo(b))
    }

    /**
     * Length comparison takes priority over content.
     * A shorter array is always less than a longer one, regardless of byte values.
     * byteArrayOf(0xff.toByte()) length=1  vs  byteArrayOf(0, 0) length=2 → 1-2 = -1 (negative).
     */
    @Test
    fun compareTo_shorterArrayIsLessThanLonger_regardlessOfContent() {
        val shorter = ObvBytesKey(byteArrayOf(0xff.toByte()))
        val longer = ObvBytesKey(byteArrayOf(0, 0))
        assertTrue(
            "A shorter array must compare as less than a longer array regardless of byte values",
            shorter.compareTo(longer) < 0
        )
    }

    /**
     * Symmetry of the length comparison: longer > shorter → positive.
     */
    @Test
    fun compareTo_longerArrayIsGreaterThanShorter() {
        val shorter = ObvBytesKey(byteArrayOf(1))
        val longer = ObvBytesKey(byteArrayOf(1, 2))
        assertTrue(
            "A longer array must compare as greater than a shorter array",
            longer.compareTo(shorter) > 0
        )
    }

    /**
     * Same-length arrays, byte-by-byte comparison:
     * byteArrayOf(1, 2) < byteArrayOf(1, 3) because byte index 1: 2 < 3.
     */
    @Test
    fun compareTo_sameLengthByteDifference_smallerFirstByteIsLess() {
        val a = ObvBytesKey(byteArrayOf(1, 2))
        val b = ObvBytesKey(byteArrayOf(1, 3))
        assertTrue(
            "byteArrayOf(1,2) must compare as less than byteArrayOf(1,3)",
            a.compareTo(b) < 0
        )
    }

    /**
     * Same-length arrays, byte-by-byte comparison — symmetric:
     * byteArrayOf(1, 3) > byteArrayOf(1, 2).
     */
    @Test
    fun compareTo_sameLengthByteDifference_largerFirstByteIsGreater() {
        val a = ObvBytesKey(byteArrayOf(1, 3))
        val b = ObvBytesKey(byteArrayOf(1, 2))
        assertTrue(
            "byteArrayOf(1,3) must compare as greater than byteArrayOf(1,2)",
            a.compareTo(b) > 0
        )
    }

    /**
     * THE LOAD-BEARING UNSIGNED TEST.
     *
     * The implementation computes `(bytes[i] & 0xff) - (other.bytes[i] & 0xff)`.
     *
     * 0x80 as unsigned = 128; 0x7f as unsigned = 127 → 0x80 > 0x7f → compareTo returns positive.
     *
     * A SIGNED comparison would compute: (-128) - 127 = negative → WRONG ORDER.
     *
     * This test catches any Kotlin migration that drops the `& 0xff` mask.
     */
    @Test
    fun compareTo_unsignedComparison_0x80IsGreaterThan0x7f() {
        val highBit = ObvBytesKey(byteArrayOf(0x80.toByte()))  // signed: -128, unsigned: 128
        val belowHighBit = ObvBytesKey(byteArrayOf(0x7f.toByte()))  // signed: 127, unsigned: 127
        assertTrue(
            "0x80 (unsigned 128) must compare as GREATER than 0x7f (unsigned 127); " +
                    "a signed comparison would give the OPPOSITE result (-128 < 127)",
            highBit.compareTo(belowHighBit) > 0
        )
    }

    /**
     * Second unsigned-comparison pin:
     * 0xff as unsigned = 255; 0x00 as unsigned = 0 → 0xff > 0x00 → positive.
     * A signed comparison: (-1) - 0 = -1 → negative → WRONG ORDER.
     */
    @Test
    fun compareTo_unsignedComparison_0xffIsGreaterThan0x00() {
        val maxByte = ObvBytesKey(byteArrayOf(0xff.toByte()))   // signed: -1, unsigned: 255
        val zeroByte = ObvBytesKey(byteArrayOf(0x00.toByte()))  // signed: 0, unsigned: 0
        assertTrue(
            "0xff (unsigned 255) must compare as GREATER than 0x00 (unsigned 0); " +
                    "a signed comparison would give the OPPOSITE result (-1 < 0)",
            maxByte.compareTo(zeroByte) > 0
        )
    }

    /**
     * Asymmetry check within a same-length pair:
     * byteArrayOf(0x80.toByte(), 0x00) vs byteArrayOf(0x00, 0x80.toByte()).
     * First bytes differ: unsigned 0x80=128 > 0x00=0 → left side is greater.
     */
    @Test
    fun compareTo_unsignedComparison_asymmetryOnFirstByte() {
        val a = ObvBytesKey(byteArrayOf(0x80.toByte(), 0x00))
        val b = ObvBytesKey(byteArrayOf(0x00, 0x80.toByte()))
        assertTrue(
            "byteArrayOf(0x80, 0x00) must compare as greater than byteArrayOf(0x00, 0x80) " +
                    "because the first byte (unsigned) 0x80=128 > 0x00=0",
            a.compareTo(b) > 0
        )
    }

    /** compareTo of identical empty arrays must return 0. */
    @Test
    fun compareTo_emptyArrays_returnsZero() {
        val a = ObvBytesKey(byteArrayOf())
        val b = ObvBytesKey(byteArrayOf())
        assertEquals("compareTo of two empty arrays must return 0", 0, a.compareTo(b))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 4: Comparable interface integration — TreeSet ordering
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Multiple ObvBytesKey instances inserted into a TreeSet must be automatically
     * sorted by compareTo. Pin the expected order:
     *
     *   byteArrayOf(1)     → length 1, unsigned value 1
     *   byteArrayOf(2)     → length 1, unsigned value 2
     *   byteArrayOf(1, 2)  → length 2, always after any length-1 key
     *
     * Length wins, so byteArrayOf(1) < byteArrayOf(2) < byteArrayOf(1, 2).
     */
    @Test
    fun compareTo_treeSet_keysAreSortedByCompareTo() {
        val k1 = ObvBytesKey(byteArrayOf(1))
        val k2 = ObvBytesKey(byteArrayOf(2))
        val k3 = ObvBytesKey(byteArrayOf(1, 2))

        val set = TreeSet<ObvBytesKey>()
        // Insert in reversed order to confirm TreeSet does the sorting
        set.add(k3)
        set.add(k2)
        set.add(k1)

        val sorted = set.toList()
        assertArrayEquals(
            "TreeSet[0] must be byteArrayOf(1) — shortest, smallest unsigned value",
            byteArrayOf(1),
            sorted[0].getBytes()
        )
        assertArrayEquals(
            "TreeSet[1] must be byteArrayOf(2) — shortest, larger unsigned value",
            byteArrayOf(2),
            sorted[1].getBytes()
        )
        assertArrayEquals(
            "TreeSet[2] must be byteArrayOf(1, 2) — longest",
            byteArrayOf(1, 2),
            sorted[2].getBytes()
        )
    }

    /**
     * TreeSet treats compareTo==0 as equal and collapses duplicate-content keys.
     * Two ObvBytesKey instances with the same content must occupy a single slot.
     */
    @Test
    fun compareTo_treeSet_sameContentCollapsesToOneEntry() {
        val a = ObvBytesKey(byteArrayOf(5, 6, 7))
        val b = ObvBytesKey(byteArrayOf(5, 6, 7)) // different object, same content
        val set = TreeSet<ObvBytesKey>()
        set.add(a)
        set.add(b)
        assertEquals(
            "TreeSet must collapse two ObvBytesKey instances with the same content to one entry",
            1,
            set.size
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 5 & 6: Constructor stores byte[] by reference; getBytes() returns it
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * The constructor stores the byte[] BY REFERENCE — it does NOT clone the array.
     * Mutating the source array after construction must be reflected in the stored bytes.
     *
     * This pins the lack of defensive copying. If a future migration adds a defensive copy
     * (e.g. `this.bytes = bytes.clone()`), this test will fail — surfacing a semantic change.
     */
    @Test
    fun constructor_storesByteArrayByReference_mutationReflected() {
        val src = byteArrayOf(1, 2, 3)
        val key = ObvBytesKey(src)
        src[0] = 99.toByte() // mutate after construction
        assertEquals(
            "getBytes()[0] must reflect the mutation of the source array (no defensive copy)",
            99.toByte(),
            key.getBytes()[0]
        )
    }

    /**
     * getBytes() must return the SAME array reference that was passed to the constructor,
     * not a copy. Using assertSame to pin the reference identity.
     */
    @Test
    fun getBytes_returnsStoredReference() {
        val src = byteArrayOf(10, 20, 30)
        val key = ObvBytesKey(src)
        assertSame(
            "getBytes() must return the exact same array reference passed to the constructor",
            src,
            key.getBytes()
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 7: ObvBytesKey.KeySerializer — map key serialization
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * When ObvBytesKey is used as a map key with @JsonSerialize(keyUsing = KeySerializer),
     * Jackson must write a Base64-encoded string as the JSON field name.
     *
     * We verify this by checking that the JSON contains a non-empty string field name,
     * not a raw decimal representation of the bytes.
     */
    @Test
    fun keySerializer_writesBase64EncodedFieldName() {
        val bytes = byteArrayOf(1, 2, 3)
        val wrapper = MapKeyWrapper()
        wrapper.data[ObvBytesKey(bytes)] = "value"

        val json = mapper.writeValueAsString(wrapper)

        // The key must be the Base64 encoding of [1, 2, 3] in Jackson's default variant: "AQID"
        assertTrue(
            "KeySerializer must write the Base64 encoding \"AQID\" for byteArrayOf(1,2,3) as a field name; got: $json",
            json.contains("\"AQID\"")
        )
    }

    /**
     * KeySerializer must NOT write the raw bytes as an integer array or decimal string.
     */
    @Test
    fun keySerializer_doesNotWriteRawBytes() {
        val bytes = byteArrayOf(1, 2, 3)
        val wrapper = MapKeyWrapper()
        wrapper.data[ObvBytesKey(bytes)] = "value"

        val json = mapper.writeValueAsString(wrapper)

        assertFalse(
            "KeySerializer must not write raw decimal bytes like \"[1,2,3]\" as the key; got: $json",
            json.contains("[1,2,3]")
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 8: ObvBytesKey.KeyDeserializer — map key deserialization
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * When deserializing a JSON with a Base64-encoded field name via KeyDeserializer,
     * the resulting ObvBytesKey must contain the correctly decoded bytes.
     *
     * "AQID" in Jackson's default Base64 variant decodes to byteArrayOf(1, 2, 3).
     */
    @Test
    fun keyDeserializer_decodesBase64FieldNameToBytes() {
        // "AQID" is the standard Base64 encoding of byteArrayOf(1, 2, 3)
        val json = """{"data":{"AQID":"value"}}"""
        val wrapper = mapper.readValue(json, MapKeyWrapper::class.java)

        assertEquals("Deserialized map must contain exactly one entry", 1, wrapper.data.size)
        val key = wrapper.data.keys.first()
        assertArrayEquals(
            "KeyDeserializer must decode \"AQID\" back to byteArrayOf(1, 2, 3)",
            byteArrayOf(1, 2, 3),
            key.getBytes()
        )
        assertEquals("Map value must be preserved after deserialization", "value", wrapper.data[key])
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 9: ObvBytesKey.Serializer / Deserializer — top-level value
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * The value Serializer must write the bytes as a Base64-encoded JSON string.
     * byteArrayOf(1, 2, 3) → "AQID" in Jackson's default Base64 variant.
     */
    @Test
    fun serializer_writesBase64EncodedString() {
        val key = ObvBytesKey(byteArrayOf(1, 2, 3))
        val json = mapper.writeValueAsString(key)
        assertEquals(
            "Serializer must produce a JSON string of the Base64 encoding of the bytes",
            "\"AQID\"",
            json
        )
    }

    /**
     * The value Deserializer must decode a Base64-encoded JSON string back to bytes.
     * "AQID" → byteArrayOf(1, 2, 3).
     */
    @Test
    fun deserializer_decodesBase64StringToBytes() {
        val key = mapper.readValue("\"AQID\"", ObvBytesKey::class.java)
        assertArrayEquals(
            "Deserializer must decode the Base64 string \"AQID\" back to byteArrayOf(1, 2, 3)",
            byteArrayOf(1, 2, 3),
            key.getBytes()
        )
    }

    /**
     * Empty byte array serializes to the empty-string Base64 representation.
     */
    @Test
    fun serializer_emptyByteArray_writesEmptyBase64() {
        val key = ObvBytesKey(byteArrayOf())
        val json = mapper.writeValueAsString(key)
        assertEquals(
            "Serializer must produce \"\" for an empty byte array",
            "\"\"",
            json
        )
    }

    /**
     * Deserializing the empty-string Base64 must yield an empty byte array.
     */
    @Test
    fun deserializer_emptyBase64String_producesEmptyByteArray() {
        val key = mapper.readValue("\"\"", ObvBytesKey::class.java)
        assertArrayEquals(
            "Deserializer must produce an empty byte array for an empty Base64 string",
            byteArrayOf(),
            key.getBytes()
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Group 10: Full round-trip — HashMap<ObvBytesKey, ObvBytesKey>
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * A HashMap<ObvBytesKey, ObvBytesKey> with multiple entries must survive a full
     * serialize → deserialize cycle with all keys and values intact.
     *
     * This exercises KeySerializer + KeyDeserializer (for the map key) and
     * Serializer + Deserializer (for the map value, via contentUsing annotation on the value field).
     * The MapKeyValueWrapper uses @JsonSerialize(keyUsing=KeySerializer) for keys, and the
     * ObjectMapper's SimpleModule provides the value (de)serializer.
     */
    @Test
    fun jacksonRoundTrip_hashMapKeyAndValue_allEntriesSurvive() {
        val original = MapKeyValueWrapper()
        original.data[ObvBytesKey(byteArrayOf(1, 2, 3))] = ObvBytesKey(byteArrayOf(10, 20, 30))
        original.data[ObvBytesKey(byteArrayOf(4, 5))] = ObvBytesKey(byteArrayOf(40, 50))
        original.data[ObvBytesKey(byteArrayOf(0xff.toByte()))] = ObvBytesKey(byteArrayOf(0x00))

        val json = mapper.writeValueAsString(original)
        val restored = mapper.readValue(json, MapKeyValueWrapper::class.java)

        assertEquals(
            "Restored map must contain the same number of entries as the original",
            original.data.size,
            restored.data.size
        )

        for ((originalKey, originalValue) in original.data) {
            val restoredValue = restored.data[originalKey]
            assertArrayEquals(
                "Value for key ${originalKey.getBytes().contentToString()} must survive round-trip",
                originalValue.getBytes(),
                restoredValue?.getBytes()
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Additional: HashMap usage (equals + hashCode integration)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two ObvBytesKey instances with the same content must resolve to the SAME HashMap entry.
     * This tests that equals + hashCode are consistent for HashMap lookup.
     */
    @Test
    fun hashMap_lookupByEqualContent_returnsCorrectValue() {
        val insertKey = ObvBytesKey(byteArrayOf(1, 2, 3))
        val lookupKey = ObvBytesKey(byteArrayOf(1, 2, 3)) // same content, different object

        val map = HashMap<ObvBytesKey, String>()
        map[insertKey] = "found"

        assertEquals(
            "Looking up a key by content-equal ObvBytesKey must find the original entry",
            "found",
            map[lookupKey]
        )
    }

    /**
     * Two distinct-content ObvBytesKey instances must not collide in a HashMap.
     */
    @Test
    fun hashMap_distinctContentKeys_doNotCollide() {
        val k1 = ObvBytesKey(byteArrayOf(1, 2, 3))
        val k2 = ObvBytesKey(byteArrayOf(4, 5, 6))

        val map = HashMap<ObvBytesKey, String>()
        map[k1] = "alpha"
        map[k2] = "beta"

        assertEquals("Map must contain two separate entries for distinct keys", 2, map.size)
        assertEquals("alpha", map[k1])
        assertEquals("beta", map[k2])
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Additional: hashCode is different for different content (collision check)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Two instances with different content must produce different hashCodes.
     * byteArrayOf(1,2,3) and byteArrayOf(4,5,6) are verified to have distinct
     * Arrays.hashCode results.
     */
    @Test
    fun hashCode_differentContent_hasDifferentHashCode() {
        val a = ObvBytesKey(byteArrayOf(1, 2, 3))
        val b = ObvBytesKey(byteArrayOf(4, 5, 6))
        assertNotEquals(
            "Different ObvBytesKey content must produce different hashCodes",
            a.hashCode(),
            b.hashCode()
        )
    }
}
