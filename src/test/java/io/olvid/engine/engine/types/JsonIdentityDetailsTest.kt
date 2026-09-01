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
import io.olvid.engine.datatypes.ObvBase64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Method

/**
 * Characterization tests for [JsonIdentityDetails].
 *
 * This is the most complex Jackson DTO in the engine, combining:
 *  - @JsonProperty wire-key remapping (first_name, last_name, custom_fields, signed_user_details)
 *  - @JsonIgnoreProperties(ignoreUnknown = true) for forward-compatibility
 *  - @JsonIgnore on computed/derived methods so they are not serialized
 *  - nullOrTrim() private helper called by 4-arg constructor and four setters
 *  - formatDisplayName() dispatching across 7 format-string constants
 *  - Custom equals() checking signedUserDetails only by null-ness and JWT "kid" header value
 *  - fieldsAreTheSame() which ignores signedUserDetails entirely
 *  - firstAndLastNamesAreTheSame() comparing only firstName + lastName
 *  - static joinNames() helper for name ordering and uppercasing
 *  - static joinCompany() private helper (observable via formatPositionAndCompany)
 *  - getSignatureKid() private static method for JWT kid extraction (tested via reflection)
 *
 * A Kotlin migration that changes any of these contracts will be caught here.
 */
class JsonIdentityDetailsTest {

    private lateinit var mapper: ObjectMapper

    @Before
    fun setUp() {
        mapper = ObjectMapper()
    }

    // ── Helper builders ───────────────────────────────────────────────────────

    /** Full instance with all four name/company/position fields set. */
    private fun fullInstance(): JsonIdentityDetails =
        JsonIdentityDetails("Alice", "Smith", "Acme Corp", "Engineer")

    /**
     * Build a JWT-style signature string with the given kid value encoded in the header.
     * Structure: base64({"kid":"<kid>"}).whatever
     */
    private fun jwtWithKid(kid: String): String {
        val header = """{"kid":"$kid"}"""
        val encodedHeader = ObvBase64.encode(header.toByteArray(Charsets.UTF_8))
        return "$encodedHeader.payload.signature"
    }

    // ── Group 1: WIRE-FORMAT pin (@JsonProperty mappings) ────────────────────

    @Test
    fun testSerializedJsonContainsWireKey_first_name() {
        val json = mapper.writeValueAsString(fullInstance())
        assertTrue("Expected wire key \"first_name\" in serialized JSON; got: $json", json.contains("\"first_name\""))
    }

    @Test
    fun testSerializedJsonContainsWireKey_last_name() {
        val json = mapper.writeValueAsString(fullInstance())
        assertTrue("Expected wire key \"last_name\" in serialized JSON; got: $json", json.contains("\"last_name\""))
    }

    @Test
    fun testSerializedJsonContainsWireKey_custom_fields_whenSet() {
        val instance = fullInstance()
        instance.customFields = hashMapOf("dept" to "R&D")
        val json = mapper.writeValueAsString(instance)
        assertTrue("Expected wire key \"custom_fields\" in serialized JSON; got: $json", json.contains("\"custom_fields\""))
    }

    @Test
    fun testSerializedJsonContainsWireKey_signed_user_details_whenSet() {
        val instance = fullInstance()
        instance.signedUserDetails = "some.jwt.token"
        val json = mapper.writeValueAsString(instance)
        assertTrue("Expected wire key \"signed_user_details\" in serialized JSON; got: $json", json.contains("\"signed_user_details\""))
    }

    @Test
    fun testSerializedJsonContainsDefaultKey_company() {
        val json = mapper.writeValueAsString(fullInstance())
        assertTrue("Expected key \"company\" in serialized JSON; got: $json", json.contains("\"company\""))
    }

    @Test
    fun testSerializedJsonContainsDefaultKey_position() {
        val json = mapper.writeValueAsString(fullInstance())
        assertTrue("Expected key \"position\" in serialized JSON; got: $json", json.contains("\"position\""))
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_firstName() {
        val json = mapper.writeValueAsString(fullInstance())
        assertFalse("Java field name \"firstName\" must not appear in JSON; got: $json", json.contains("\"firstName\""))
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_lastName() {
        val json = mapper.writeValueAsString(fullInstance())
        assertFalse("Java field name \"lastName\" must not appear in JSON; got: $json", json.contains("\"lastName\""))
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_customFields() {
        val instance = fullInstance()
        instance.customFields = hashMapOf("key" to "value")
        val json = mapper.writeValueAsString(instance)
        assertFalse("Java field name \"customFields\" must not appear in JSON; got: $json", json.contains("\"customFields\""))
    }

    @Test
    fun testSerializedJsonDoesNotContainJavaFieldName_signedUserDetails() {
        val instance = fullInstance()
        instance.signedUserDetails = "jwt.token"
        val json = mapper.writeValueAsString(instance)
        assertFalse("Java field name \"signedUserDetails\" must not appear in JSON; got: $json", json.contains("\"signedUserDetails\""))
    }

    @Test
    fun testDeserializationFromWireJson_allFieldsRoundTrip() {
        val wireJson = """
            {
                "first_name": "Bob",
                "last_name": "Jones",
                "company": "TechCorp",
                "position": "Director",
                "custom_fields": {"team": "infra"},
                "signed_user_details": "header.payload.sig"
            }
        """.trimIndent()
        val deserialized = mapper.readValue(wireJson, JsonIdentityDetails::class.java)

        assertEquals("first_name wire key must map to firstName", "Bob", deserialized.firstName)
        assertEquals("last_name wire key must map to lastName", "Jones", deserialized.lastName)
        assertEquals("company wire key must map to company", "TechCorp", deserialized.company)
        assertEquals("position wire key must map to position", "Director", deserialized.position)
        assertNotNull("custom_fields wire key must map to customFields", deserialized.customFields)
        assertEquals("customFields value must survive deserialization", "infra", deserialized.customFields!!["team"])
        assertEquals("signed_user_details wire key must map to signedUserDetails", "header.payload.sig", deserialized.signedUserDetails)
    }

    @Test
    fun testFullRoundTrip_allFieldsPreserved() {
        val original = fullInstance()
        original.customFields = hashMapOf("role" to "admin")
        original.signedUserDetails = "a.b.c"

        val json = mapper.writeValueAsString(original)
        val deserialized = mapper.readValue(json, JsonIdentityDetails::class.java)

        assertEquals("firstName must survive round-trip", original.firstName, deserialized.firstName)
        assertEquals("lastName must survive round-trip", original.lastName, deserialized.lastName)
        assertEquals("company must survive round-trip", original.company, deserialized.company)
        assertEquals("position must survive round-trip", original.position, deserialized.position)
        assertEquals("customFields must survive round-trip", original.customFields, deserialized.customFields)
        assertEquals("signedUserDetails must survive round-trip", original.signedUserDetails, deserialized.signedUserDetails)
    }

    // ── Group 2: @JsonIgnore — computed methods must not appear in JSON ────────

    @Test
    fun testJsonIgnore_isEmptyDoesNotAppearInSerializedJson() {
        val json = mapper.writeValueAsString(fullInstance())
        assertFalse("@JsonIgnore isEmpty() must not appear as a key in JSON; got: $json", json.contains("\"empty\""))
        assertFalse("@JsonIgnore isEmpty() must not appear as a key in JSON; got: $json", json.contains("\"isEmpty\""))
    }

    // ── Group 3: @JsonIgnoreProperties(ignoreUnknown = true) contract ─────────

    @Test
    fun testDeserializationIgnoresUnknownFields() {
        val wireJson = """
            {
                "first_name": "Carol",
                "last_name": "White",
                "unknownFutureField": "some-value",
                "anotherNewField": 999
            }
        """.trimIndent()
        // Must not throw
        val deserialized = mapper.readValue(wireJson, JsonIdentityDetails::class.java)
        assertEquals("Known field first_name must still be mapped despite extra fields", "Carol", deserialized.firstName)
        assertEquals("Known field last_name must still be mapped despite extra fields", "White", deserialized.lastName)
    }

    // ── Group 4: nullOrTrim() behavior via setters ───────────────────────────

    @Test
    fun testNullOrTrim_emptyStringBecomesNull_viaSetFirstName() {
        val instance = JsonIdentityDetails()
        instance.setFirstName("")
        assertNull("Empty string must become null via setFirstName", instance.firstName)
    }

    @Test
    fun testNullOrTrim_whitespaceOnlyBecomesNull_viaSetLastName() {
        val instance = JsonIdentityDetails()
        instance.setLastName("   ")
        assertNull("Whitespace-only string must become null via setLastName", instance.lastName)
    }

    @Test
    fun testNullOrTrim_paddedStringIsTrimmed_viaSetFirstName() {
        val instance = JsonIdentityDetails()
        instance.setFirstName("  hello  ")
        assertEquals("Padded string must be trimmed to \"hello\" via setFirstName", "hello", instance.firstName)
    }

    @Test
    fun testNullOrTrim_nullRemainsNull_viaSetCompany() {
        val instance = JsonIdentityDetails()
        instance.setCompany("initial")
        instance.setCompany(null)
        assertNull("null input must remain null via setCompany", instance.company)
    }

    @Test
    fun testNullOrTrim_singleCharNoOp_viaSetPosition() {
        val instance = JsonIdentityDetails()
        instance.setPosition("x")
        assertEquals("Single char string must be unchanged via setPosition", "x", instance.position)
    }

    // ── Group 5: nullOrTrim applied at correct call sites ────────────────────

    @Test
    fun testFourArgConstructor_appliesNullOrTrimToFirstName() {
        val instance = JsonIdentityDetails("  trimmed  ", "Last", null, null)
        assertEquals("4-arg constructor must trim firstName", "trimmed", instance.firstName)
    }

    @Test
    fun testFourArgConstructor_appliesNullOrTrimToLastName() {
        val instance = JsonIdentityDetails("First", "  ", null, null)
        assertNull("4-arg constructor must convert whitespace-only lastName to null", instance.lastName)
    }

    @Test
    fun testFourArgConstructor_appliesNullOrTrimToCompany() {
        val instance = JsonIdentityDetails("First", "Last", "", null)
        assertNull("4-arg constructor must convert empty company to null", instance.company)
    }

    @Test
    fun testFourArgConstructor_appliesNullOrTrimToPosition() {
        val instance = JsonIdentityDetails("First", "Last", null, "  eng  ")
        assertEquals("4-arg constructor must trim position", "eng", instance.position)
    }

    @Test
    fun testSetCustomFields_doesNotApplyNullOrTrim_keepsAsIs() {
        val instance = JsonIdentityDetails()
        val fields = HashMap<String?, String?>().also { it["key"] = "  value with spaces  " }
        instance.customFields = fields
        // setCustomFields must NOT trim values
        assertEquals("setCustomFields must not trim map values", "  value with spaces  ", instance.customFields!!["key"])
    }

    @Test
    fun testSetSignedUserDetails_doesNotApplyNullOrTrim_keepsWhitespace() {
        val instance = JsonIdentityDetails()
        instance.signedUserDetails = "  padded.jwt  "
        // setSignedUserDetails must NOT trim the string
        assertEquals("setSignedUserDetails must not trim the JWT string", "  padded.jwt  ", instance.signedUserDetails)
    }

    // ── Group 6: FORMAT_STRING_* constants — exact values (stored in settings) ─

    @Test
    fun testConstant_FORMAT_STRING_FIRST_LAST() {
        assertEquals("%f %l", JsonIdentityDetails.FORMAT_STRING_FIRST_LAST)
    }

    @Test
    fun testConstant_FORMAT_STRING_FIRST_LAST_COMPANY() {
        assertEquals("%f %l (%c)", JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_COMPANY)
    }

    @Test
    fun testConstant_FORMAT_STRING_FIRST_LAST_POSITION_COMPANY() {
        assertEquals("%f %l (%p @ %c)", JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_POSITION_COMPANY)
    }

    @Test
    fun testConstant_FORMAT_STRING_LAST_FIRST() {
        assertEquals("%l %f", JsonIdentityDetails.FORMAT_STRING_LAST_FIRST)
    }

    @Test
    fun testConstant_FORMAT_STRING_LAST_FIRST_COMPANY() {
        assertEquals("%l %f (%c)", JsonIdentityDetails.FORMAT_STRING_LAST_FIRST_COMPANY)
    }

    @Test
    fun testConstant_FORMAT_STRING_LAST_FIRST_POSITION_COMPANY() {
        assertEquals("%l %f (%p @ %c)", JsonIdentityDetails.FORMAT_STRING_LAST_FIRST_POSITION_COMPANY)
    }

    @Test
    fun testConstant_FORMAT_STRING_FOR_SEARCH() {
        assertEquals("%f %l %p %c", JsonIdentityDetails.FORMAT_STRING_FOR_SEARCH)
    }

    // ── Group 7: formatDisplayName() dispatch over 7 format strings ──────────

    @Test
    fun testFormatDisplayName_FIRST_LAST() {
        val instance = fullInstance()
        assertEquals(
            "FIRST_LAST must produce 'firstName lastName'",
            "Alice Smith",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST, false)
        )
    }

    @Test
    fun testFormatDisplayName_FIRST_LAST_COMPANY() {
        val instance = fullInstance()
        assertEquals(
            "FIRST_LAST_COMPANY must produce 'firstName lastName (company)'",
            "Alice Smith (Acme Corp)",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_COMPANY, false)
        )
    }

    @Test
    fun testFormatDisplayName_FIRST_LAST_POSITION_COMPANY() {
        val instance = fullInstance()
        assertEquals(
            "FIRST_LAST_POSITION_COMPANY must produce 'firstName lastName (position @ company)'",
            "Alice Smith (Engineer @ Acme Corp)",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_POSITION_COMPANY, false)
        )
    }

    @Test
    fun testFormatDisplayName_LAST_FIRST() {
        val instance = fullInstance()
        assertEquals(
            "LAST_FIRST must produce 'lastName firstName'",
            "Smith Alice",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_LAST_FIRST, false)
        )
    }

    @Test
    fun testFormatDisplayName_LAST_FIRST_COMPANY() {
        val instance = fullInstance()
        assertEquals(
            "LAST_FIRST_COMPANY must produce 'lastName firstName (company)'",
            "Smith Alice (Acme Corp)",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_LAST_FIRST_COMPANY, false)
        )
    }

    @Test
    fun testFormatDisplayName_LAST_FIRST_POSITION_COMPANY() {
        val instance = fullInstance()
        assertEquals(
            "LAST_FIRST_POSITION_COMPANY must produce 'lastName firstName (position @ company)'",
            "Smith Alice (Engineer @ Acme Corp)",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_LAST_FIRST_POSITION_COMPANY, false)
        )
    }

    @Test
    fun testFormatDisplayName_FOR_SEARCH() {
        val instance = fullInstance()
        assertEquals(
            "FOR_SEARCH must produce 'firstName lastName position @ company'",
            "Alice Smith Engineer @ Acme Corp",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FOR_SEARCH, false)
        )
    }

    @Test
    fun testFormatDisplayName_unknownFormatFallsThrough_toFirstLast() {
        val instance = fullInstance()
        assertEquals(
            "Unknown format string must fall through to FIRST_LAST output",
            "Alice Smith",
            instance.formatDisplayName("unknown-format-string", false)
        )
    }

    @Test
    fun testFormatDisplayName_uppercaseLastName_FIRST_LAST() {
        val instance = fullInstance()
        assertEquals(
            "uppercaseLastName=true with FIRST_LAST must uppercase the last name",
            "Alice SMITH",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST, true)
        )
    }

    @Test
    fun testFormatDisplayName_companyNull_FIRST_LAST_COMPANY_omitsParens() {
        val instance = JsonIdentityDetails("Alice", "Smith", null, "Engineer")
        assertEquals(
            "FIRST_LAST_COMPANY with company=null must omit the (...) clause",
            "Alice Smith",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_COMPANY, false)
        )
    }

    @Test
    fun testFormatDisplayName_positionNullCompanySet_FIRST_LAST_POSITION_COMPANY_showsOnlyCompany() {
        val instance = JsonIdentityDetails("Alice", "Smith", "Acme Corp", null)
        assertEquals(
            "FIRST_LAST_POSITION_COMPANY with position=null must show just '(company)'",
            "Alice Smith (Acme Corp)",
            instance.formatDisplayName(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST_POSITION_COMPANY, false)
        )
    }

    // ── Group 8: joinNames() public static helper ─────────────────────────────

    @Test
    fun testJoinNames_bothNull_returnsEmpty() {
        assertEquals("Both null must return empty string", "", JsonIdentityDetails.joinNames(null, null, false, false))
    }

    @Test
    fun testJoinNames_onlyFirstName_returnsFirstName() {
        assertEquals("Only firstName must return firstName", "Alice", JsonIdentityDetails.joinNames("Alice", null, false, false))
    }

    @Test
    fun testJoinNames_onlyLastName_returnsLastName() {
        assertEquals("Only lastName must return lastName", "Smith", JsonIdentityDetails.joinNames(null, "Smith", false, false))
    }

    @Test
    fun testJoinNames_both_lastFirstFalse_returnsFirstLast() {
        assertEquals("lastFirst=false must produce 'firstName lastName'", "Alice Smith", JsonIdentityDetails.joinNames("Alice", "Smith", false, false))
    }

    @Test
    fun testJoinNames_both_lastFirstTrue_returnsLastFirst() {
        assertEquals("lastFirst=true must produce 'lastName firstName'", "Smith Alice", JsonIdentityDetails.joinNames("Alice", "Smith", true, false))
    }

    @Test
    fun testJoinNames_both_uppercaseLastTrue_lastNameUppercased() {
        assertEquals("uppercaseLast=true must uppercase lastName", "Alice SMITH", JsonIdentityDetails.joinNames("Alice", "Smith", false, true))
    }

    @Test
    fun testJoinNames_both_lastFirstTrue_uppercaseLastTrue() {
        assertEquals("lastFirst=true + uppercaseLast=true must produce 'LASTNAME firstName'", "SMITH Alice", JsonIdentityDetails.joinNames("Alice", "Smith", true, true))
    }

    // ── Group 9: joinCompany() via formatPositionAndCompany() ────────────────

    @Test
    fun testJoinCompany_bothNull_returnsNull() {
        val instance = JsonIdentityDetails("F", "L", null, null)
        assertNull("Both position and company null must return null", instance.formatPositionAndCompany(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST))
    }

    @Test
    fun testJoinCompany_onlyPosition_returnsPosition() {
        val instance = JsonIdentityDetails("F", "L", null, "Engineer")
        assertEquals("Only position must return position", "Engineer", instance.formatPositionAndCompany(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST))
    }

    @Test
    fun testJoinCompany_onlyCompany_returnsCompany() {
        val instance = JsonIdentityDetails("F", "L", "Acme", null)
        assertEquals("Only company must return company", "Acme", instance.formatPositionAndCompany(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST))
    }

    @Test
    fun testJoinCompany_both_returnsPositionAtCompany() {
        val instance = JsonIdentityDetails("F", "L", "Acme", "Engineer")
        assertEquals("Both set must return 'position @ company'", "Engineer @ Acme", instance.formatPositionAndCompany(JsonIdentityDetails.FORMAT_STRING_FIRST_LAST))
    }

    // ── Group 10: isEmpty() ───────────────────────────────────────────────────

    @Test
    fun testIsEmpty_allFieldsNull_returnsTrue() {
        val instance = JsonIdentityDetails()
        assertTrue("All fields null must return isEmpty() == true", instance.isEmpty())
    }

    @Test
    fun testIsEmpty_onlyCompanySet_returnsTrue() {
        val instance = JsonIdentityDetails()
        instance.company = "Acme"
        assertTrue("Only company set (no firstName/lastName) must still return isEmpty() == true", instance.isEmpty())
    }

    @Test
    fun testIsEmpty_firstNameSet_returnsFalse() {
        val instance = JsonIdentityDetails()
        instance.firstName = "Alice"
        assertFalse("firstName set must return isEmpty() == false", instance.isEmpty())
    }

    @Test
    fun testIsEmpty_lastNameSet_returnsFalse() {
        val instance = JsonIdentityDetails()
        instance.lastName = "Smith"
        assertFalse("lastName set must return isEmpty() == false", instance.isEmpty())
    }

    // ── Group 11: Custom equals() contract ───────────────────────────────────

    @Test
    fun testEquals_identicalFieldsBothSignedNull_returnsTrue() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        // signedUserDetails both null → equal
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("Identical fields + both signedUserDetails null must be equal", a.equals(b))
    }

    @Test
    fun testEquals_sameKid_differentSignedContent_returnsTrue() {
        val kid = "key-same"
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.signedUserDetails = jwtWithKid(kid)
        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.signedUserDetails = jwtWithKid(kid)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("Same kid in both JWTs must be equal regardless of payload", a.equals(b))
    }

    @Test
    fun testEquals_differentFirstName_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        val b = JsonIdentityDetails("Bob", "Smith", "Acme", "Eng")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Different firstName must not be equal", a.equals(b))
    }

    @Test
    fun testEquals_oneSignedNullOtherNonNull_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.signedUserDetails = jwtWithKid("some-key")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("One signedUserDetails null and the other non-null must not be equal", a.equals(b))
    }

    @Test
    fun testEquals_differentKid_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.signedUserDetails = jwtWithKid("key1")
        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.signedUserDetails = jwtWithKid("key2")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Different kid in JWT headers must not be equal", a.equals(b))
    }

    @Test
    fun testEquals_differentCustomFields_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.customFields = hashMapOf("k" to "v1")
        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.customFields = hashMapOf("k" to "v2")
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("Different customFields must not be equal", a.equals(b))
    }

    @Test
    fun testEquals_null_returnsFalse() {
        val a = fullInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(null) must return false", a.equals(null))
    }

    @Test
    fun testEquals_differentType_returnsFalse() {
        val a = fullInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals(String) must return false", a.equals("not a JsonIdentityDetails"))
    }

    @Test
    fun testEquals_reflexive() {
        val a = fullInstance()
        @Suppress("ReplaceCallWithBinaryOperator")
        assertTrue("equals must be reflexive: a.equals(a) must be true", a.equals(a))
    }

    // ── Group 12: fieldsAreTheSame() vs equals() asymmetry ───────────────────

    @Test
    fun testFieldsAreTheSame_ignoringSignedUserDetails_returnsTrueWhenSignedDiffers() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.signedUserDetails = jwtWithKid("key1")

        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.signedUserDetails = null

        assertTrue(
            "fieldsAreTheSame() must return true when only signedUserDetails differs (null vs non-null)",
            a.fieldsAreTheSame(b)
        )
    }

    @Test
    fun testEqualsVsFieldsAreTheSame_asymmetry_signedNullVsNonNull() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.signedUserDetails = jwtWithKid("key1")

        val b = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        b.signedUserDetails = null

        // fieldsAreTheSame ignores signedUserDetails → true
        assertTrue("fieldsAreTheSame() must ignore signedUserDetails", a.fieldsAreTheSame(b))
        // equals checks signedUserDetails null-ness → false (one null, one non-null)
        @Suppress("ReplaceCallWithBinaryOperator")
        assertFalse("equals() must be false when one signedUserDetails is null and the other is not", a.equals(b))
    }

    // ── Group 13: firstAndLastNamesAreTheSame() ───────────────────────────────

    @Test
    fun testFirstAndLastNamesAreTheSame_sameNames_differentOtherFields_returnsTrue() {
        val a = JsonIdentityDetails("Alice", "Smith", "Acme", "Eng")
        a.signedUserDetails = jwtWithKid("key1")
        val b = JsonIdentityDetails("Alice", "Smith", "OtherCorp", "Manager")
        b.signedUserDetails = null
        assertTrue(
            "firstAndLastNamesAreTheSame() must return true for same first+last even if other fields differ",
            a.firstAndLastNamesAreTheSame(b)
        )
    }

    @Test
    fun testFirstAndLastNamesAreTheSame_differentFirstName_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", null, null)
        val b = JsonIdentityDetails("Bob", "Smith", null, null)
        assertFalse("Different firstName must make firstAndLastNamesAreTheSame() false", a.firstAndLastNamesAreTheSame(b))
    }

    @Test
    fun testFirstAndLastNamesAreTheSame_differentLastName_returnsFalse() {
        val a = JsonIdentityDetails("Alice", "Smith", null, null)
        val b = JsonIdentityDetails("Alice", "Jones", null, null)
        assertFalse("Different lastName must make firstAndLastNamesAreTheSame() false", a.firstAndLastNamesAreTheSame(b))
    }

    // ── Group 14: getSignatureKid() private static — via reflection ───────────

    /**
     * Obtains the private static getSignatureKid method via reflection and invokes it.
     * Signature: getSignatureKid(ObjectMapper, String) : String?
     */
    private fun invokeGetSignatureKid(signature: String?): String? {
        val companionClass = Class.forName("io.olvid.engine.engine.types.JsonIdentityDetails\$Companion")
        val method: Method = companionClass.getDeclaredMethod(
            "getSignatureKid",
            ObjectMapper::class.java,
            String::class.java
        )
        method.isAccessible = true
        val companion = JsonIdentityDetails::class.java.getField("Companion").get(null)
        @Suppress("UNCHECKED_CAST")
        return method.invoke(companion, mapper, signature) as String?
    }

    @Test
    fun testGetSignatureKid_nullSignature_returnsNull() {
        assertNull("null signature must return null kid", invokeGetSignatureKid(null))
    }

    @Test
    fun testGetSignatureKid_noDot_returnsNull() {
        assertNull("Signature without '.' must return null kid", invokeGetSignatureKid("nodothere"))
    }

    @Test
    fun testGetSignatureKid_validBase64JsonWithKid_returnsKid() {
        val kid = "my-test-key"
        val header = """{"kid":"$kid"}"""
        val encodedHeader = ObvBase64.encode(header.toByteArray(Charsets.UTF_8))
        val signature = "$encodedHeader.payload"
        assertEquals("Valid JWT header with kid must return kid value", kid, invokeGetSignatureKid(signature))
    }

    @Test
    fun testGetSignatureKid_validBase64JsonWithoutKid_returnsNull() {
        val header = """{"alg":"RS256","typ":"JWT"}"""
        val encodedHeader = ObvBase64.encode(header.toByteArray(Charsets.UTF_8))
        val signature = "$encodedHeader.payload"
        assertNull("Valid JWT header without kid field must return null", invokeGetSignatureKid(signature))
    }

    @Test
    fun testGetSignatureKid_nonBase64Garbage_returnsNull() {
        // The header portion contains characters that will fail ObvBase64 or JSON parsing
        val signature = "!!!not-valid-base64!!!.payload"
        assertNull("Non-base64 header must return null without throwing", invokeGetSignatureKid(signature))
    }

    // ── Group 15: No-arg constructor ─────────────────────────────────────────

    @Test
    fun testNoArgConstructor_allFieldsNull() {
        val instance = JsonIdentityDetails()
        assertNull("firstName must be null after no-arg construction", instance.firstName)
        assertNull("lastName must be null after no-arg construction", instance.lastName)
        assertNull("company must be null after no-arg construction", instance.company)
        assertNull("position must be null after no-arg construction", instance.position)
        assertNull("signedUserDetails must be null after no-arg construction", instance.signedUserDetails)
        assertNull("customFields must be null after no-arg construction", instance.customFields)
    }
}
