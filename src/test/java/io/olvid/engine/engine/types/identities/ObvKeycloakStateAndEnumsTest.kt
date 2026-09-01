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

import io.olvid.engine.Logger
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for three types in engine/types/identities/:
 *
 *  - [ObvContactActiveOrInactiveReason]  — a simple two-constant Java enum
 *  - [ObvKeycloakAuthType]               — a Java sealed interface with two inner classes
 *  - [ObvKeycloakState]                  — a DTO with an Encoded wire-format round-trip
 *
 * JUnit 4 doesn't support @Nested, so sections are separated by comments.
 */
class ObvKeycloakStateAndEnumsTest {

    // ─── Minimal JWK JSON literals used throughout the suite ──────────────────
    // An RSA public key is the simplest JWK that jose4j accepts without complaints.
    private val RSA_JWK_JSON = """{
        "kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB"
    }"""

    private val JWKS_JSON = """{"keys":[$RSA_JWK_JSON]}"""

    private lateinit var testJwks: JsonWebKeySet
    private lateinit var testSignatureKey: JsonWebKey

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        testJwks = JsonWebKeySet(JWKS_JSON)
        testSignatureKey = JsonWebKey.Factory.newJwk(RSA_JWK_JSON)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Section 1 — ObvContactActiveOrInactiveReason (Java enum, 2 constants)
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    fun contactReason_forcefullyUnblocked_constantExists() {
        // Pin that the FORCEFULLY_UNBLOCKED constant exists under its exact name.
        // A Kotlin migration that renames it would break callers that switch on this enum.
        val reason = ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED
        assertNotNull(reason)
    }

    @Test
    fun contactReason_revoked_constantExists() {
        // Pin that the REVOKED constant exists under its exact name.
        val reason = ObvContactActiveOrInactiveReason.REVOKED
        assertNotNull(reason)
    }

    @Test
    fun contactReason_exactlyTwoConstants() {
        // Pin the total count. Adding or removing a constant is a wire-format break
        // because callers enumerate them via values() for notification dispatch.
        assertEquals(
            "ObvContactActiveOrInactiveReason must have exactly 2 constants",
            2,
            ObvContactActiveOrInactiveReason.entries.size,
        )
    }

    @Test
    fun contactReason_ordinalForcefullyUnblocked_isZero() {
        // Ordinal order is declaration order. Pin it so a reorder is caught.
        assertEquals(0, ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED.ordinal)
    }

    @Test
    fun contactReason_ordinalRevoked_isOne() {
        assertEquals(1, ObvContactActiveOrInactiveReason.REVOKED.ordinal)
    }

    @Test
    fun contactReason_nameMatchesDeclaration_forcefullyUnblocked() {
        // Pin the exact name string (used in logs and potentially serialization).
        assertEquals("FORCEFULLY_UNBLOCKED", ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED.name)
    }

    @Test
    fun contactReason_nameMatchesDeclaration_revoked() {
        assertEquals("REVOKED", ObvContactActiveOrInactiveReason.REVOKED.name)
    }

    @Test
    fun contactReason_valueOfRoundtrip_forcefullyUnblocked() {
        val parsed = ObvContactActiveOrInactiveReason.valueOf("FORCEFULLY_UNBLOCKED")
        assertEquals(ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED, parsed)
    }

    @Test
    fun contactReason_valueOfRoundtrip_revoked() {
        val parsed = ObvContactActiveOrInactiveReason.valueOf("REVOKED")
        assertEquals(ObvContactActiveOrInactiveReason.REVOKED, parsed)
    }

    @Test
    fun contactReason_distinctConstants_areNotEqual() {
        assertFalse(
            ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED ==
                ObvContactActiveOrInactiveReason.REVOKED,
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Section 2 — ObvKeycloakAuthType (Java sealed interface, 2 inner classes)
    // ══════════════════════════════════════════════════════════════════════════
    // NOTE: ObvKeycloakAuthType is a sealed interface, NOT an enum. Its two
    // permitted subtypes are IdBased and OpenIdConnect — both final inner classes.
    // There is no values() / valueOf(); tests pin construction and field access.

    @Test
    fun authType_idBased_instantiates() {
        // IdBased is a no-arg final class; pin that construction succeeds.
        val idBased = ObvKeycloakAuthType.IdBased()
        assertNotNull(idBased)
    }

    @Test
    fun authType_idBased_implementsObvKeycloakAuthType() {
        val idBased = ObvKeycloakAuthType.IdBased()
        assertTrue(idBased is ObvKeycloakAuthType)
    }

    @Test
    fun authType_openIdConnect_instantiatesWithBothArgs() {
        val oidc = ObvKeycloakAuthType.OpenIdConnect("my-client-id", "my-secret")
        assertNotNull(oidc)
    }

    @Test
    fun authType_openIdConnect_implementsObvKeycloakAuthType() {
        val oidc = ObvKeycloakAuthType.OpenIdConnect("id", null)
        assertTrue(oidc is ObvKeycloakAuthType)
    }

    @Test
    fun authType_openIdConnect_storesClientId() {
        val oidc = ObvKeycloakAuthType.OpenIdConnect("client-123", null)
        assertEquals("client-123", oidc.clientId)
    }

    @Test
    fun authType_openIdConnect_storesClientSecret() {
        val oidc = ObvKeycloakAuthType.OpenIdConnect("id", "secret-xyz")
        assertEquals("secret-xyz", oidc.clientSecret)
    }

    @Test
    fun authType_openIdConnect_clientSecretMayBeNull() {
        // The comment in the source says "may be null for non-authenticated OIDC".
        val oidc = ObvKeycloakAuthType.OpenIdConnect("id", null)
        assertNull(oidc.clientSecret)
    }

    @Test
    fun authType_idBased_andOpenIdConnect_areDistinctTypes() {
        // Pattern-matching (instanceof) must distinguish them — this is how
        // ObvKeycloakState.encode() dispatches on auth type.
        val idBased: ObvKeycloakAuthType = ObvKeycloakAuthType.IdBased()
        val oidc: ObvKeycloakAuthType = ObvKeycloakAuthType.OpenIdConnect("id", null)
        assertFalse(idBased is ObvKeycloakAuthType.OpenIdConnect)
        assertFalse(oidc is ObvKeycloakAuthType.IdBased)
    }

    @Test
    fun authType_openIdConnect_clientIdFieldIsMutable() {
        // The field is declared `public String clientId` (not final) — verify mutation works.
        val oidc = ObvKeycloakAuthType.OpenIdConnect("original", null)
        oidc.clientId = "updated"
        assertEquals("updated", oidc.clientId)
    }

    @Test
    fun authType_openIdConnect_clientSecretFieldIsMutable() {
        val oidc = ObvKeycloakAuthType.OpenIdConnect("id", null)
        oidc.clientSecret = "new-secret"
        assertEquals("new-secret", oidc.clientSecret)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Section 3 — ObvKeycloakState (DTO with Encoded wire-format round-trip)
    // ══════════════════════════════════════════════════════════════════════════

    // ─── 3a. Constructor stores fields exactly ─────────────────────────────────

    @Test
    fun keycloakState_constructor_storesKeycloakServer() {
        val state = buildState()
        assertEquals("https://keycloak.example.com/auth", state.keycloakServer)
    }

    @Test
    fun keycloakState_constructor_storesSupportedAuthMethods_sameReference() {
        val authMethods = listOf<ObvKeycloakAuthType>(ObvKeycloakAuthType.IdBased())
        val state = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            authMethods,
            testJwks,
            testSignatureKey,
            "auth-state-token",
            false,
            "api-key-xyz",
            1_000_000L,
            2_000_000L,
        )
        assertSame(authMethods, state.supportedAuthenticationMethods)
    }

    @Test
    fun keycloakState_constructor_storesJwks_sameReference() {
        val state = buildState()
        assertSame(testJwks, state.jwks)
    }

    @Test
    fun keycloakState_constructor_storesSignatureKey_sameReference() {
        val state = buildState()
        assertSame(testSignatureKey, state.signatureKey)
    }

    @Test
    fun keycloakState_constructor_storesSerializedAuthState() {
        val state = buildState()
        assertEquals("auth-state-token", state.serializedAuthState)
    }

    @Test
    fun keycloakState_constructor_storesTransferRestricted_true() {
        val state = buildState(transferRestricted = true)
        assertTrue(state.transferRestricted)
    }

    @Test
    fun keycloakState_constructor_storesTransferRestricted_false() {
        val state = buildState(transferRestricted = false)
        assertFalse(state.transferRestricted)
    }

    @Test
    fun keycloakState_constructor_storesOwnApiKey() {
        val state = buildState()
        assertEquals("api-key-xyz", state.ownApiKey)
    }

    @Test
    fun keycloakState_constructor_storesLatestRevocationListTimestamp() {
        val state = buildState()
        assertEquals(1_000_000L, state.latestRevocationListTimestamp)
    }

    @Test
    fun keycloakState_constructor_storesLatestGroupUpdateTimestamp() {
        val state = buildState()
        assertEquals(2_000_000L, state.latestGroupUpdateTimestamp)
    }

    // ─── 3b. Public field accessibility ───────────────────────────────────────

    @Test
    fun keycloakState_allFieldsArePubliclyReadable() {
        // Pin that all documented public final fields are accessible without reflection.
        val state = buildState()
        assertNotNull(state.keycloakServer)
        assertNotNull(state.supportedAuthenticationMethods)
        assertNotNull(state.jwks)
        assertNotNull(state.signatureKey)
        assertNotNull(state.serializedAuthState)
        assertNotNull(state.ownApiKey)
    }

    // ─── 3c. encode() → of() full round-trip ──────────────────────────────────

    @Test
    fun keycloakState_roundTrip_keycloakServer_survivesEncoding() {
        val original = buildState()
        val restored = ObvKeycloakState.of(original.encode())
        assertEquals(original.keycloakServer, restored.keycloakServer)
    }

    @Test
    fun keycloakState_roundTrip_transferRestricted_true_survivesEncoding() {
        val original = buildState(transferRestricted = true)
        val restored = ObvKeycloakState.of(original.encode())
        assertTrue(restored.transferRestricted)
    }

    @Test
    fun keycloakState_roundTrip_transferRestricted_false_survivesEncoding() {
        val original = buildState(transferRestricted = false)
        val restored = ObvKeycloakState.of(original.encode())
        assertFalse(restored.transferRestricted)
    }

    @Test
    fun keycloakState_roundTrip_jwks_jsonRoundTrips() {
        // jwks survives encode/of via JSON serialization internally.
        // Pin by comparing the JSON representations (jose4j doesn't override equals).
        val original = buildState()
        val restored = ObvKeycloakState.of(original.encode())
        assertNotNull(restored.jwks)
        assertEquals(original.jwks!!.toJson(), restored.jwks!!.toJson())
    }

    @Test
    fun keycloakState_roundTrip_signatureKey_jsonRoundTrips() {
        val original = buildState()
        val restored = ObvKeycloakState.of(original.encode())
        assertNotNull(restored.signatureKey)
        assertEquals(original.signatureKey!!.toJson(), restored.signatureKey!!.toJson())
    }

    @Test
    fun keycloakState_roundTrip_oidcAuthMethod_clientId_survivesEncoding() {
        // When OpenIdConnect is in the list the clientId is encoded under "ci".
        val oidcMethod = ObvKeycloakAuthType.OpenIdConnect("my-client", "my-secret")
        val state = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            listOf(oidcMethod),
            testJwks,
            testSignatureKey,
            null,
            false,
            null,
            0L,
            0L,
        )
        val restored = ObvKeycloakState.of(state.encode())
        val restoredOidc = restored.supportedAuthenticationMethods
            .filterIsInstance<ObvKeycloakAuthType.OpenIdConnect>()
            .firstOrNull()
        assertNotNull("OpenIdConnect must survive encode/of round-trip", restoredOidc)
        assertEquals("my-client", restoredOidc!!.clientId)
    }

    @Test
    fun keycloakState_roundTrip_oidcAuthMethod_clientSecret_survivesEncoding() {
        val oidcMethod = ObvKeycloakAuthType.OpenIdConnect("my-client", "my-secret")
        val state = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            listOf(oidcMethod),
            testJwks,
            testSignatureKey,
            null,
            false,
            null,
            0L,
            0L,
        )
        val restored = ObvKeycloakState.of(state.encode())
        val restoredOidc = restored.supportedAuthenticationMethods
            .filterIsInstance<ObvKeycloakAuthType.OpenIdConnect>()
            .firstOrNull()
        assertNotNull(restoredOidc)
        assertEquals("my-secret", restoredOidc!!.clientSecret)
    }

    @Test
    fun keycloakState_roundTrip_idBasedAuthMethod_survivesEncoding() {
        val state = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            listOf(ObvKeycloakAuthType.IdBased()),
            testJwks,
            testSignatureKey,
            null,
            false,
            null,
            0L,
            0L,
        )
        val restored = ObvKeycloakState.of(state.encode())
        assertTrue(
            "IdBased must survive encode/of round-trip",
            restored.supportedAuthenticationMethods.any { it is ObvKeycloakAuthType.IdBased },
        )
    }

    // ─── 3d. Device-local fields are NOT in the encoded wire format ────────────
    // This is the most safety-critical constraint: ownApiKey, latestRevocationListTimestamp,
    // and latestGroupUpdateTimestamp must never cross to other devices via encoding.
    // serializedAuthState IS encoded (it's a device-bound auth token deliberately included).

    @Test
    fun keycloakState_ownApiKey_isNullAfterRoundTrip() {
        // ownApiKey is explicitly excluded from the encoded dict (see ObvKeycloakState.encode()).
        // of() always reconstructs it as null (hardcoded on the return line).
        val original = buildState(ownApiKey = "super-secret-api-key")
        val restored = ObvKeycloakState.of(original.encode())
        assertNull(
            "ownApiKey must be null after encode→of round-trip: it is a device-local field excluded from the wire format",
            restored.ownApiKey,
        )
    }

    @Test
    fun keycloakState_latestRevocationListTimestamp_isZeroAfterRoundTrip() {
        // latestRevocationListTimestamp is not encoded; of() hardcodes 0.
        val original = buildState(latestRevocationListTimestamp = 9_999_999L)
        val restored = ObvKeycloakState.of(original.encode())
        assertEquals(
            "latestRevocationListTimestamp must be reset to 0 after encode→of: it is a device-local field excluded from the wire format",
            0L,
            restored.latestRevocationListTimestamp,
        )
    }

    @Test
    fun keycloakState_latestGroupUpdateTimestamp_isZeroAfterRoundTrip() {
        // latestGroupUpdateTimestamp is not encoded; of() hardcodes 0.
        val original = buildState(latestGroupUpdateTimestamp = 8_888_888L)
        val restored = ObvKeycloakState.of(original.encode())
        assertEquals(
            "latestGroupUpdateTimestamp must be reset to 0 after encode→of: it is a device-local field excluded from the wire format",
            0L,
            restored.latestGroupUpdateTimestamp,
        )
    }

    @Test
    fun keycloakState_serializedAuthState_doesSurviveRoundTrip() {
        // Contrast with the three fields above: serializedAuthState IS in the encoded dict
        // (under key "sas") and IS reconstructed by of(). It is device-bound but deliberately
        // included so the auth token can be shared across the same device's encoding/decoding.
        val original = buildState(serializedAuthState = "my-auth-token")
        val restored = ObvKeycloakState.of(original.encode())
        assertEquals(
            "serializedAuthState must survive encode→of round-trip: it IS included in the wire format",
            "my-auth-token",
            restored.serializedAuthState,
        )
    }

    // ─── 3e. encode() layout pin — decode the Encoded result and verify content ─

    @Test
    fun keycloakState_encode_producesDecodableDictionary() {
        // The top-level Encoded returned by encode() must be a dictionary.
        val state = buildState()
        val encoded = state.encode()
        // decodeDictionary() throws DecodingException if the type byte is not 0x04 (DICTIONARY).
        val dict = encoded.decodeDictionary()
        assertNotNull(dict)
    }

    @Test
    fun keycloakState_encode_dictionaryContainsKeycloakServerKey() {
        val state = buildState()
        val dict = state.encode().decodeDictionary()
        val ksKey = io.olvid.engine.datatypes.DictionaryKey("ks")
        assertTrue(
            "Encoded dictionary must contain the 'ks' key for keycloakServer",
            dict.containsKey(ksKey),
        )
        assertEquals("https://keycloak.example.com/auth", dict[ksKey]!!.decodeString())
    }

    @Test
    fun keycloakState_encode_dictionaryContainsJwksKey() {
        val state = buildState()
        val dict = state.encode().decodeDictionary()
        val jwksKey = io.olvid.engine.datatypes.DictionaryKey("jwks")
        assertTrue("Encoded dictionary must contain the 'jwks' key", dict.containsKey(jwksKey))
    }

    @Test
    fun keycloakState_encode_dictionaryContainsSignatureKeyKey() {
        val state = buildState()
        val dict = state.encode().decodeDictionary()
        val skKey = io.olvid.engine.datatypes.DictionaryKey("sk")
        assertTrue("Encoded dictionary must contain the 'sk' key", dict.containsKey(skKey))
    }

    @Test
    fun keycloakState_encode_transferRestrictedTrue_addsKeyToDictionary() {
        val state = buildState(transferRestricted = true)
        val dict = state.encode().decodeDictionary()
        val trKey = io.olvid.engine.datatypes.DictionaryKey("tr")
        assertTrue("'tr' key must be present when transferRestricted=true", dict.containsKey(trKey))
        assertTrue(dict[trKey]!!.decodeBoolean())
    }

    @Test
    fun keycloakState_encode_transferRestrictedFalse_omitsKeyFromDictionary() {
        // encode() only writes the "tr" entry when transferRestricted is true (saves space).
        val state = buildState(transferRestricted = false)
        val dict = state.encode().decodeDictionary()
        val trKey = io.olvid.engine.datatypes.DictionaryKey("tr")
        assertFalse("'tr' key must be absent when transferRestricted=false", dict.containsKey(trKey))
    }

    @Test
    fun keycloakState_encode_ownApiKey_isAbsentFromDictionary() {
        // ownApiKey must never appear in the serialized dictionary.
        val state = buildState(ownApiKey = "must-not-be-encoded")
        val dict = state.encode().decodeDictionary()
        // There is no dedicated key for ownApiKey; confirm no entry decodes to the value.
        for ((_, value) in dict) {
            // Only string-typed entries are relevant; others will throw on decodeString.
            try {
                assertFalse(
                    "ownApiKey value must not appear anywhere in the encoded dictionary",
                    value.decodeString() == "must-not-be-encoded",
                )
            } catch (_: DecodingException) {
                // Non-string entry — expected and fine.
            }
        }
    }

    @Test
    fun keycloakState_encode_serializedAuthState_encodedUnderSasKey() {
        val state = buildState(serializedAuthState = "token-abc")
        val dict = state.encode().decodeDictionary()
        val sasKey = io.olvid.engine.datatypes.DictionaryKey("sas")
        assertTrue("'sas' key must be present when serializedAuthState is non-null", dict.containsKey(sasKey))
        assertEquals("token-abc", dict[sasKey]!!.decodeString())
    }

    // ─── 3f. of() error paths ─────────────────────────────────────────────────

    @Test(expected = DecodingException::class)
    fun keycloakState_of_throwsDecodingException_forNonDictionaryEncoded() {
        // Passing a string-encoded value instead of a dictionary-encoded value
        // must cause decodeDictionary() to throw DecodingException.
        val notADict = Encoded.of("this is not a dictionary")
        ObvKeycloakState.of(notADict)
    }

    @Test(expected = DecodingException::class)
    fun keycloakState_of_throwsDecodingException_forBooleanEncoded() {
        // A boolean-encoded value is likewise not a dictionary.
        val notADict = Encoded.of(true)
        ObvKeycloakState.of(notADict)
    }

    // ─── 3g. Empty / minimal state round-trip ─────────────────────────────────

    @Test
    fun keycloakState_minimalState_nullOptionalFields_roundTrips() {
        // A state with only the required fields (null jwks, signatureKey, serializedAuthState)
        // must encode and decode without throwing.
        val minimal = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            emptyList(),
            null,
            null,
            null,
            false,
            null,
            0L,
            0L,
        )
        val restored = ObvKeycloakState.of(minimal.encode())
        assertEquals(minimal.keycloakServer, restored.keycloakServer)
        assertNull(restored.jwks)
        assertNull(restored.signatureKey)
        assertNull(restored.serializedAuthState)
        assertFalse(restored.transferRestricted)
    }

    @Test
    fun keycloakState_minimalState_emptyAuthMethods_roundTrips() {
        val minimal = ObvKeycloakState(
            "https://keycloak.example.com/auth",
            emptyList(),
            null,
            null,
            null,
            false,
            null,
            0L,
            0L,
        )
        val restored = ObvKeycloakState.of(minimal.encode())
        // No auth methods means neither OIDC nor IdBased are present.
        assertFalse(
            restored.supportedAuthenticationMethods.any { it is ObvKeycloakAuthType.IdBased },
        )
        assertFalse(
            restored.supportedAuthenticationMethods.any { it is ObvKeycloakAuthType.OpenIdConnect },
        )
    }

    // ─── 3h. Wire-format golden-hex pin ───────────────────────────────────────

    @Test
    fun keycloakState_encode_keycloakServerBytesMatchKnownContent() {
        // Build a state with a deterministic keycloakServer string and verify the encoded
        // dictionary "ks" entry contains exactly those UTF-8 bytes when decoded.
        val server = "https://kc.test/auth"
        val state = ObvKeycloakState(server, emptyList(), null, null, null, false, null, 0L, 0L)
        val dict = state.encode().decodeDictionary()
        val ksKey = io.olvid.engine.datatypes.DictionaryKey("ks")
        val decoded = dict[ksKey]!!.decodeString()
        assertEquals(
            "The 'ks' entry in the encoded dictionary must round-trip the server URL exactly",
            server,
            decoded,
        )
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════════════════════════════════════════

    private fun buildState(
        keycloakServer: String = "https://keycloak.example.com/auth",
        authMethods: List<ObvKeycloakAuthType> = listOf(ObvKeycloakAuthType.IdBased()),
        jwks: JsonWebKeySet? = testJwks,
        signatureKey: JsonWebKey? = testSignatureKey,
        serializedAuthState: String? = "auth-state-token",
        transferRestricted: Boolean = false,
        ownApiKey: String? = "api-key-xyz",
        latestRevocationListTimestamp: Long = 1_000_000L,
        latestGroupUpdateTimestamp: Long = 2_000_000L,
    ) = ObvKeycloakState(
        keycloakServer,
        authMethods,
        jwks,
        signatureKey,
        serializedAuthState,
        transferRestricted,
        ownApiKey,
        latestRevocationListTimestamp,
        latestGroupUpdateTimestamp,
    )
}
