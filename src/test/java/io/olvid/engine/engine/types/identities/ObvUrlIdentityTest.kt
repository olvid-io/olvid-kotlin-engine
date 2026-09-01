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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [ObvUrlIdentity] and [ObvMutualScanUrl].
 *
 * Both classes are load-bearing wire-format contracts: they encode/decode invitation URLs
 * that are exchanged out-of-band (QR codes, deep links, copy-paste).  Any change to the
 * URL constants, regex pattern, or serialisation format silently breaks every existing
 * shipped invitation.  These tests pin those contracts.
 *
 * Test setup
 * ----------
 * A deterministic PRNG (all-zero 32-byte seed) generates the same key pair on every run,
 * so golden URL values are stable across machines and across builds.
 */
class ObvUrlIdentityTest {

    // ── Shared fixtures ───────────────────────────────────────────────────────

    private lateinit var identity: Identity

    /** A fixed display name used for all golden-pin tests. */
    private val displayName = "Alice Test"

    /** A fixed signature used for ObvMutualScanUrl golden-pin tests. */
    private val signature = ByteArray(32) { it.toByte() }

    @Before
    fun setUp() {
        // Swallow all Logger output — the engine logs decode exceptions in fromUrlRepresentation.
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        // Deterministic PRNG — same keys on every run.
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        identity = Identity(
            "test.olvid.io",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPair.publicKey as EncryptionPublicKey,
        )
    }

    // ════════════════════════════════════════════════════════════════════════
    // ObvUrlIdentity
    // ════════════════════════════════════════════════════════════════════════

    // ── 1. Wire-format URL constants ─────────────────────────────────────────

    @Test
    fun obvUrlIdentity_urlProtocolIsHttps() {
        assertEquals(
            "URL_PROTOCOL must remain \"https\" — changing it breaks every shipped invitation",
            "https",
            ObvUrlIdentity.URL_PROTOCOL,
        )
    }

    @Test
    fun obvUrlIdentity_urlProtocolOlvidIsOlvid() {
        assertEquals(
            "URL_PROTOCOL_OLVID must remain \"olvid\" — changing it breaks deep-link handling",
            "olvid",
            ObvUrlIdentity.URL_PROTOCOL_OLVID,
        )
    }

    @Test
    fun obvUrlIdentity_urlInvitationHostIsPinned() {
        assertEquals(
            "URL_INVITATION_HOST must remain \"invitation.olvid.io\" — changing it breaks every shipped invitation",
            "invitation.olvid.io",
            ObvUrlIdentity.URL_INVITATION_HOST,
        )
    }

    // ── 2. INVITATION_PATTERN regex contract ─────────────────────────────────

    @Test
    fun invitationPattern_matchesHttpsWithHashFragment() {
        val url = "https://invitation.olvid.io/#abc123"
        assertTrue(
            "INVITATION_PATTERN must match standard https invitation URL",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_matchesOlvidProtocol() {
        val url = "olvid://invitation.olvid.io/#abc123"
        assertTrue(
            "INVITATION_PATTERN must match olvid:// protocol",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_matchesMutualScanVariantWithSlash1Hash() {
        // /1# prefix is the mutual-scan variant produced by getUrlRepresentation(true)
        val url = "https://invitation.olvid.io/1#abc123"
        assertTrue(
            "INVITATION_PATTERN must match mutual-scan variant with /1# prefix",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_doesNotMatchPlainHttp() {
        val url = "http://invitation.olvid.io/#abc"
        assertFalse(
            "INVITATION_PATTERN must NOT match http:// (only https and olvid)",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_doesNotMatchWrongHost() {
        val url = "https://other.olvid.io/#abc"
        assertFalse(
            "INVITATION_PATTERN must NOT match a URL with a different host",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_doesNotMatchMissingHashFragment() {
        val url = "https://invitation.olvid.io/abc"
        assertFalse(
            "INVITATION_PATTERN must NOT match a URL without a # fragment",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_doesNotMatchPayloadOnlyOfForbiddenChars() {
        // The payload must be non-empty and drawn from [-_a-zA-Z0-9].
        // A fragment that is ENTIRELY forbidden characters (no valid prefix) produces no match.
        val url = "https://invitation.olvid.io/#@@@"
        assertFalse(
            "INVITATION_PATTERN must NOT match when the fragment consists only of forbidden characters",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun invitationPattern_findMatchesValidPrefixEvenWithTrailingForbiddenChars() {
        // Pattern uses find(), not matches(). 'abc' is a valid payload; '@def' is simply
        // not consumed. This is the actual characterised behaviour — pin it explicitly so
        // a future migration that switches to matches() will be caught.
        val url = "https://invitation.olvid.io/#abc@def"
        assertTrue(
            "INVITATION_PATTERN with find() must match the valid 'abc' prefix even when '@def' follows",
            ObvUrlIdentity.INVITATION_PATTERN.matcher(url).find(),
        )
    }

    // ── 3. getUrlRepresentation ──────────────────────────────────────────────

    @Test
    fun getUrlRepresentation_falseStartsWithHttpsHashPrefix() {
        val url = ObvUrlIdentity(identity, displayName).getUrlRepresentation(false)
        assertTrue(
            "getUrlRepresentation(false) must start with \"https://invitation.olvid.io/#\"",
            url.startsWith("https://invitation.olvid.io/#"),
        )
    }

    @Test
    fun getUrlRepresentation_trueStartsWithHttpsSlash1HashPrefix() {
        val url = ObvUrlIdentity(identity, displayName).getUrlRepresentation(true)
        assertTrue(
            "getUrlRepresentation(true) must start with \"https://invitation.olvid.io/1#\"",
            url.startsWith("https://invitation.olvid.io/1#"),
        )
    }

    /**
     * Golden-string pin for ObvUrlIdentity wire format.
     *
     * The expected value was captured on the first run using the deterministic PRNG
     * (all-zero 32-byte seed, server = "test.olvid.io", displayName = "Alice Test").
     * Do NOT change this literal unless the serialisation format is intentionally
     * updated AND the protocol team approves.  A change here means existing QR codes
     * and deep links sent to users will fail to decode.
     */
    @Test
    fun getUrlRepresentation_goldenPinForMutualScanFalse() {
        val url = ObvUrlIdentity(identity, displayName).getUrlRepresentation(false)
        assertEquals(
            "ObvUrlIdentity URL wire-format has changed — existing invitations will break",
            GOLDEN_OBV_URL_IDENTITY_FALSE,
            url,
        )
    }

    @Test
    fun getUrlRepresentation_goldenPinForMutualScanTrue() {
        val url = ObvUrlIdentity(identity, displayName).getUrlRepresentation(true)
        assertEquals(
            "ObvUrlIdentity mutual-scan URL wire-format has changed — existing invitations will break",
            GOLDEN_OBV_URL_IDENTITY_TRUE,
            url,
        )
    }

    // ── 4. fromUrlRepresentation round-trip ──────────────────────────────────

    @Test
    fun fromUrlRepresentation_roundTripForMutualScanFalse() {
        val original = ObvUrlIdentity(identity, displayName)
        val url = original.getUrlRepresentation(false)
        val decoded = ObvUrlIdentity.fromUrlRepresentation(url)

        assertNotNull("fromUrlRepresentation must return non-null for a valid URL", decoded)
        assertArrayEquals(
            "Identity bytes must survive the URL round-trip (forMutualScan=false)",
            identity.getBytes(),
            decoded!!.identity!!.getBytes(),
        )
        assertEquals(
            "Display name must survive the URL round-trip (forMutualScan=false)",
            displayName,
            decoded.displayName,
        )
    }

    @Test
    fun fromUrlRepresentation_roundTripForMutualScanTrue() {
        val original = ObvUrlIdentity(identity, displayName)
        val url = original.getUrlRepresentation(true)
        val decoded = ObvUrlIdentity.fromUrlRepresentation(url)

        assertNotNull("fromUrlRepresentation must return non-null for a valid URL", decoded)
        assertArrayEquals(
            "Identity bytes must survive the URL round-trip (forMutualScan=true)",
            identity.getBytes(),
            decoded!!.identity!!.getBytes(),
        )
        assertEquals(
            "Display name must survive the URL round-trip (forMutualScan=true)",
            displayName,
            decoded.displayName,
        )
    }

    @Test
    fun fromUrlRepresentation_returnsNullForInvalidUrl() {
        val result = ObvUrlIdentity.fromUrlRepresentation("foo")
        assertNull("fromUrlRepresentation must return null for a completely invalid URL", result)
    }

    @Test
    fun fromUrlRepresentation_returnsNullForInvalidBase64Payload() {
        // The URL matches the pattern (valid structure) but the fragment is not valid encoded data
        val result = ObvUrlIdentity.fromUrlRepresentation("https://invitation.olvid.io/#aaaa")
        assertNull(
            "fromUrlRepresentation must return null (not throw) when payload cannot be decoded",
            result,
        )
    }

    // ── 5. Constructor variants ───────────────────────────────────────────────

    @Test
    fun constructorIdentityString_storesIdentityField() {
        val obj = ObvUrlIdentity(identity, displayName)
        assertEquals(
            "Constructor(Identity, String) must store the identity reference",
            identity,
            obj.identity,
        )
    }

    @Test
    fun constructorIdentityString_storesDisplayNameField() {
        val obj = ObvUrlIdentity(identity, displayName)
        assertEquals(
            "Constructor(Identity, String) must store the displayName string",
            displayName,
            obj.displayName,
        )
    }

    @Test
    fun constructorBytesString_decodesValidIdentity() {
        val obj = ObvUrlIdentity(identity.getBytes(), displayName)
        assertNotNull(
            "Constructor(byte[], String) must decode valid identity bytes without returning null identity",
            obj.identity,
        )
        assertArrayEquals(
            "Constructor(byte[], String) must decode the same identity as the original",
            identity.getBytes(),
            obj.identity!!.getBytes(),
        )
    }

    @Test
    fun constructorBytesString_setsIdentityNullOnInvalidBytes() {
        val invalidBytes = byteArrayOf(0x01, 0x02, 0x03) // no null separator → DecodingException
        val obj = ObvUrlIdentity(invalidBytes, displayName)
        assertNull(
            "Constructor(byte[], String) must set identity to null when bytes cannot be decoded",
            obj.identity,
        )
        // displayName is still stored even on decode failure
        assertEquals(
            "displayName must be stored even when identity decoding fails",
            displayName,
            obj.displayName,
        )
    }

    // ── 6. getBytesIdentity ───────────────────────────────────────────────────

    @Test
    fun getBytesIdentity_returnsIdentityGetBytes() {
        val obj = ObvUrlIdentity(identity, displayName)
        assertArrayEquals(
            "getBytesIdentity() must return the same bytes as identity.getBytes()",
            identity.getBytes(),
            obj.getBytesIdentity(),
        )
    }

    @Test
    fun getBytesIdentity_throwsNpeWhenIdentityIsNull() {
        val invalidBytes = byteArrayOf(0x01, 0x02, 0x03)
        val obj = ObvUrlIdentity(invalidBytes, displayName)
        // identity is null after a failed decode
        try {
            obj.getBytesIdentity()
            // If we reach here the implementation has been changed; the test must fail
            // because callers rely on NPE to detect a null identity.
            throw AssertionError(
                "getBytesIdentity() should throw NullPointerException when identity is null",
            )
        } catch (_: NullPointerException) {
            // expected — pins the behaviour callers depend on
        }
    }

    // ── 7. Public final field accessibility ───────────────────────────────────

    @Test
    fun publicFinalFields_areAccessibleWithoutGetters() {
        // This test compiles only if `identity` and `displayName` are public fields.
        // A Kotlin migration that changes them to private properties with getters only
        // will break Java callers that use instance.identity / instance.displayName
        // directly, which this test catches at compile time.
        val obj = ObvUrlIdentity(identity, displayName)
        val accessedIdentity: Identity? = obj.identity
        val accessedDisplayName: String = obj.displayName
        assertNotNull(accessedIdentity)
        assertNotNull(accessedDisplayName)
    }

    // ════════════════════════════════════════════════════════════════════════
    // ObvMutualScanUrl
    // ════════════════════════════════════════════════════════════════════════

    // ── 1. Wire-format URL constants ─────────────────────────────────────────

    @Test
    fun obvMutualScanUrl_urlProtocolIsHttps() {
        assertEquals(
            "ObvMutualScanUrl.URL_PROTOCOL must remain \"https\"",
            "https",
            ObvMutualScanUrl.URL_PROTOCOL,
        )
    }

    @Test
    fun obvMutualScanUrl_urlProtocolOlvidIsOlvid() {
        assertEquals(
            "ObvMutualScanUrl.URL_PROTOCOL_OLVID must remain \"olvid\"",
            "olvid",
            ObvMutualScanUrl.URL_PROTOCOL_OLVID,
        )
    }

    @Test
    fun obvMutualScanUrl_urlInvitationHostIsPinned() {
        assertEquals(
            "ObvMutualScanUrl.URL_INVITATION_HOST must remain \"invitation.olvid.io\"",
            "invitation.olvid.io",
            ObvMutualScanUrl.URL_INVITATION_HOST,
        )
    }

    // ── 2. MUTUAL_SCAN_PATTERN regex contract ────────────────────────────────

    @Test
    fun mutualScanPattern_matchesHttpsWithSlash2Hash() {
        val url = "https://invitation.olvid.io/2#abc123"
        assertTrue(
            "MUTUAL_SCAN_PATTERN must match https URL with /2# prefix",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_matchesOlvidProtocol() {
        val url = "olvid://invitation.olvid.io/2#abc123"
        assertTrue(
            "MUTUAL_SCAN_PATTERN must match olvid:// protocol",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_doesNotMatchPlainHttp() {
        val url = "http://invitation.olvid.io/2#abc123"
        assertFalse(
            "MUTUAL_SCAN_PATTERN must NOT match plain http://",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_doesNotMatchWrongHost() {
        val url = "https://other.olvid.io/2#abc123"
        assertFalse(
            "MUTUAL_SCAN_PATTERN must NOT match a different host",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_doesNotMatchSlash1HashPrefix() {
        // /1# is ObvUrlIdentity's mutual-scan prefix, not ObvMutualScanUrl's /2#
        val url = "https://invitation.olvid.io/1#abc123"
        assertFalse(
            "MUTUAL_SCAN_PATTERN must NOT match /1# prefix (that belongs to ObvUrlIdentity)",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_doesNotMatchMissingSlash2Prefix() {
        val url = "https://invitation.olvid.io/#abc123"
        assertFalse(
            "MUTUAL_SCAN_PATTERN must NOT match /#prefix (requires /2#)",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_doesNotMatchPayloadOnlyOfForbiddenChars() {
        val url = "https://invitation.olvid.io/2#@@@"
        assertFalse(
            "MUTUAL_SCAN_PATTERN must NOT match when the fragment consists only of forbidden characters",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    @Test
    fun mutualScanPattern_findMatchesValidPrefixEvenWithTrailingForbiddenChars() {
        // Same find()-vs-matches() characterisation as INVITATION_PATTERN.
        val url = "https://invitation.olvid.io/2#abc@def"
        assertTrue(
            "MUTUAL_SCAN_PATTERN with find() must match the valid 'abc' prefix even when '@def' follows",
            ObvMutualScanUrl.MUTUAL_SCAN_PATTERN.matcher(url).find(),
        )
    }

    // ── 3. Constructor field storage ─────────────────────────────────────────

    @Test
    fun obvMutualScanUrl_constructorStoresIdentity() {
        val obj = ObvMutualScanUrl(identity, displayName, signature)
        assertEquals(
            "Constructor must store the identity field",
            identity,
            obj.identity,
        )
    }

    @Test
    fun obvMutualScanUrl_constructorStoresDisplayName() {
        val obj = ObvMutualScanUrl(identity, displayName, signature)
        assertEquals(
            "Constructor must store the displayName field",
            displayName,
            obj.displayName,
        )
    }

    @Test
    fun obvMutualScanUrl_constructorStoresSignature() {
        val obj = ObvMutualScanUrl(identity, displayName, signature)
        assertArrayEquals(
            "Constructor must store the signature bytes",
            signature,
            obj.signature,
        )
    }

    // ── 4. getUrlRepresentation golden-string pin ─────────────────────────────

    /**
     * Golden-string pin for ObvMutualScanUrl wire format.
     *
     * Captured with: identity from deterministic PRNG (all-zero 32-byte seed,
     * server = "test.olvid.io"), displayName = "Alice Test",
     * signature = 0x00..0x1f (32 bytes, i.toByte()).
     */
    @Test
    fun obvMutualScanUrl_getUrlRepresentation_goldenPin() {
        val url = ObvMutualScanUrl(identity, displayName, signature).getUrlRepresentation()
        assertEquals(
            "ObvMutualScanUrl URL wire-format has changed — existing mutual-scan invitations will break",
            GOLDEN_OBV_MUTUAL_SCAN_URL,
            url,
        )
    }

    // ── 5. fromUrlRepresentation round-trip + error paths ───────────────────

    @Test
    fun obvMutualScanUrl_roundTripPreservesIdentityBytes() {
        val original = ObvMutualScanUrl(identity, displayName, signature)
        val url = original.getUrlRepresentation()
        val decoded = ObvMutualScanUrl.fromUrlRepresentation(url)

        assertNotNull("fromUrlRepresentation must return non-null for a valid URL", decoded)
        assertArrayEquals(
            "Identity bytes must survive the ObvMutualScanUrl URL round-trip",
            identity.getBytes(),
            decoded!!.identity.getBytes(),
        )
    }

    @Test
    fun obvMutualScanUrl_roundTripPreservesDisplayName() {
        val original = ObvMutualScanUrl(identity, displayName, signature)
        val url = original.getUrlRepresentation()
        val decoded = ObvMutualScanUrl.fromUrlRepresentation(url)

        assertNotNull(decoded)
        assertEquals(
            "Display name must survive the ObvMutualScanUrl URL round-trip",
            displayName,
            decoded!!.displayName,
        )
    }

    @Test
    fun obvMutualScanUrl_roundTripPreservesSignature() {
        val original = ObvMutualScanUrl(identity, displayName, signature)
        val url = original.getUrlRepresentation()
        val decoded = ObvMutualScanUrl.fromUrlRepresentation(url)

        assertNotNull(decoded)
        assertArrayEquals(
            "Signature bytes must survive the ObvMutualScanUrl URL round-trip",
            signature,
            decoded!!.signature,
        )
    }

    @Test
    fun obvMutualScanUrl_fromUrlRepresentation_returnsNullForInvalidUrl() {
        val result = ObvMutualScanUrl.fromUrlRepresentation("foo")
        assertNull("fromUrlRepresentation must return null for a completely invalid URL", result)
    }

    @Test
    fun obvMutualScanUrl_fromUrlRepresentation_returnsNullForInvalidBase64() {
        val result = ObvMutualScanUrl.fromUrlRepresentation("https://invitation.olvid.io/2#aaaa")
        assertNull(
            "fromUrlRepresentation must return null (not throw) for an undecodable payload",
            result,
        )
    }

    // ── 6. Public final field accessibility ───────────────────────────────────

    @Test
    fun obvMutualScanUrl_publicFinalFields_areAccessibleWithoutGetters() {
        val obj = ObvMutualScanUrl(identity, displayName, signature)
        val accessedIdentity: Identity = obj.identity
        val accessedDisplayName: String = obj.displayName
        val accessedSignature: ByteArray = obj.signature
        assertNotNull(accessedIdentity)
        assertNotNull(accessedDisplayName)
        assertNotNull(accessedSignature)
    }

    // ════════════════════════════════════════════════════════════════════════
    // Golden-string constants
    // (populated after the first run — DO NOT modify without protocol approval)
    // ════════════════════════════════════════════════════════════════════════

    companion object {
        // ObvUrlIdentity — forMutualScan=false (/#)
        // Captured with: PRNG seed = ByteArray(32) {0}, server = "test.olvid.io",
        // displayName = "Alice Test".
        // DO NOT change without protocol-team approval — changes break shipped invitations.
        private const val GOLDEN_OBV_URL_IDENTITY_FALSE =
            "https://invitation.olvid.io/#AwAAAGQAAAAAUHRlc3Qub2x2aWQuaW8AAWk4Ux4tM96-0_1D0sNp1-x2neK6UH3Efr8B2ODIfquFAXsFGc52KVflISEZij6BfGnw5fpoj8Ujk_BQJoEDTT8tAAAAAApBbGljZSBUZXN0"

        // ObvUrlIdentity — forMutualScan=true (/1#)
        // Same inputs as above; only the path prefix changes from /# to /1#.
        // DO NOT change without protocol-team approval — changes break shipped invitations.
        private const val GOLDEN_OBV_URL_IDENTITY_TRUE =
            "https://invitation.olvid.io/1#AwAAAGQAAAAAUHRlc3Qub2x2aWQuaW8AAWk4Ux4tM96-0_1D0sNp1-x2neK6UH3Efr8B2ODIfquFAXsFGc52KVflISEZij6BfGnw5fpoj8Ujk_BQJoEDTT8tAAAAAApBbGljZSBUZXN0"

        // ObvMutualScanUrl (/2#)
        // Captured with: PRNG seed = ByteArray(32) {0}, server = "test.olvid.io",
        // displayName = "Alice Test", signature = ByteArray(32) { it.toByte() } (0x00..0x1f).
        // DO NOT change without protocol-team approval — changes break shipped invitations.
        private const val GOLDEN_OBV_MUTUAL_SCAN_URL =
            "https://invitation.olvid.io/2#AwAAAIkAAAAAUHRlc3Qub2x2aWQuaW8AAWk4Ux4tM96-0_1D0sNp1-x2neK6UH3Efr8B2ODIfquFAXsFGc52KVflISEZij6BfGnw5fpoj8Ujk_BQJoEDTT8tAAAAAApBbGljZSBUZXN0AAAAACAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw"
    }
}
