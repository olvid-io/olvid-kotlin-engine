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

package io.olvid.engine.datatypes.containers

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2.Identifier
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [TrustOrigin].
 *
 * Written before migrating the class from Java to Kotlin so we have a
 * behavioural safety net for all five factory variants, getter contracts,
 * and the `equals` semantics (which intentionally ignores the timestamp).
 */
class TrustOriginTest {

    // -------------------------------------------------------------------
    // Helpers — built once and shared across all tests
    // -------------------------------------------------------------------

    private lateinit var identityA: Identity
    private lateinit var identityB: Identity
    private lateinit var groupIdentifier: Identifier
    private lateinit var groupIdentifierDifferent: Identifier

    @Before
    fun silenceLogger() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.NONE)
    }

    @Before
    fun buildFixtures() {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPairA = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairA = EncryptionEciesCurve25519KeyPair.generate(prng)
        identityA = Identity(
            "server-a.olvid.io",
            serverAuthKeyPairA.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairA.publicKey as EncryptionPublicKey,
        )

        val serverAuthKeyPairB = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encryptionKeyPairB = EncryptionEciesCurve25519KeyPair.generate(prng)
        identityB = Identity(
            "server-b.olvid.io",
            serverAuthKeyPairB.publicKey as ServerAuthenticationPublicKey,
            encryptionKeyPairB.publicKey as EncryptionPublicKey,
        )

        val uid1 = UID(ByteArray(UID.UID_LENGTH) { 0x01 })
        groupIdentifier = Identifier(uid1, "server-a.olvid.io", Identifier.CATEGORY_SERVER)

        val uid2 = UID(ByteArray(UID.UID_LENGTH) { 0x02 })
        groupIdentifierDifferent = Identifier(uid2, "server-b.olvid.io", Identifier.CATEGORY_KEYCLOAK)
    }

    // -------------------------------------------------------------------
    // 1. TrustType enum — name and ordinal stability
    // -------------------------------------------------------------------

    @Test
    fun enumValuesExistWithExpectedNames() {
        val values = TrustOrigin.TYPE.values()
        val names = values.map { it.name }
        assertTrue("DIRECT must be present", names.contains("DIRECT"))
        assertTrue("INTRODUCTION must be present", names.contains("INTRODUCTION"))
        assertTrue("GROUP must be present", names.contains("GROUP"))
        assertTrue("KEYCLOAK must be present", names.contains("KEYCLOAK"))
        assertTrue("SERVER_GROUP_V2 must be present", names.contains("SERVER_GROUP_V2"))
        assertEquals("Exactly 5 enum values", 5, values.size)
    }

    @Test
    fun enumOrdinalsAreStable() {
        assertEquals(0, TrustOrigin.TYPE.DIRECT.ordinal)
        assertEquals(1, TrustOrigin.TYPE.INTRODUCTION.ordinal)
        assertEquals(2, TrustOrigin.TYPE.GROUP.ordinal)
        assertEquals(3, TrustOrigin.TYPE.KEYCLOAK.ordinal)
        assertEquals(4, TrustOrigin.TYPE.SERVER_GROUP_V2.ordinal)
    }

    // -------------------------------------------------------------------
    // 2. Factory: createDirectTrustOrigin
    // -------------------------------------------------------------------

    @Test
    fun directFactory_setsTypeAndTimestamp() {
        val ts = 123_456_789L
        val origin = TrustOrigin.createDirectTrustOrigin(ts)

        assertNotNull(origin)
        assertEquals(TrustOrigin.TYPE.DIRECT, origin.type)
        assertEquals(ts, origin.timestamp)
    }

    @Test
    fun directFactory_hasNullFields() {
        val origin = TrustOrigin.createDirectTrustOrigin(0L)

        assertNull("mediatorOrGroupOwnerIdentity must be null for DIRECT", origin.mediatorOrGroupOwnerIdentity)
        assertNull("keycloakServer must be null for DIRECT", origin.keycloakServer)
        assertNull("groupIdentifier must be null for DIRECT", origin.groupIdentifier)
    }

    // -------------------------------------------------------------------
    // 3. Factory: createIntroductionTrustOrigin
    // -------------------------------------------------------------------

    @Test
    fun introductionFactory_setsTypeTimestampAndMediator() {
        val ts = 111L
        val origin = TrustOrigin.createIntroductionTrustOrigin(ts, identityA)

        assertEquals(TrustOrigin.TYPE.INTRODUCTION, origin.type)
        assertEquals(ts, origin.timestamp)
        assertEquals(identityA, origin.mediatorOrGroupOwnerIdentity)
    }

    @Test
    fun introductionFactory_hasNullKeycloakAndGroup() {
        val origin = TrustOrigin.createIntroductionTrustOrigin(0L, identityA)

        assertNull("keycloakServer must be null for INTRODUCTION", origin.keycloakServer)
        assertNull("groupIdentifier must be null for INTRODUCTION", origin.groupIdentifier)
    }

    // -------------------------------------------------------------------
    // 4. Factory: createGroupTrustOrigin
    // -------------------------------------------------------------------

    @Test
    fun groupFactory_setsTypeTimestampAndGroupOwner() {
        val ts = 222L
        val origin = TrustOrigin.createGroupTrustOrigin(ts, identityA)

        assertEquals(TrustOrigin.TYPE.GROUP, origin.type)
        assertEquals(ts, origin.timestamp)
        assertEquals(identityA, origin.mediatorOrGroupOwnerIdentity)
    }

    @Test
    fun groupFactory_hasNullKeycloakAndGroupIdentifier() {
        val origin = TrustOrigin.createGroupTrustOrigin(0L, identityA)

        assertNull("keycloakServer must be null for GROUP", origin.keycloakServer)
        assertNull("groupIdentifier must be null for GROUP", origin.groupIdentifier)
    }

    // -------------------------------------------------------------------
    // 5. Factory: createKeycloakTrustOrigin
    // -------------------------------------------------------------------

    @Test
    fun keycloakFactory_setsTypeTimestampAndServer() {
        val ts = 333L
        val server = "https://keycloak.example.com/auth/realms/olvid"
        val origin = TrustOrigin.createKeycloakTrustOrigin(ts, server)

        assertEquals(TrustOrigin.TYPE.KEYCLOAK, origin.type)
        assertEquals(ts, origin.timestamp)
        assertEquals(server, origin.keycloakServer)
    }

    @Test
    fun keycloakFactory_hasNullIdentityAndGroupIdentifier() {
        val origin = TrustOrigin.createKeycloakTrustOrigin(0L, "https://kc.example.com")

        assertNull("mediatorOrGroupOwnerIdentity must be null for KEYCLOAK", origin.mediatorOrGroupOwnerIdentity)
        assertNull("groupIdentifier must be null for KEYCLOAK", origin.groupIdentifier)
    }

    // -------------------------------------------------------------------
    // 6. Factory: createServerGroupV2TrustOrigin
    // -------------------------------------------------------------------

    @Test
    fun serverGroupV2Factory_setsTypeTimestampAndGroupIdentifier() {
        val ts = 444L
        val origin = TrustOrigin.createServerGroupV2TrustOrigin(ts, groupIdentifier)

        assertEquals(TrustOrigin.TYPE.SERVER_GROUP_V2, origin.type)
        assertEquals(ts, origin.timestamp)
        assertEquals(groupIdentifier, origin.groupIdentifier)
    }

    @Test
    fun serverGroupV2Factory_hasNullIdentityAndKeycloak() {
        val origin = TrustOrigin.createServerGroupV2TrustOrigin(0L, groupIdentifier)

        assertNull("mediatorOrGroupOwnerIdentity must be null for SERVER_GROUP_V2", origin.mediatorOrGroupOwnerIdentity)
        assertNull("keycloakServer must be null for SERVER_GROUP_V2", origin.keycloakServer)
    }

    // -------------------------------------------------------------------
    // 7. equals — DIRECT: any two DIRECT origins are equal regardless of timestamp
    // -------------------------------------------------------------------

    @Test
    fun directEquals_ignoresTimestamp() {
        val o1 = TrustOrigin.createDirectTrustOrigin(100L)
        val o2 = TrustOrigin.createDirectTrustOrigin(999L)

        assertEquals("Two DIRECT origins must be equal regardless of timestamp", o1, o2)
    }

    @Test
    fun directEquals_reflexive() {
        val o = TrustOrigin.createDirectTrustOrigin(1L)
        assertEquals(o, o)
    }

    @Test
    fun directEquals_notEqualToNonTrustOrigin() {
        val o = TrustOrigin.createDirectTrustOrigin(1L)
        assertNotEquals(o, "not a TrustOrigin")
        assertFalse(o.equals(null))
    }

    // -------------------------------------------------------------------
    // 8. equals — INTRODUCTION: compares mediatorIdentity, ignores timestamp
    // -------------------------------------------------------------------

    @Test
    fun introductionEquals_sameMediator_differentTimestamp_isEqual() {
        val o1 = TrustOrigin.createIntroductionTrustOrigin(1L, identityA)
        val o2 = TrustOrigin.createIntroductionTrustOrigin(999L, identityA)

        assertEquals(o1, o2)
    }

    @Test
    fun introductionEquals_differentMediator_isNotEqual() {
        val o1 = TrustOrigin.createIntroductionTrustOrigin(1L, identityA)
        val o2 = TrustOrigin.createIntroductionTrustOrigin(1L, identityB)

        assertNotEquals(o1, o2)
    }

    @Test
    fun introductionEquals_notEqualToDirect() {
        val introduction = TrustOrigin.createIntroductionTrustOrigin(1L, identityA)
        val direct = TrustOrigin.createDirectTrustOrigin(1L)

        assertNotEquals(introduction, direct)
    }

    // -------------------------------------------------------------------
    // 9. equals — GROUP: compares groupOwnerIdentity, ignores timestamp
    // -------------------------------------------------------------------

    @Test
    fun groupEquals_sameOwner_differentTimestamp_isEqual() {
        val o1 = TrustOrigin.createGroupTrustOrigin(1L, identityA)
        val o2 = TrustOrigin.createGroupTrustOrigin(999L, identityA)

        assertEquals(o1, o2)
    }

    @Test
    fun groupEquals_differentOwner_isNotEqual() {
        val o1 = TrustOrigin.createGroupTrustOrigin(1L, identityA)
        val o2 = TrustOrigin.createGroupTrustOrigin(1L, identityB)

        assertNotEquals(o1, o2)
    }

    @Test
    fun groupEquals_notEqualToIntroduction_sameIdentity() {
        val group = TrustOrigin.createGroupTrustOrigin(1L, identityA)
        val intro = TrustOrigin.createIntroductionTrustOrigin(1L, identityA)

        // Different TYPE => not equal
        assertNotEquals(group, intro)
    }

    // -------------------------------------------------------------------
    // 10. equals — KEYCLOAK: compares keycloakServer string, ignores timestamp
    // -------------------------------------------------------------------

    @Test
    fun keycloakEquals_sameServer_differentTimestamp_isEqual() {
        val server = "https://kc.example.com"
        val o1 = TrustOrigin.createKeycloakTrustOrigin(1L, server)
        val o2 = TrustOrigin.createKeycloakTrustOrigin(999L, server)

        assertEquals(o1, o2)
    }

    @Test
    fun keycloakEquals_differentServer_isNotEqual() {
        val o1 = TrustOrigin.createKeycloakTrustOrigin(1L, "https://kc-a.example.com")
        val o2 = TrustOrigin.createKeycloakTrustOrigin(1L, "https://kc-b.example.com")

        assertNotEquals(o1, o2)
    }

    @Test
    fun keycloakEquals_nullServer_isEqual() {
        val o1 = TrustOrigin.createKeycloakTrustOrigin(1L, null)
        val o2 = TrustOrigin.createKeycloakTrustOrigin(999L, null)

        assertEquals("Two KEYCLOAK with null server must be equal", o1, o2)
    }

    // -------------------------------------------------------------------
    // 11. equals — SERVER_GROUP_V2: compares groupIdentifier, ignores timestamp
    // -------------------------------------------------------------------

    @Test
    fun serverGroupV2Equals_sameIdentifier_differentTimestamp_isEqual() {
        val o1 = TrustOrigin.createServerGroupV2TrustOrigin(1L, groupIdentifier)
        val o2 = TrustOrigin.createServerGroupV2TrustOrigin(999L, groupIdentifier)

        assertEquals(o1, o2)
    }

    @Test
    fun serverGroupV2Equals_differentIdentifier_isNotEqual() {
        val o1 = TrustOrigin.createServerGroupV2TrustOrigin(1L, groupIdentifier)
        val o2 = TrustOrigin.createServerGroupV2TrustOrigin(1L, groupIdentifierDifferent)

        assertNotEquals(o1, o2)
    }

    @Test
    fun serverGroupV2Equals_notEqualToDirect() {
        val sgv2 = TrustOrigin.createServerGroupV2TrustOrigin(1L, groupIdentifier)
        val direct = TrustOrigin.createDirectTrustOrigin(1L)

        assertNotEquals(sgv2, direct)
    }

    // -------------------------------------------------------------------
    // 12. Cross-type inequality sanity
    // -------------------------------------------------------------------

    @Test
    fun allFiveTypes_areNotEqualToEachOther() {
        val direct = TrustOrigin.createDirectTrustOrigin(1L)
        val intro = TrustOrigin.createIntroductionTrustOrigin(1L, identityA)
        val group = TrustOrigin.createGroupTrustOrigin(1L, identityA)
        val kc = TrustOrigin.createKeycloakTrustOrigin(1L, "https://kc.example.com")
        val sgv2 = TrustOrigin.createServerGroupV2TrustOrigin(1L, groupIdentifier)

        val all = listOf(direct, intro, group, kc, sgv2)
        for (i in all.indices) {
            for (j in all.indices) {
                if (i != j) {
                    assertNotEquals(
                        "TYPE[${all[i].type}] must not equal TYPE[${all[j].type}]",
                        all[i],
                        all[j],
                    )
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // 13. Full-constructor (package-private path) — all five combinations
    // -------------------------------------------------------------------

    @Test
    fun fullConstructor_direct_roundTrip() {
        val ts = 500L
        val origin = TrustOrigin(TrustOrigin.TYPE.DIRECT, ts, null, null, null)

        assertEquals(TrustOrigin.TYPE.DIRECT, origin.type)
        assertEquals(ts, origin.timestamp)
        assertNull(origin.mediatorOrGroupOwnerIdentity)
        assertNull(origin.keycloakServer)
        assertNull(origin.groupIdentifier)
    }

    @Test
    fun fullConstructor_introduction_roundTrip() {
        val origin = TrustOrigin(TrustOrigin.TYPE.INTRODUCTION, 1L, identityA, null, null)

        assertEquals(TrustOrigin.TYPE.INTRODUCTION, origin.type)
        assertEquals(identityA, origin.mediatorOrGroupOwnerIdentity)
    }

    @Test
    fun fullConstructor_group_roundTrip() {
        val origin = TrustOrigin(TrustOrigin.TYPE.GROUP, 1L, identityB, null, null)

        assertEquals(TrustOrigin.TYPE.GROUP, origin.type)
        assertEquals(identityB, origin.mediatorOrGroupOwnerIdentity)
    }

    @Test
    fun fullConstructor_keycloak_roundTrip() {
        val server = "https://kc.olvid.io"
        val origin = TrustOrigin(TrustOrigin.TYPE.KEYCLOAK, 1L, null, server, null)

        assertEquals(TrustOrigin.TYPE.KEYCLOAK, origin.type)
        assertEquals(server, origin.keycloakServer)
    }

    @Test
    fun fullConstructor_serverGroupV2_roundTrip() {
        val origin = TrustOrigin(TrustOrigin.TYPE.SERVER_GROUP_V2, 1L, null, null, groupIdentifier)

        assertEquals(TrustOrigin.TYPE.SERVER_GROUP_V2, origin.type)
        assertEquals(groupIdentifier, origin.groupIdentifier)
    }
}
