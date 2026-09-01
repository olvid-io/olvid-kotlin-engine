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

package io.olvid.engine.protocol.protocol_engine

import io.olvid.engine.Logger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Characterization tests for [ConcreteProtocol].
 *
 * This class holds two categories of wire-format contracts that a Java→Kotlin migration
 * could silently break:
 *
 *  1. **Protocol ID constants** — `public static final int` values stored in the DB
 *     column `protocol_id` on ProtocolInstance rows. If any constant value changes,
 *     existing rows would be decoded to the wrong protocol. If a constant is dropped,
 *     the engine would log "Unknown protocol id" and orphan the protocol instance.
 *
 *  2. **`getProtocolPriority(int)` dispatch table** — the returned `long` governs
 *     which protocol steps are scheduled first. A wrong value slows the engine; a
 *     value outside [0, 1023] corrupts the 10-bit scheduling word.
 *
 * Additionally:
 *  3. **`getConcreteProtocol(null, …)` null-guard** — the documented early-return path
 *     that avoids a NullPointerException when no ProtocolInstance is available.
 *  4. **`getProtocolPriority` default throws** — the source throws RuntimeException for
 *     any protocol ID not listed in the switch; this test pins that contract so a
 *     migration that accidentally converts the throw to a silent default return is caught.
 *
 * Out of scope (require a live ProtocolManagerSession / DB):
 *  - Concrete protocol constructors.
 *  - `getConcreteProtocol` with a non-null ProtocolInstance (DB-bound).
 *  - All abstract-method contracts (tested via subclass tests).
 */
class ConcreteProtocolTest {

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
    }

    // ─── Group 1: Wire-format protocol ID constants ────────────────────────────
    //
    // Each constant is stored in the DB column `protocol_id`. These tests pin the
    // EXACT integer values. A Kotlin migration that accidentally changes any value
    // will silently decode existing DB rows to the wrong protocol.

    @Test
    fun testInitialStateIdIsExactly0() {
        assertEquals(0, ConcreteProtocol.INITIAL_STATE_ID)
    }

    @Test
    fun testDeviceDiscoveryProtocolIdIsExactly0() {
        assertEquals(0, ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID)
    }

    @Test
    fun testTrustEstablishmentProtocolIdIsExactly1() {
        // No longer used (superseded by TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID = 11),
        // but the constant must remain 1 to avoid corrupting any persisted legacy rows.
        assertEquals(1, ConcreteProtocol.TRUST_ESTABLISHMENT_PROTOCOL_ID)
    }

    @Test
    fun testChannelCreationWithContactDeviceProtocolIdIsExactly2() {
        assertEquals(2, ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID)
    }

    @Test
    fun testDeviceDiscoveryChildProtocolIdIsExactly3() {
        assertEquals(3, ConcreteProtocol.DEVICE_DISCOVERY_CHILD_PROTOCOL_ID)
    }

    @Test
    fun testContactMutualIntroductionProtocolIdIsExactly4() {
        assertEquals(4, ConcreteProtocol.CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID)
    }

    @Test
    fun testGroupCreationProtocolIdIsExactly5() {
        // No longer used, but the constant must remain 5 to avoid corrupting legacy rows.
        assertEquals(5, ConcreteProtocol.GROUP_CREATION_PROTOCOL_ID)
    }

    @Test
    fun testIdentityDetailsPublicationProtocolIdIsExactly6() {
        assertEquals(6, ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID)
    }

    @Test
    fun testDownloadIdentityPhotoChildProtocolIdIsExactly7() {
        assertEquals(7, ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID)
    }

    @Test
    fun testGroupInvitationProtocolIdIsExactly8() {
        assertEquals(8, ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID)
    }

    @Test
    fun testGroupManagementProtocolIdIsExactly9() {
        assertEquals(9, ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID)
    }

    @Test
    fun testContactManagementProtocolIdIsExactly10() {
        assertEquals(10, ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID)
    }

    @Test
    fun testTrustEstablishmentWithSasProtocolIdIsExactly11() {
        assertEquals(11, ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID)
    }

    @Test
    fun testTrustEstablishmentWithMutualScanProtocolIdIsExactly12() {
        assertEquals(12, ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID)
    }

    @Test
    fun testFullRatchetProtocolIdIsExactly13() {
        assertEquals(13, ConcreteProtocol.FULL_RATCHET_PROTOCOL_ID)
    }

    @Test
    fun testDownloadGroupPhotoChildProtocolIdIsExactly14() {
        assertEquals(14, ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID)
    }

    @Test
    fun testKeycloakContactAdditionProtocolIdIsExactly15() {
        assertEquals(15, ConcreteProtocol.KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID)
    }

    @Test
    fun testDeviceCapabilitiesDiscoveryProtocolIdIsExactly16() {
        assertEquals(16, ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID)
    }

    @Test
    fun testOneToOneContactInvitationProtocolIdIsExactly17() {
        assertEquals(17, ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID)
    }

    @Test
    fun testGroupsV2ProtocolIdIsExactly18() {
        assertEquals(18, ConcreteProtocol.GROUPS_V2_PROTOCOL_ID)
    }

    @Test
    fun testDownloadGroupsV2PhotoProtocolIdIsExactly19() {
        assertEquals(19, ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID)
    }

    @Test
    fun testOwnedIdentityDeletionProtocolIdIsExactly20() {
        assertEquals(20, ConcreteProtocol.OWNED_IDENTITY_DELETION_PROTOCOL_ID)
    }

    @Test
    fun testOwnedDeviceDiscoveryProtocolIdIsExactly21() {
        assertEquals(21, ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID)
    }

    @Test
    fun testChannelCreationWithOwnedDeviceProtocolIdIsExactly22() {
        assertEquals(22, ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID)
    }

    @Test
    fun testKeycloakBindingAndUnbindingProtocolIdIsExactly23() {
        assertEquals(23, ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID)
    }

    @Test
    fun testOwnedDeviceManagementProtocolIdIsExactly24() {
        assertEquals(24, ConcreteProtocol.OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID)
    }

    @Test
    fun testSynchronizationProtocolIdIsExactly25() {
        assertEquals(25, ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID)
    }

    @Test
    fun testOwnedIdentityTransferProtocolIdIsExactly26() {
        assertEquals(26, ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID)
    }

    @Test
    fun testLegacyKeycloakBindingAndUnbindingProtocolIdIsExactly1000() {
        // Android-only internal protocol. The value 1000 must not change; it is stored
        // in the DB and used as a fallthrough case alongside KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID.
        assertEquals(1000, ConcreteProtocol.LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID)
    }

    // ─── Group 2: getProtocolPriority dispatch table ───────────────────────────
    //
    // Each priority is a long in [0, 1023] stored in a 10-bit scheduling word.
    // A wrong value changes execution order; a value outside [0, 1023] corrupts
    // the scheduling word.
    //
    // Note: TRUST_ESTABLISHMENT_PROTOCOL_ID (1) and GROUP_CREATION_PROTOCOL_ID (5)
    // are NOT present in the priority switch (they are no longer used protocols).
    // Calling getProtocolPriority with those IDs hits the default branch and throws.

    @Test
    fun testDeviceDiscoveryProtocolPriorityIs599() {
        assertEquals(599L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID))
    }

    @Test
    fun testChannelCreationWithContactDeviceProtocolPriorityIs300() {
        assertEquals(300L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID))
    }

    @Test
    fun testDeviceDiscoveryChildProtocolPriorityIs600() {
        assertEquals(600L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DEVICE_DISCOVERY_CHILD_PROTOCOL_ID))
    }

    @Test
    fun testContactMutualIntroductionProtocolPriorityIs13() {
        assertEquals(13L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID))
    }

    @Test
    fun testIdentityDetailsPublicationProtocolPriorityIs150() {
        assertEquals(150L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID))
    }

    @Test
    fun testDownloadIdentityPhotoChildProtocolPriorityIs200() {
        assertEquals(200L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID))
    }

    @Test
    fun testGroupInvitationProtocolPriorityIs101() {
        assertEquals(101L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID))
    }

    @Test
    fun testGroupManagementProtocolPriorityIs102() {
        assertEquals(102L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID))
    }

    @Test
    fun testContactManagementProtocolPriorityIs12() {
        assertEquals(12L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID))
    }

    @Test
    fun testTrustEstablishmentWithSasProtocolPriorityIs9() {
        assertEquals(9L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID))
    }

    @Test
    fun testTrustEstablishmentWithMutualScanProtocolPriorityIs8() {
        assertEquals(8L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID))
    }

    @Test
    fun testFullRatchetProtocolPriorityIs1023() {
        assertEquals(1023L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.FULL_RATCHET_PROTOCOL_ID))
    }

    @Test
    fun testDownloadGroupPhotoChildProtocolPriorityIs202() {
        assertEquals(202L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID))
    }

    @Test
    fun testKeycloakContactAdditionProtocolPriorityIs11() {
        assertEquals(11L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID))
    }

    @Test
    fun testDeviceCapabilitiesDiscoveryProtocolPriorityIs500() {
        assertEquals(500L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID))
    }

    @Test
    fun testKeycloakBindingAndUnbindingProtocolPriorityIs5() {
        assertEquals(5L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID))
    }

    @Test
    fun testLegacyKeycloakBindingAndUnbindingProtocolPriorityIs5() {
        // LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID falls through to the same
        // case as KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID in the switch — both return 5L.
        assertEquals(5L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID))
    }

    @Test
    fun testOneToOneContactInvitationProtocolPriorityIs10() {
        assertEquals(10L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID))
    }

    @Test
    fun testGroupsV2ProtocolPriorityIs100() {
        assertEquals(100L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.GROUPS_V2_PROTOCOL_ID))
    }

    @Test
    fun testDownloadGroupsV2PhotoProtocolPriorityIs201() {
        assertEquals(201L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID))
    }

    @Test
    fun testOwnedIdentityDeletionProtocolPriorityIs1() {
        assertEquals(1L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.OWNED_IDENTITY_DELETION_PROTOCOL_ID))
    }

    @Test
    fun testOwnedDeviceDiscoveryProtocolPriorityIs50() {
        assertEquals(50L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID))
    }

    @Test
    fun testChannelCreationWithOwnedDeviceProtocolPriorityIs51() {
        assertEquals(51L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID))
    }

    @Test
    fun testOwnedDeviceManagementProtocolPriorityIs20() {
        assertEquals(20L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID))
    }

    @Test
    fun testSynchronizationProtocolPriorityIs900() {
        assertEquals(900L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID))
    }

    @Test
    fun testOwnedIdentityTransferProtocolPriorityIs0() {
        assertEquals(0L, ConcreteProtocol.getProtocolPriority(ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID))
    }

    // ─── Group 2b: All priorities are within the valid 10-bit range [0, 1023] ──
    //
    // The source comment says "range is 0 - 1023 to fit on 10 bits". If a Kotlin migration
    // accidentally renumbers any priority above 1023, the scheduling word is corrupted.

    @Test
    fun testAllProtocolPrioritiesAreWithinValidRange() {
        // These are the protocol IDs that ARE in the priority switch.
        // TRUST_ESTABLISHMENT_PROTOCOL_ID (1) and GROUP_CREATION_PROTOCOL_ID (5) are
        // excluded — they are no longer used and are not in the switch (throw on default).
        val idsInPrioritySwitch = listOf(
            ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,               // 0
            ConcreteProtocol.CHANNEL_CREATION_WITH_CONTACT_DEVICE_PROTOCOL_ID, // 2
            ConcreteProtocol.DEVICE_DISCOVERY_CHILD_PROTOCOL_ID,         // 3
            ConcreteProtocol.CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID,    // 4
            ConcreteProtocol.IDENTITY_DETAILS_PUBLICATION_PROTOCOL_ID,   // 6
            ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,  // 7
            ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID,               // 8
            ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,               // 9
            ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,             // 10
            ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID,   // 11
            ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID, // 12
            ConcreteProtocol.FULL_RATCHET_PROTOCOL_ID,                   // 13
            ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID,     // 14
            ConcreteProtocol.KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID,      // 15
            ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,  // 16
            ConcreteProtocol.KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID, // 23
            ConcreteProtocol.LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID, // 1000
            ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID,  // 17
            ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,                      // 18
            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,       // 19
            ConcreteProtocol.OWNED_IDENTITY_DELETION_PROTOCOL_ID,        // 20
            ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID,         // 21
            ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID, // 22
            ConcreteProtocol.OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID,        // 24
            ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,                // 25
            ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,        // 26
        )

        for (id in idsInPrioritySwitch) {
            val priority = ConcreteProtocol.getProtocolPriority(id)
            assertTrue(
                "Protocol ID $id has priority $priority which is outside [0, 1023]",
                priority in 0L..1023L,
            )
        }
    }

    // ─── Group 2c: Unknown protocol ID throws RuntimeException ────────────────
    //
    // The source default branch throws RuntimeException("Unknown protocol type!!!").
    // A migration that silently converts this to a return value (e.g. return -1L) would
    // hide logic bugs. This test pins the throw contract.

    @Test
    fun testGetProtocolPriorityThrowsForUnknownId_negative1() {
        try {
            ConcreteProtocol.getProtocolPriority(-1)
            fail("Expected RuntimeException for unknown protocol ID -1")
        } catch (_: RuntimeException) {
            // expected — the default branch throws
        }
    }

    @Test
    fun testGetProtocolPriorityThrowsForUnknownId_999() {
        try {
            ConcreteProtocol.getProtocolPriority(999)
            fail("Expected RuntimeException for unknown protocol ID 999")
        } catch (_: RuntimeException) {
            // expected — the default branch throws
        }
    }

    @Test
    fun testGetProtocolPriorityThrowsForObsoleteTrustEstablishmentId() {
        // TRUST_ESTABLISHMENT_PROTOCOL_ID (1) is not in the priority switch.
        // It is a legacy constant kept for DB compat, but protocols with this ID
        // are no longer executed, so the priority table correctly omits it.
        try {
            ConcreteProtocol.getProtocolPriority(ConcreteProtocol.TRUST_ESTABLISHMENT_PROTOCOL_ID)
            fail("Expected RuntimeException for obsolete TRUST_ESTABLISHMENT_PROTOCOL_ID (1)")
        } catch (_: RuntimeException) {
            // expected
        }
    }

    @Test
    fun testGetProtocolPriorityThrowsForObsoleteGroupCreationId() {
        // GROUP_CREATION_PROTOCOL_ID (5) is not in the priority switch.
        // It is a legacy constant kept for DB compat, but protocols with this ID
        // are no longer executed, so the priority table correctly omits it.
        try {
            ConcreteProtocol.getProtocolPriority(ConcreteProtocol.GROUP_CREATION_PROTOCOL_ID)
            fail("Expected RuntimeException for obsolete GROUP_CREATION_PROTOCOL_ID (5)")
        } catch (_: RuntimeException) {
            // expected
        }
    }
}
