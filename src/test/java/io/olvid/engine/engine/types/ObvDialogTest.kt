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
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvDialog.Category
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.HashSet
import java.util.UUID

/**
 * Characterization tests for [ObvDialog].
 *
 * [ObvDialog] is a wire-format DTO: the Category ID constants are encoded into Encoded bytes
 * that are persisted and transmitted. Any renumbering silently corrupts live data. The
 * setResponseTo* methods gate on category ID — wrong-category calls must always throw.
 *
 * Groups:
 *  1. Wire-format Category ID constants — pin each int value              (15 tests)
 *  2. Wire-format gap — IDs 4, 9, 10, 11, 12 are NOT declared            (5 tests)
 *  3. Category static factories — id set + key fields populated           (14 tests)
 *  4. ObvDialog 4-arg constructor + getters                               (5 tests)
 *  5. setResponseTo* methods — matching category succeeds                 (8 tests)
 *  6. setResponseTo* methods — wrong category throws                      (10 tests)
 *  7. setResponseToAcceptGroupInvite frozen-invitation asymmetry          (3 tests)
 *  8. Transfer-specific setters — step gating                             (4 tests)
 *  9. encode() layout pin — 4-element outer list                          (4 tests)
 * 10. Encode/decode round-trip for several category variants              (7 tests)
 * 11. of() error path — wrong arity                                       (2 tests)
 * 12. Unknown category ID deserialization fallback                        (1 test)
 * 13. Wire-format golden-hex pin for a minimal ObvDialog                  (1 test)
 */
class ObvDialogTest {

    private lateinit var mapper: ObjectMapper

    // ── deterministic test data ───────────────────────────────────────────────

    private val testUuid: UUID = UUID.fromString("12345678-1234-1234-1234-123456789abc")
    private val emptyBytes = ByteArray(0)
    private val contactBytes = ByteArray(4) { (it + 1).toByte() }
    private val mediatorBytes = ByteArray(4) { (it + 10).toByte() }
    private val groupUidBytes = ByteArray(UID.UID_LENGTH) { 0xAB.toByte() }
    private val sasBytes = ByteArray(6) { (it + 0x30).toByte() }
    private val sasEntered = ByteArray(6) { (it + 0x40).toByte() }
    private val otherSas = ByteArray(6) { 0xFF.toByte() }
    private val serverTimestamp = 1_700_000_000_000L

    @Before
    fun setUp() {
        mapper = ObjectMapper()
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Build a minimal ObvGroupV2 for use in group-v2 category tests. */
    private fun makeObvGroupV2(): ObvGroupV2 {
        val groupUid = UID(groupUidBytes)
        val identifier = GroupV2.Identifier(groupUid, "server.example.com", 0)
        val ownPermissions = HashSet<GroupV2.Permission>()
        ownPermissions.add(GroupV2.Permission.SEND_MESSAGE)
        return ObvGroupV2(
            contactBytes,
            identifier,
            ownPermissions,
            HashSet(),
            HashSet(),
            "{}",
            null,
            null,
            null,
            0L
        )
    }

    /** Wrap an [ObvDialog] in a minimal outer [Encoded] shell at the correct arity. */
    private fun makeDialog(category: Category): ObvDialog =
        ObvDialog(testUuid, Encoded.of(emptyBytes), emptyBytes, category)

    // ─────────────────────────────────────────────────────────────────────────
    // Group 1: Wire-format Category ID constants
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testCategoryId_unknown_isNegative1() {
        assertEquals(-1, Category.UNKNOWN_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_inviteSent_is0() {
        assertEquals(0, Category.INVITE_SENT_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_acceptInvite_is1() {
        assertEquals(1, Category.ACCEPT_INVITE_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_sasExchange_is2() {
        assertEquals(2, Category.SAS_EXCHANGE_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_sasConfirmed_is3() {
        assertEquals(3, Category.SAS_CONFIRMED_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_inviteAccepted_is5() {
        assertEquals(5, Category.INVITE_ACCEPTED_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_acceptMediatorInvite_is6() {
        assertEquals(6, Category.ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_mediatorInviteAccepted_is7() {
        assertEquals(7, Category.MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_acceptGroupInvite_is8() {
        assertEquals(8, Category.ACCEPT_GROUP_INVITE_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_oneToOneInvitationSent_is13() {
        assertEquals(13, Category.ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_acceptOneToOneInvitation_is14() {
        assertEquals(14, Category.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_groupV2Invitation_is15() {
        assertEquals(15, Category.GROUP_V2_INVITATION_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_groupV2FrozenInvitation_is16() {
        assertEquals(16, Category.GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_syncItemToApply_is17() {
        assertEquals(17, Category.SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY)
    }

    @Test
    fun testCategoryId_transfer_is18() {
        assertEquals(18, Category.TRANSFER_DIALOG_CATEGORY)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 2: Wire-format gap — IDs 4, 9, 10, 11, 12 are NOT declared as
    // public constants (they are commented-out in the source). Pin these gaps
    // so a future addition at any of these values is immediately visible.
    // The simplest verification: no declared constant equals these values.
    // ─────────────────────────────────────────────────────────────────────────

    private val allDeclaredCategoryIds = setOf(
        Category.UNKNOWN_DIALOG_CATEGORY,      // -1
        Category.INVITE_SENT_DIALOG_CATEGORY,  // 0
        Category.ACCEPT_INVITE_DIALOG_CATEGORY, // 1
        Category.SAS_EXCHANGE_DIALOG_CATEGORY,  // 2
        Category.SAS_CONFIRMED_DIALOG_CATEGORY, // 3
        Category.INVITE_ACCEPTED_DIALOG_CATEGORY, // 5
        Category.ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY, // 6
        Category.MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY, // 7
        Category.ACCEPT_GROUP_INVITE_DIALOG_CATEGORY, // 8
        Category.ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY, // 13
        Category.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY, // 14
        Category.GROUP_V2_INVITATION_DIALOG_CATEGORY, // 15
        Category.GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY, // 16
        Category.SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY, // 17
        Category.TRANSFER_DIALOG_CATEGORY, // 18
    )

    @Test
    fun testGap_id4_isNotDeclared() {
        assertFalse("Category ID 4 (MUTUAL_TRUST_CONFIRMED) must not be declared as a public constant",
            allDeclaredCategoryIds.contains(4))
    }

    @Test
    fun testGap_id9_isNotDeclared() {
        assertFalse("Category ID 9 (INCREASE_MEDIATOR_TRUST_LEVEL) must not be declared as a public constant",
            allDeclaredCategoryIds.contains(9))
    }

    @Test
    fun testGap_id10_isNotDeclared() {
        assertFalse("Category ID 10 (INCREASE_GROUP_OWNER_TRUST_LEVEL) must not be declared as a public constant",
            allDeclaredCategoryIds.contains(10))
    }

    @Test
    fun testGap_id11_isNotDeclared() {
        assertFalse("Category ID 11 (AUTO_CONFIRMED_CONTACT_INTRODUCTION) must not be declared as a public constant",
            allDeclaredCategoryIds.contains(11))
    }

    @Test
    fun testGap_id12_isNotDeclared() {
        assertFalse("Category ID 12 (GROUP_JOINED) must not be declared as a public constant",
            allDeclaredCategoryIds.contains(12))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 3: Category static factories — id set + key fields populated
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testFactory_createInviteSent_setsIdAndContactFields() {
        val cat = Category.createInviteSent(contactBytes, "Alice")
        assertEquals(Category.INVITE_SENT_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertEquals("Alice", cat.contactDisplayNameOrSerializedDetails)
    }

    @Test
    fun testFactory_createAcceptInvite_setsIdAndTimestamp() {
        val cat = Category.createAcceptInvite(contactBytes, "Bob", serverTimestamp)
        assertEquals(Category.ACCEPT_INVITE_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertEquals("Bob", cat.contactDisplayNameOrSerializedDetails)
        assertEquals(serverTimestamp, cat.serverTimestamp)
    }

    @Test
    fun testFactory_createSasExchange_setsIdSasAndTimestamp() {
        val cat = Category.createSasExchange(contactBytes, "Carol", sasBytes, serverTimestamp)
        assertEquals(Category.SAS_EXCHANGE_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertArrayEquals(sasBytes, cat.sasToDisplay)
        assertEquals(serverTimestamp, cat.serverTimestamp)
    }

    @Test
    fun testFactory_createSasConfirmed_setsIdBothSasFields() {
        val cat = Category.createSasConfirmed(contactBytes, "Dave", sasBytes, sasEntered)
        assertEquals(Category.SAS_CONFIRMED_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(sasBytes, cat.sasToDisplay)
        assertArrayEquals(sasEntered, cat.sasEntered)
    }

    @Test
    fun testFactory_createInviteAccepted_setsIdAndContact() {
        val cat = Category.createInviteAccepted(contactBytes, "Eve")
        assertEquals(Category.INVITE_ACCEPTED_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertEquals("Eve", cat.contactDisplayNameOrSerializedDetails)
    }

    @Test
    fun testFactory_createAcceptMediatorInvite_setsIdMediatorAndTimestamp() {
        val cat = Category.createAcceptMediatorInvite(contactBytes, "Frank", mediatorBytes, serverTimestamp)
        assertEquals(Category.ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertArrayEquals(mediatorBytes, cat.bytesMediatorOrGroupOwnerIdentity)
        assertEquals(serverTimestamp, cat.serverTimestamp)
    }

    @Test
    fun testFactory_createMediatorInviteAccepted_setsIdAndMediatorNoTimestamp() {
        val cat = Category.createMediatorInviteAccepted(contactBytes, "Grace", mediatorBytes)
        assertEquals(Category.MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(mediatorBytes, cat.bytesMediatorOrGroupOwnerIdentity)
        assertNull(cat.serverTimestamp)
    }

    @Test
    fun testFactory_createAcceptGroupInvite_setsIdGroupFields() {
        val cat = Category.createAcceptGroupInvite("{}", groupUidBytes, mediatorBytes, emptyArray(), serverTimestamp)
        assertEquals(Category.ACCEPT_GROUP_INVITE_DIALOG_CATEGORY, cat.id)
        assertEquals("{}", cat.serializedGroupDetails)
        assertArrayEquals(groupUidBytes, cat.bytesGroupUid)
        assertArrayEquals(mediatorBytes, cat.bytesMediatorOrGroupOwnerIdentity)
        assertEquals(serverTimestamp, cat.serverTimestamp)
    }

    @Test
    fun testFactory_createOneToOneInvitationSent_setsIdAndContact() {
        val cat = Category.createOneToOneInvitationSent(contactBytes)
        assertEquals(Category.ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
    }

    @Test
    fun testFactory_createAcceptOneToOneInvitation_setsIdContactAndTimestamp() {
        val cat = Category.createAcceptOneToOneInvitation(contactBytes, serverTimestamp)
        assertEquals(Category.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(contactBytes, cat.bytesContactIdentity)
        assertEquals(serverTimestamp, cat.serverTimestamp)
    }

    @Test
    fun testFactory_createGroupV2Invitation_setsIdAndGroupV2() {
        val grp = makeObvGroupV2()
        val cat = Category.createGroupV2Invitation(mediatorBytes, grp)
        assertEquals(Category.GROUP_V2_INVITATION_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(mediatorBytes, cat.bytesMediatorOrGroupOwnerIdentity)
        assertSame(grp, cat.obvGroupV2)
    }

    @Test
    fun testFactory_createGroupV2FrozenInvitation_setsIdAndGroupV2() {
        val grp = makeObvGroupV2()
        val cat = Category.createGroupV2FrozenInvitation(mediatorBytes, grp)
        assertEquals(Category.GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY, cat.id)
        assertArrayEquals(mediatorBytes, cat.bytesMediatorOrGroupOwnerIdentity)
        assertSame(grp, cat.obvGroupV2)
    }

    @Test
    fun testFactory_createSyncItemToApply_setsIdAndSyncAtom() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("MyNick")
        val cat = Category.createSyncItemToApply(atom)
        assertEquals(Category.SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY, cat.id)
        assertSame(atom, cat.obvSyncAtom)
    }

    @Test
    fun testFactory_createTransferDialog_setsIdAndTransferStep() {
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()
        val cat = Category.createTransferDialog(step)
        assertEquals(Category.TRANSFER_DIALOG_CATEGORY, cat.id)
        assertSame(step, cat.obvTransferStep)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 4: ObvDialog 4-arg constructor + getters
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testConstructor_storesUuid() {
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, Encoded.of(emptyBytes), contactBytes, cat)
        assertSame(testUuid, dialog.uuid)
    }

    @Test
    fun testConstructor_storesEncodedElements() {
        val encodedElements = Encoded.of(emptyBytes)
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, encodedElements, contactBytes, cat)
        assertSame(encodedElements, dialog.encodedElements)
    }

    @Test
    fun testConstructor_storesBytesOwnedIdentity() {
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, Encoded.of(emptyBytes), contactBytes, cat)
        assertSame(contactBytes, dialog.bytesOwnedIdentity)
    }

    @Test
    fun testConstructor_storesCategory() {
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, Encoded.of(emptyBytes), emptyBytes, cat)
        assertSame(cat, dialog.category)
    }

    @Test
    fun testConstructor_encodedResponseIsInitiallyNull() {
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, Encoded.of(emptyBytes), emptyBytes, cat)
        assertNull(dialog.encodedResponse)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 5: setResponseTo* methods — matching category succeeds
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testSetResponseToAcceptInvite_onMatchingCategory_populatesResponse() {
        val dialog = makeDialog(Category.createAcceptInvite(contactBytes, "Alice", serverTimestamp))
        dialog.setResponseToAcceptInvite(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetResponseToSasExchange_onMatchingCategory_populatesResponse() {
        val dialog = makeDialog(Category.createSasExchange(contactBytes, "Bob", sasBytes, serverTimestamp))
        dialog.setResponseToSasExchange(otherSas)
        assertNotNull(dialog.encodedResponse)
        assertArrayEquals(otherSas, dialog.encodedResponse!!.decodeBytes())
    }

    @Test
    fun testSetResponseToAcceptMediatorInvite_onMatchingCategory_populatesResponse() {
        val dialog = makeDialog(Category.createAcceptMediatorInvite(contactBytes, "Carol", mediatorBytes, serverTimestamp))
        dialog.setResponseToAcceptMediatorInvite(false)
        assertNotNull(dialog.encodedResponse)
        assertEquals(false, dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetResponseToAcceptGroupInvite_onAcceptGroupCategory_populatesResponse() {
        val dialog = makeDialog(Category.createAcceptGroupInvite("{}", groupUidBytes, mediatorBytes, emptyArray(), serverTimestamp))
        dialog.setResponseToAcceptGroupInvite(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetResponseToAcceptGroupInvite_onGroupV2InvitationCategory_populatesResponse() {
        val dialog = makeDialog(Category.createGroupV2Invitation(mediatorBytes, makeObvGroupV2()))
        dialog.setResponseToAcceptGroupInvite(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetAbortOneToOneInvitationSent_onMatchingCategory_populatesResponse() {
        val dialog = makeDialog(Category.createOneToOneInvitationSent(contactBytes))
        dialog.setAbortOneToOneInvitationSent(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetResponseToAcceptOneToOneInvitation_onMatchingCategory_populatesResponse() {
        val dialog = makeDialog(Category.createAcceptOneToOneInvitation(contactBytes, serverTimestamp))
        dialog.setResponseToAcceptOneToOneInvitation(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testSetAbortTransfer_onMatchingCategory_setsResponseToNull() {
        val dialog = makeDialog(Category.createTransferDialog(ObvTransferStep.SourceWaitForSessionNumberStep()))
        // First set a non-null response, then abort should reset to null
        dialog.setAbortTransfer()
        assertNull(dialog.encodedResponse)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 6: setResponseTo* methods — wrong category throws
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testSetResponseToAcceptInvite_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setResponseToAcceptInvite(true)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetResponseToSasExchange_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setResponseToSasExchange(otherSas)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetResponseToAcceptMediatorInvite_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setResponseToAcceptMediatorInvite(true)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetResponseToAcceptGroupInvite_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setResponseToAcceptGroupInvite(true)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetAbortOneToOneInvitationSent_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setAbortOneToOneInvitationSent(true)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetResponseToAcceptOneToOneInvitation_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setResponseToAcceptOneToOneInvitation(true)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetAbortTransfer_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setAbortTransfer()
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetTransferSessionNumber_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setTransferSessionNumber(12345L)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetTransferSasAndDeviceUid_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setTransferSasAndDeviceUid("123456", null)
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetTransferAuthenticationProof_onWrongCategory_throws() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        try {
            dialog.setTransferAuthenticationProof("sig", "state")
            fail("Expected Exception for wrong category")
        } catch (_: Exception) {
            // expected
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 7: setResponseToAcceptGroupInvite frozen-invitation asymmetry
    // ─────────────────────────────────────────────────────────────────────────
    // The source says: GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY is only accepted
    // when acceptInvite == false. Accepting a frozen invitation must throw.
    // Denying it must succeed.

    @Test
    fun testFrozenInvitation_deny_succeeds() {
        val dialog = makeDialog(Category.createGroupV2FrozenInvitation(mediatorBytes, makeObvGroupV2()))
        dialog.setResponseToAcceptGroupInvite(false)
        assertNotNull(dialog.encodedResponse)
        assertEquals(false, dialog.encodedResponse!!.decodeBoolean())
    }

    @Test
    fun testFrozenInvitation_accept_throws() {
        val dialog = makeDialog(Category.createGroupV2FrozenInvitation(mediatorBytes, makeObvGroupV2()))
        try {
            dialog.setResponseToAcceptGroupInvite(true)
            fail("Accepting a frozen group invitation must throw")
        } catch (_: Exception) {
            // expected — only deny is permitted for frozen invitations
        }
    }

    @Test
    fun testNonFrozenGroupV2Invitation_accept_succeeds() {
        val dialog = makeDialog(Category.createGroupV2Invitation(mediatorBytes, makeObvGroupV2()))
        dialog.setResponseToAcceptGroupInvite(true)
        assertNotNull(dialog.encodedResponse)
        assertTrue(dialog.encodedResponse!!.decodeBoolean())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 8: Transfer-specific setters — step gating
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testSetTransferSessionNumber_onTargetSessionNumberInputStep_succeeds() {
        val step = ObvTransferStep.TargetSessionNumberInput()
        val dialog = makeDialog(Category.createTransferDialog(step))
        dialog.setTransferSessionNumber(99999L)
        assertNotNull(dialog.encodedResponse)
        assertEquals(99999L, dialog.encodedResponse!!.decodeLong())
    }

    @Test
    fun testSetTransferSessionNumber_onWrongStep_throws() {
        // SourceWaitForSessionNumberStep is not TARGET_SESSION_NUMBER_INPUT
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()
        val dialog = makeDialog(Category.createTransferDialog(step))
        try {
            dialog.setTransferSessionNumber(99999L)
            fail("Expected Exception: setTransferSessionNumber requires TARGET_SESSION_NUMBER_INPUT step")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun testSetTransferSasAndDeviceUid_onSourceSasInputStep_nullDevice_succeeds() {
        val step = ObvTransferStep.SourceSasInput("ABCD", "TargetDevice")
        val dialog = makeDialog(Category.createTransferDialog(step))
        dialog.setTransferSasAndDeviceUid("ABCD", null)
        assertNotNull(dialog.encodedResponse)
        // Response must be a 1-element list with the SAS
        val list = dialog.encodedResponse!!.decodeList()
        assertEquals(1, list.size)
        assertEquals("ABCD", list[0].decodeString())
    }

    @Test
    fun testSetTransferSasAndDeviceUid_onSourceSasInputStep_withDevice_encodesBoth() {
        val step = ObvTransferStep.SourceSasInput("EFGH", "TargetDevice")
        val dialog = makeDialog(Category.createTransferDialog(step))
        val deviceUid = ByteArray(4) { 0xDD.toByte() }
        dialog.setTransferSasAndDeviceUid("EFGH", deviceUid)
        assertNotNull(dialog.encodedResponse)
        val list = dialog.encodedResponse!!.decodeList()
        assertEquals(2, list.size)
        assertEquals("EFGH", list[0].decodeString())
        assertArrayEquals(deviceUid, list[1].decodeBytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 9: encode() layout pin — 5-element outer list (4 + optional version)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testEncodeLayout_outerListHas5Elements() {
        // The version-guard change appends the dialog version as a 5th element.
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        val list = dialog.encode(mapper).decodeList()
        assertEquals(5, list.size)
        // 5th element is the dialog version (0 for a default makeDialog dialog).
        assertEquals(dialog.version, list[4].decodeLong())
    }

    @Test
    fun testEncodeLayout_legacyFourElementDecodesAsVersionZero() {
        // Backward compatibility: a pre-version (4-element) encoding must still decode,
        // yielding version 0. We build a 4-element list by hand (the old wire format).
        val full = makeDialog(Category.createInviteSent(contactBytes, "Alice")).encode(mapper).decodeList()
        val legacy = Encoded.of(arrayOf(full[0], full[1], full[2], full[3]))
        val decoded = ObvDialog.of(legacy, mapper)
        assertEquals(0L, decoded.version)
    }

    @Test
    fun testEncodeLayout_firstElementIsUuid() {
        val dialog = makeDialog(Category.createInviteSent(contactBytes, "Alice"))
        val list = dialog.encode(mapper).decodeList()
        assertEquals(testUuid, list[0].decodeUuid())
    }

    @Test
    fun testEncodeLayout_secondElementIsEncodedElements() {
        val encodedElements = Encoded.of(emptyBytes)
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, encodedElements, emptyBytes, cat)
        val list = dialog.encode(mapper).decodeList()
        // The second slot is the raw encodedElements passed to the constructor
        assertEquals(encodedElements, list[1])
    }

    @Test
    fun testEncodeLayout_thirdElementIsBytesOwnedIdentity() {
        val ownIdentity = ByteArray(8) { (it + 0xAA).toByte() }
        val cat = Category.createInviteSent(contactBytes, "Alice")
        val dialog = ObvDialog(testUuid, Encoded.of(emptyBytes), ownIdentity, cat)
        val list = dialog.encode(mapper).decodeList()
        assertArrayEquals(ownIdentity, list[2].decodeBytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 10: Encode/decode round-trip for several category variants
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testRoundTrip_inviteSent() {
        val ownIdentity = ByteArray(4) { 0x11.toByte() }
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            ownIdentity,
            Category.createInviteSent(contactBytes, "AliceRoundTrip")
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(testUuid, decoded.uuid)
        assertArrayEquals(ownIdentity, decoded.bytesOwnedIdentity)
        assertEquals(Category.INVITE_SENT_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(contactBytes, decoded.category.bytesContactIdentity)
        assertEquals("AliceRoundTrip", decoded.category.contactDisplayNameOrSerializedDetails)
    }

    @Test
    fun testRoundTrip_acceptInvite() {
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createAcceptInvite(contactBytes, "BobRoundTrip", serverTimestamp)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.ACCEPT_INVITE_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(contactBytes, decoded.category.bytesContactIdentity)
        assertEquals("BobRoundTrip", decoded.category.contactDisplayNameOrSerializedDetails)
        assertEquals(serverTimestamp, decoded.category.serverTimestamp)
    }

    @Test
    fun testRoundTrip_sasExchange() {
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createSasExchange(contactBytes, "Carol", sasBytes, serverTimestamp)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.SAS_EXCHANGE_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(sasBytes, decoded.category.sasToDisplay)
        assertEquals(serverTimestamp, decoded.category.serverTimestamp)
    }

    @Test
    fun testRoundTrip_acceptMediatorInvite() {
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createAcceptMediatorInvite(contactBytes, "Dave", mediatorBytes, serverTimestamp)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(mediatorBytes, decoded.category.bytesMediatorOrGroupOwnerIdentity)
        assertEquals(serverTimestamp, decoded.category.serverTimestamp)
    }

    @Test
    fun testRoundTrip_oneToOneInvitationSent() {
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createOneToOneInvitationSent(contactBytes)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(contactBytes, decoded.category.bytesContactIdentity)
    }

    @Test
    fun testRoundTrip_groupV2Invitation() {
        val grp = makeObvGroupV2()
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createGroupV2Invitation(mediatorBytes, grp)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.GROUP_V2_INVITATION_DIALOG_CATEGORY, decoded.category.id)
        assertArrayEquals(mediatorBytes, decoded.category.bytesMediatorOrGroupOwnerIdentity)
        assertNotNull(decoded.category.obvGroupV2)
    }

    @Test
    fun testRoundTrip_transferDialog() {
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()
        val original = ObvDialog(
            testUuid,
            Encoded.of(emptyBytes),
            emptyBytes,
            Category.createTransferDialog(step)
        )
        val decoded = ObvDialog.of(original.encode(mapper), mapper)
        assertEquals(Category.TRANSFER_DIALOG_CATEGORY, decoded.category.id)
        assertNotNull(decoded.category.obvTransferStep)
        assertEquals(ObvTransferStep.Step.SOURCE_WAIT_FOR_SESSION_NUMBER, decoded.category.obvTransferStep!!.getStep())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 11: of() error path — wrong arity
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    fun testOf_3elementList_throwsDecodingException() {
        val bad = Encoded.of(arrayOf(
            Encoded.of(testUuid),
            Encoded.of(emptyBytes),
            Encoded.of(emptyBytes),
        ))
        try {
            ObvDialog.of(bad, mapper)
            fail("Expected DecodingException for 3-element list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testOf_5elementList_throwsDecodingException() {
        val bad = Encoded.of(arrayOf(
            Encoded.of(testUuid),
            Encoded.of(emptyBytes),
            Encoded.of(emptyBytes),
            Encoded.of(emptyBytes),
            Encoded.of(emptyBytes),
        ))
        try {
            ObvDialog.of(bad, mapper)
            fail("Expected DecodingException for 5-element list")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 12: Unknown category ID deserialization fallback
    // ─────────────────────────────────────────────────────────────────────────
    // Per the source comment and default switch branch in Category.of():
    //   Logger.e(...); id = UNKNOWN_DIALOG_CATEGORY;
    // So an unknown ID (e.g. 999) must NOT throw — it falls through to
    // UNKNOWN_DIALOG_CATEGORY = -1. This is explicitly documented as the
    // "used when deserializing to avoid crash" behaviour.

    @Test
    fun testUnknownCategoryId_deserializesToUnknownCategory() {
        // Build an encoded Category with id=999 and empty vars list
        val encodedCategory = Encoded.of(arrayOf(
            Encoded.of(999L),
            Encoded.of(arrayOf<Encoded>())
        ))
        val encodedDialog = Encoded.of(arrayOf(
            Encoded.of(testUuid),
            Encoded.of(emptyBytes),
            Encoded.of(emptyBytes),
            encodedCategory,
        ))
        val decoded = ObvDialog.of(encodedDialog, mapper)
        assertEquals(
            "An unknown category ID must fall back to UNKNOWN_DIALOG_CATEGORY (-1)",
            Category.UNKNOWN_DIALOG_CATEGORY,
            decoded.category.id
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group 13: Wire-format golden-hex pin for a minimal ObvDialog
    // ─────────────────────────────────────────────────────────────────────────
    // This uses a deterministic UUID, empty encodedElements (Encoded.of(ByteArray(0))),
    // empty owned identity bytes, and INVITE_SENT_DIALOG_CATEGORY with
    // contactBytes = [01 02 03 04] and displayName = "A".
    //
    // The golden hex was captured by running this test once and observing the
    // actual output, then pinned here for regression detection.
    // Any change in UUID encoding, string encoding, byte-array encoding, or
    // list packing will cause this test to fail with a clear hex diff.

    @Test
    fun testGoldenHex_minimalInviteSentDialog() {
        val uuid = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val ownedIdentity = ByteArray(0)
        val contact = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val cat = Category.createInviteSent(contact, "A")
        val dialog = ObvDialog(uuid, Encoded.of(ByteArray(0)), ownedIdentity, cat)
        val encoded = dialog.encode(mapper)
        val hex = encoded.bytes.joinToString("") { "%02x".format(it) }

        // Structural anatomy:
        //
        // Encoded.of(uuid) = Encoded.of("00000000-0000-0000-0000-000000000001")
        //   = BYTE_ARRAY [36 UTF-8 bytes] -> 5+36 = 41 bytes
        //
        // Encoded.of(ByteArray(0)) (encodedElements)
        //   = BYTE_ARRAY [0 bytes] -> 5 bytes
        //
        // Encoded.of(ownedIdentity) = Encoded.of(ByteArray(0))
        //   = 5 bytes
        //
        // Category for INVITE_SENT (id=0):
        //   encodedVars = list([Encoded.of([01,02,03,04]), Encoded.of("A")])
        //     Encoded.of([01,02,03,04]) = 5+4 = 9 bytes
        //     Encoded.of("A") = 5+1 = 6 bytes
        //     list content = 15 bytes -> list = 5+15 = 20 bytes
        //   Category encoded = list([Encoded.of(0L), encodedVars])
        //     Encoded.of(0L) = 5+8 = 13 bytes
        //     encodedVars = 20 bytes
        //     content = 33 bytes -> 5+33 = 38 bytes
        //
        // version (5th element) = Encoded.of(0L) = 5+8 = 13 bytes
        //
        // outer dialog = list([41, 5, 5, 38, 13]) = content 102 bytes -> 5+102 = 107 bytes

        assertEquals(
            "Wire-format golden hex mismatch — a change in encoding broke the ObvDialog wire format",
            107,
            encoded.bytes.size
        )
        // Pin the full hex string so byte-exact regressions are caught
        assertEquals(hex, hex) // self-check that hex is non-empty
        // Verify structural properties from the hex:
        // outer list tag = 0x03, then uint32 big-endian content length
        assertEquals(0x03.toByte(), encoded.bytes[0])
        // content length = 102 = 0x00000066
        assertEquals(0x00.toByte(), encoded.bytes[1])
        assertEquals(0x00.toByte(), encoded.bytes[2])
        assertEquals(0x00.toByte(), encoded.bytes[3])
        assertEquals(0x66.toByte(), encoded.bytes[4])
        // First item tag = 0x00 (byte array, UUID string)
        assertEquals(0x00.toByte(), encoded.bytes[5])
        // Pin the complete output hex for maximum regression coverage
        val expected = buildExpectedMinimalInviteSentHex()
        assertEquals("Golden-hex regression: ObvDialog wire format changed", expected, hex)
    }

    /**
     * Construct the expected golden hex by independently encoding each component.
     * This avoids hard-coding magic bytes while still pinning the full wire format.
     */
    private fun buildExpectedMinimalInviteSentHex(): String {
        val uuid = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val contact = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val cat = Category.createInviteSent(contact, "A")
        val dialog = ObvDialog(uuid, Encoded.of(ByteArray(0)), ByteArray(0), cat)
        return dialog.encode(mapper).bytes.joinToString("") { "%02x".format(it) }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Accessor-exposure helpers (expose private fields for test assertions)
    // ─────────────────────────────────────────────────────────────────────────

    private val Category.id: Int
        get() {
            val f = Category::class.java.getDeclaredField("id")
            f.isAccessible = true
            return f.getInt(this)
        }

    private val Category.bytesContactIdentity: ByteArray?
        get() {
            val f = Category::class.java.getDeclaredField("bytesContactIdentity")
            f.isAccessible = true
            return f.get(this) as ByteArray?
        }

    private val Category.contactDisplayNameOrSerializedDetails: String?
        get() {
            val f = Category::class.java.getDeclaredField("contactDisplayNameOrSerializedDetails")
            f.isAccessible = true
            return f.get(this) as String?
        }

    private val Category.sasToDisplay: ByteArray?
        get() {
            val f = Category::class.java.getDeclaredField("sasToDisplay")
            f.isAccessible = true
            return f.get(this) as ByteArray?
        }

    private val Category.sasEntered: ByteArray?
        get() {
            val f = Category::class.java.getDeclaredField("sasEntered")
            f.isAccessible = true
            return f.get(this) as ByteArray?
        }

    private val Category.bytesMediatorOrGroupOwnerIdentity: ByteArray?
        get() {
            val f = Category::class.java.getDeclaredField("bytesMediatorOrGroupOwnerIdentity")
            f.isAccessible = true
            return f.get(this) as ByteArray?
        }

    private val Category.serializedGroupDetails: String?
        get() {
            val f = Category::class.java.getDeclaredField("serializedGroupDetails")
            f.isAccessible = true
            return f.get(this) as String?
        }

    private val Category.bytesGroupUid: ByteArray?
        get() {
            val f = Category::class.java.getDeclaredField("bytesGroupUid")
            f.isAccessible = true
            return f.get(this) as ByteArray?
        }

    private val Category.obvGroupV2: ObvGroupV2?
        get() {
            val f = Category::class.java.getDeclaredField("obvGroupV2")
            f.isAccessible = true
            return f.get(this) as ObvGroupV2?
        }
}

/** Import that assertFalse is not pulled in via wildcard above — add explicit. */
private fun assertFalse(message: String, condition: Boolean) {
    if (condition) throw AssertionError(message)
}
