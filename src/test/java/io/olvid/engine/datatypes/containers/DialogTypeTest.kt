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
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.engine.types.ObvTransferStep
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test
import java.util.HashSet

/**
 * Characterization tests for [DialogType].
 *
 * Written before migrating DialogType from Java to Kotlin. Each factory method is exercised
 * to confirm the `id` constant, that the correct fields are populated, and that all
 * non-relevant fields are left null.
 */
class DialogTypeTest {

    // --- test fixtures ---

    private lateinit var contactIdentity: Identity
    private lateinit var mediatorIdentity: Identity
    private lateinit var groupOwnerIdentity: Identity
    private lateinit var groupUid: UID

    @Before
    fun setUp() {
        // Silence logger — DialogType itself is silent, but Identity / UID helpers may log.
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        fun makeIdentity(server: String): Identity {
            val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
            val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
            return Identity(
                server,
                serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
                encryptionKeyPair.publicKey as EncryptionPublicKey
            )
        }

        contactIdentity = makeIdentity("contact.olvid.io")
        mediatorIdentity = makeIdentity("mediator.olvid.io")
        groupOwnerIdentity = makeIdentity("groupowner.olvid.io")
        groupUid = UID(prng)
    }

    // -----------------------------------------------------------------------
    // ID constant values
    // -----------------------------------------------------------------------

    @Test
    fun testIdConstantValues() {
        assertEquals(-1, DialogType.DELETE_DIALOG_ID)
        assertEquals(0,  DialogType.INVITE_SENT_DIALOG_ID)
        assertEquals(1,  DialogType.ACCEPT_INVITE_DIALOG_ID)
        assertEquals(2,  DialogType.SAS_EXCHANGE_DIALOG_ID)
        assertEquals(3,  DialogType.SAS_CONFIRMED_DIALOG_ID)
        assertEquals(5,  DialogType.INVITE_ACCEPTED_DIALOG_ID)
        assertEquals(6,  DialogType.ACCEPT_MEDIATOR_INVITE_DIALOG_ID)
        assertEquals(7,  DialogType.MEDIATOR_INVITE_ACCEPTED_DIALOG_ID)
        assertEquals(8,  DialogType.ACCEPT_GROUP_INVITE_DIALOG_ID)
        assertEquals(13, DialogType.ONE_TO_ONE_INVITATION_SENT_DIALOG_ID)
        assertEquals(14, DialogType.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_ID)
        assertEquals(15, DialogType.ACCEPT_GROUP_V2_INVITATION_DIALOG_ID)
        assertEquals(16, DialogType.GROUP_V2_FROZEN_INVITATION_DIALOG_ID)
        assertEquals(17, DialogType.SYNC_ITEM_TO_APPLY_DIALOG_ID)
        assertEquals(18, DialogType.TRANSFER_DIALOG_ID)
    }

    // -----------------------------------------------------------------------
    // createDeleteDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateDeleteDialog_hasCorrectId() {
        val d = DialogType.createDeleteDialog()
        assertEquals(DialogType.DELETE_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateDeleteDialog_allFieldsNull() {
        val d = DialogType.createDeleteDialog()
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.contactIdentity)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createInviteSentDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateInviteSentDialog_hasCorrectId() {
        val d = DialogType.createInviteSentDialog("Alice", contactIdentity)
        assertEquals(DialogType.INVITE_SENT_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateInviteSentDialog_populatesCorrectFields() {
        val d = DialogType.createInviteSentDialog("Alice", contactIdentity)
        assertEquals("Alice", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        // all others null
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createAcceptInviteDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateAcceptInviteDialog_hasCorrectId() {
        val d = DialogType.createAcceptInviteDialog("{}", contactIdentity, 1_000L)
        assertEquals(DialogType.ACCEPT_INVITE_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateAcceptInviteDialog_populatesCorrectFields() {
        val ts = 99_999L
        val d = DialogType.createAcceptInviteDialog("{\"name\":\"Bob\"}", contactIdentity, ts)
        assertEquals("{\"name\":\"Bob\"}", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertEquals(ts, d.serverTimestamp)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createSasExchangeDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateSasExchangeDialog_hasCorrectId() {
        val d = DialogType.createSasExchangeDialog("{}", contactIdentity, byteArrayOf(1, 2, 3, 4), 0L)
        assertEquals(DialogType.SAS_EXCHANGE_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateSasExchangeDialog_populatesCorrectFields() {
        val sas = byteArrayOf(0xA, 0xB, 0xC, 0xD)
        val ts = 12345L
        val d = DialogType.createSasExchangeDialog("details", contactIdentity, sas, ts)
        assertEquals("details", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertArrayEquals(sas, d.sasToDisplay)
        assertEquals(ts, d.serverTimestamp)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createSasConfirmedDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateSasConfirmedDialog_hasCorrectId() {
        val d = DialogType.createSasConfirmedDialog("{}", contactIdentity, byteArrayOf(1), byteArrayOf(2))
        assertEquals(DialogType.SAS_CONFIRMED_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateSasConfirmedDialog_populatesCorrectFields() {
        val sasToDisplay = byteArrayOf(1, 2, 3)
        val sasEntered  = byteArrayOf(4, 5, 6)
        val d = DialogType.createSasConfirmedDialog("details", contactIdentity, sasToDisplay, sasEntered)
        assertEquals("details", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertArrayEquals(sasToDisplay, d.sasToDisplay)
        assertArrayEquals(sasEntered, d.sasEntered)
        assertNull(d.serverTimestamp)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createInviteAcceptedDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateInviteAcceptedDialog_hasCorrectId() {
        val d = DialogType.createInviteAcceptedDialog("details", contactIdentity)
        assertEquals(DialogType.INVITE_ACCEPTED_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateInviteAcceptedDialog_populatesCorrectFields() {
        val d = DialogType.createInviteAcceptedDialog("details", contactIdentity)
        assertEquals("details", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createAcceptMediatorInviteDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateAcceptMediatorInviteDialog_hasCorrectId() {
        val d = DialogType.createAcceptMediatorInviteDialog("details", contactIdentity, mediatorIdentity, 0L)
        assertEquals(DialogType.ACCEPT_MEDIATOR_INVITE_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateAcceptMediatorInviteDialog_populatesCorrectFields() {
        val ts = 55_000L
        val d = DialogType.createAcceptMediatorInviteDialog("details", contactIdentity, mediatorIdentity, ts)
        assertEquals("details", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertSame(mediatorIdentity, d.mediatorOrGroupOwnerIdentity)
        assertEquals(ts, d.serverTimestamp)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createMediatorInviteAcceptedDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateMediatorInviteAcceptedDialog_hasCorrectId() {
        val d = DialogType.createMediatorInviteAcceptedDialog("details", contactIdentity, mediatorIdentity)
        assertEquals(DialogType.MEDIATOR_INVITE_ACCEPTED_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateMediatorInviteAcceptedDialog_populatesCorrectFields() {
        val d = DialogType.createMediatorInviteAcceptedDialog("details", contactIdentity, mediatorIdentity)
        assertEquals("details", d.contactDisplayNameOrSerializedDetails)
        assertSame(contactIdentity, d.contactIdentity)
        assertSame(mediatorIdentity, d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serverTimestamp)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createAcceptGroupInviteDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateAcceptGroupInviteDialog_hasCorrectId() {
        val d = DialogType.createAcceptGroupInviteDialog(
            "groupDetails", groupUid, groupOwnerIdentity,
            arrayOf(contactIdentity), arrayOf("contact details"), 0L
        )
        assertEquals(DialogType.ACCEPT_GROUP_INVITE_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateAcceptGroupInviteDialog_populatesCorrectFields() {
        val ts = 77_000L
        val members = arrayOf<Identity?>(contactIdentity, mediatorIdentity)
        val memberDetails = arrayOf<String?>("cd1", "cd2")
        val d = DialogType.createAcceptGroupInviteDialog(
            "groupDetails", groupUid, groupOwnerIdentity, members, memberDetails, ts
        )
        assertEquals("groupDetails", d.serializedGroupDetails)
        assertSame(groupUid, d.groupUid)
        assertSame(groupOwnerIdentity, d.mediatorOrGroupOwnerIdentity)
        assertEquals(ts, d.serverTimestamp)
        assertNotNull(d.pendingGroupMemberIdentities)
        assertEquals(2, d.pendingGroupMemberIdentities!!.size)
        assertSame(contactIdentity, d.pendingGroupMemberIdentities[0])
        assertSame(mediatorIdentity, d.pendingGroupMemberIdentities[1])
        assertNotNull(d.pendingGroupMemberSerializedDetails)
        assertEquals(2, d.pendingGroupMemberSerializedDetails!!.size)
        assertEquals("cd1", d.pendingGroupMemberSerializedDetails[0])
        assertEquals("cd2", d.pendingGroupMemberSerializedDetails[1])
        // contactIdentity/contactDisplayName fields unused by this factory
        assertNull(d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createOneToOneInvitationSentDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateOneToOneInvitationSentDialog_hasCorrectId() {
        val d = DialogType.createOneToOneInvitationSentDialog(contactIdentity)
        assertEquals(DialogType.ONE_TO_ONE_INVITATION_SENT_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateOneToOneInvitationSentDialog_populatesCorrectFields() {
        val d = DialogType.createOneToOneInvitationSentDialog(contactIdentity)
        assertSame(contactIdentity, d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createAcceptOneToOneInvitationDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateAcceptOneToOneInvitationDialog_hasCorrectId() {
        val d = DialogType.createAcceptOneToOneInvitationDialog(contactIdentity, 0L)
        assertEquals(DialogType.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateAcceptOneToOneInvitationDialog_populatesCorrectFields() {
        val ts = 88_888L
        val d = DialogType.createAcceptOneToOneInvitationDialog(contactIdentity, ts)
        assertSame(contactIdentity, d.contactIdentity)
        assertEquals(ts, d.serverTimestamp)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createGroupV2InvitationDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateGroupV2InvitationDialog_hasCorrectId() {
        val obvGroupV2 = makeObvGroupV2()
        val d = DialogType.createGroupV2InvitationDialog(mediatorIdentity, obvGroupV2)
        assertEquals(DialogType.ACCEPT_GROUP_V2_INVITATION_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateGroupV2InvitationDialog_populatesCorrectFields() {
        val obvGroupV2 = makeObvGroupV2()
        val d = DialogType.createGroupV2InvitationDialog(mediatorIdentity, obvGroupV2)
        assertSame(mediatorIdentity, d.mediatorOrGroupOwnerIdentity)
        assertSame(obvGroupV2, d.obvGroupV2)
        assertNull(d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createGroupV2FrozenInvitationDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateGroupV2FrozenInvitationDialog_hasCorrectId() {
        val obvGroupV2 = makeObvGroupV2()
        val d = DialogType.createGroupV2FrozenInvitationDialog(mediatorIdentity, obvGroupV2)
        assertEquals(DialogType.GROUP_V2_FROZEN_INVITATION_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateGroupV2FrozenInvitationDialog_populatesCorrectFields() {
        val obvGroupV2 = makeObvGroupV2()
        val d = DialogType.createGroupV2FrozenInvitationDialog(mediatorIdentity, obvGroupV2)
        assertSame(mediatorIdentity, d.mediatorOrGroupOwnerIdentity)
        assertSame(obvGroupV2, d.obvGroupV2)
        assertNull(d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvSyncAtom)
        assertNull(d.obvTransferStep)
    }

    /** Both Group V2 invitation variants differ only by id — other fields must match. */
    @Test
    fun testGroupV2InvitationVsFrozen_differOnlyById() {
        val obvGroupV2 = makeObvGroupV2()
        val invitation = DialogType.createGroupV2InvitationDialog(mediatorIdentity, obvGroupV2)
        val frozen     = DialogType.createGroupV2FrozenInvitationDialog(mediatorIdentity, obvGroupV2)

        // Only the id differs
        assertEquals(DialogType.ACCEPT_GROUP_V2_INVITATION_DIALOG_ID, invitation.id)
        assertEquals(DialogType.GROUP_V2_FROZEN_INVITATION_DIALOG_ID, frozen.id)

        // Payload is identical
        assertSame(invitation.mediatorOrGroupOwnerIdentity, frozen.mediatorOrGroupOwnerIdentity)
        assertSame(invitation.obvGroupV2, frozen.obvGroupV2)
    }

    // -----------------------------------------------------------------------
    // createSyncItemToApplyDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateSyncItemToApplyDialog_hasCorrectId() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("newNick")
        val d = DialogType.createSyncItemToApplyDialog(atom)
        assertEquals(DialogType.SYNC_ITEM_TO_APPLY_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateSyncItemToApplyDialog_populatesCorrectFields() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("newNick")
        val d = DialogType.createSyncItemToApplyDialog(atom)
        assertSame(atom, d.obvSyncAtom)
        assertNull(d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvTransferStep)
    }

    // -----------------------------------------------------------------------
    // createTransferDialog
    // -----------------------------------------------------------------------

    @Test
    fun testCreateTransferDialog_hasCorrectId() {
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()
        val d = DialogType.createTransferDialog(step)
        assertEquals(DialogType.TRANSFER_DIALOG_ID, d.id)
    }

    @Test
    fun testCreateTransferDialog_populatesCorrectFields() {
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()
        val d = DialogType.createTransferDialog(step)
        assertSame(step, d.obvTransferStep)
        assertNull(d.contactIdentity)
        assertNull(d.contactDisplayNameOrSerializedDetails)
        assertNull(d.sasToDisplay)
        assertNull(d.sasEntered)
        assertNull(d.mediatorOrGroupOwnerIdentity)
        assertNull(d.serializedGroupDetails)
        assertNull(d.groupUid)
        assertNull(d.pendingGroupMemberIdentities)
        assertNull(d.pendingGroupMemberSerializedDetails)
        assertNull(d.serverTimestamp)
        assertNull(d.obvGroupV2)
        assertNull(d.obvSyncAtom)
    }

    /** A non-trivial ObvTransferStep subclass is stored intact. */
    @Test
    fun testCreateTransferDialog_withSessionNumberStep() {
        val step = ObvTransferStep.SourceDisplaySessionNumber(42L)
        val d = DialogType.createTransferDialog(step)
        assertEquals(DialogType.TRANSFER_DIALOG_ID, d.id)
        val stored = d.obvTransferStep as ObvTransferStep.SourceDisplaySessionNumber
        assertEquals(42L, stored.sessionNumber)
    }

    // -----------------------------------------------------------------------
    // dispatch: each factory produces a distinct id
    // -----------------------------------------------------------------------

    @Test
    fun testAllFactoriesProduceDistinctIds() {
        val obvGroupV2 = makeObvGroupV2()
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("x")
        val step = ObvTransferStep.SourceWaitForSessionNumberStep()

        val dialogs = listOf(
            DialogType.createDeleteDialog(),
            DialogType.createInviteSentDialog("n", contactIdentity),
            DialogType.createAcceptInviteDialog("{}", contactIdentity, 0L),
            DialogType.createSasExchangeDialog("{}", contactIdentity, byteArrayOf(1), 0L),
            DialogType.createSasConfirmedDialog("{}", contactIdentity, byteArrayOf(1), byteArrayOf(2)),
            DialogType.createInviteAcceptedDialog("{}", contactIdentity),
            DialogType.createAcceptMediatorInviteDialog("{}", contactIdentity, mediatorIdentity, 0L),
            DialogType.createMediatorInviteAcceptedDialog("{}", contactIdentity, mediatorIdentity),
            DialogType.createAcceptGroupInviteDialog("gd", groupUid, groupOwnerIdentity, emptyArray(), emptyArray(), 0L),
            DialogType.createOneToOneInvitationSentDialog(contactIdentity),
            DialogType.createAcceptOneToOneInvitationDialog(contactIdentity, 0L),
            DialogType.createGroupV2InvitationDialog(mediatorIdentity, obvGroupV2),
            DialogType.createGroupV2FrozenInvitationDialog(mediatorIdentity, obvGroupV2),
            DialogType.createSyncItemToApplyDialog(atom),
            DialogType.createTransferDialog(step),
        )

        val ids = dialogs.map { it.id }
        // All ids should be unique
        assertEquals("Expected all factory ids to be distinct", ids.size, ids.toSet().size)
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private fun makeObvGroupV2(): ObvGroupV2 {
        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32) { 7 }))
        val uid = UID(prng)
        val identifier = GroupV2.Identifier(uid, "test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        return ObvGroupV2(
            ByteArray(32),           // bytesOwnedIdentity
            identifier,
            HashSet(),               // ownPermissions
            HashSet(),               // otherGroupMembers
            HashSet(),               // pendingGroupMembers
            "{}",                    // serializedGroupDetails
            null,                    // photoUrl
            null,                    // serializedPublishedDetails
            null,                    // publishedPhotoUrl
            0L                       // lastModificationTimestamp
        )
    }
}
