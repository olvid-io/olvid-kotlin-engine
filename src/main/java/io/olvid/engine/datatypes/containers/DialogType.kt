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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.engine.types.ObvTransferStep
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.sync.ObvSyncAtom


class DialogType private constructor(
    @JvmField val id: Int,
    @JvmField val contactDisplayNameOrSerializedDetails: String?,
    @JvmField val contactIdentity: Identity?,
    @JvmField val sasToDisplay: ByteArray?,
    @JvmField val sasEntered: ByteArray?,
    @JvmField val mediatorOrGroupOwnerIdentity: Identity?,
    @JvmField val serializedGroupDetails: String?,
    @JvmField val groupUid: UID?,
    @JvmField val pendingGroupMemberIdentities: Array<Identity?>?,
    @JvmField val pendingGroupMemberSerializedDetails: Array<String?>?,
    @JvmField val serverTimestamp: Long?,
    @JvmField val obvGroupV2: ObvGroupV2?,
    @JvmField val obvSyncAtom: ObvSyncAtom?,
    @JvmField val obvTransferStep: ObvTransferStep?,
    // only meaningful for DELETE_DIALOG: version (= creation timestamp) of the dialog to delete.
    // 0 means unknown/legacy → delete unconditionally.
    @JvmField val version: Long = 0
) {
    companion object {
        const val DELETE_DIALOG_ID: Int = -1
        const val INVITE_SENT_DIALOG_ID: Int = 0
        const val ACCEPT_INVITE_DIALOG_ID: Int = 1
        const val SAS_EXCHANGE_DIALOG_ID: Int = 2
        const val SAS_CONFIRMED_DIALOG_ID: Int = 3

        //public static final int MUTUAL_TRUST_CONFIRMED_DIALOG_ID = 4;
        const val INVITE_ACCEPTED_DIALOG_ID: Int = 5
        const val ACCEPT_MEDIATOR_INVITE_DIALOG_ID: Int = 6
        const val MEDIATOR_INVITE_ACCEPTED_DIALOG_ID: Int = 7
        const val ACCEPT_GROUP_INVITE_DIALOG_ID: Int = 8

        //    public static final int INCREASE_MEDIATOR_TRUST_LEVEL_DIALOG_ID = 9;
        //    public static final int INCREASE_GROUP_OWNER_TRUST_LEVEL_DIALOG_ID = 10;
        //    public static final int AUTO_CONFIRMED_CONTACT_INTRODUCTION_DIALOG_ID = 11;
        //    public static final int GROUP_JOINED_DIALOG_ID = 12;
        const val ONE_TO_ONE_INVITATION_SENT_DIALOG_ID: Int = 13
        const val ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_ID: Int = 14
        const val ACCEPT_GROUP_V2_INVITATION_DIALOG_ID: Int = 15
        const val GROUP_V2_FROZEN_INVITATION_DIALOG_ID: Int = 16
        const val SYNC_ITEM_TO_APPLY_DIALOG_ID: Int = 17
        const val TRANSFER_DIALOG_ID: Int = 18


        @JvmStatic
        @JvmOverloads
        fun createDeleteDialog(version: Long = 0): DialogType {
            return DialogType(
                DELETE_DIALOG_ID,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                version
            )
        }

        @JvmStatic
        fun createInviteSentDialog(
            contactDisplayName: String?,
            contactIdentity: Identity?
        ): DialogType {
            return DialogType(
                INVITE_SENT_DIALOG_ID,
                contactDisplayName,
                contactIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAcceptInviteDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?,
            serverTimestamp: Long
        ): DialogType {
            return DialogType(
                ACCEPT_INVITE_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                serverTimestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createSasExchangeDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?,
            sasToDisplay: ByteArray?,
            serverTimestamp: Long
        ): DialogType {
            return DialogType(
                SAS_EXCHANGE_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                sasToDisplay,
                null,
                null,
                null,
                null,
                null,
                null,
                serverTimestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createSasConfirmedDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?,
            sasToDisplay: ByteArray?,
            sasEntered: ByteArray?
        ): DialogType {
            return DialogType(
                SAS_CONFIRMED_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                sasToDisplay,
                sasEntered,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createInviteAcceptedDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?
        ): DialogType {
            return DialogType(
                INVITE_ACCEPTED_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAcceptMediatorInviteDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?,
            mediatorIdentity: Identity?,
            serverTimestamp: Long
        ): DialogType {
            return DialogType(
                ACCEPT_MEDIATOR_INVITE_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                null,
                null,
                mediatorIdentity,
                null,
                null,
                null,
                null,
                serverTimestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createMediatorInviteAcceptedDialog(
            contactSerializedDetails: String?,
            contactIdentity: Identity?,
            mediatorIdentity: Identity?
        ): DialogType {
            return DialogType(
                MEDIATOR_INVITE_ACCEPTED_DIALOG_ID,
                contactSerializedDetails,
                contactIdentity,
                null,
                null,
                mediatorIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAcceptGroupInviteDialog(
            serializedGroupDetails: String?,
            groupUid: UID?,
            groupOwnerIdentity: Identity?,
            pendingGroupMemberIdentities: Array<Identity?>?,
            pendingGroupMemberSerializedDetails: Array<String?>?,
            serverTimestamp: Long
        ): DialogType {
            return DialogType(
                ACCEPT_GROUP_INVITE_DIALOG_ID,
                null,
                null,
                null,
                null,
                groupOwnerIdentity,
                serializedGroupDetails,
                groupUid,
                pendingGroupMemberIdentities,
                pendingGroupMemberSerializedDetails,
                serverTimestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createOneToOneInvitationSentDialog(contactIdentity: Identity?): DialogType {
            return DialogType(
                ONE_TO_ONE_INVITATION_SENT_DIALOG_ID,
                null,
                contactIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAcceptOneToOneInvitationDialog(
            contactIdentity: Identity?,
            serverTimestamp: Long
        ): DialogType {
            return DialogType(
                ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_ID,
                null,
                contactIdentity,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                serverTimestamp,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createGroupV2InvitationDialog(
            inviterIdentity: Identity?,
            obvGroupV2: ObvGroupV2?
        ): DialogType {
            return DialogType(
                ACCEPT_GROUP_V2_INVITATION_DIALOG_ID,
                null,
                null,
                null,
                null,
                inviterIdentity,
                null,
                null,
                null,
                null,
                null,
                obvGroupV2,
                null,
                null
            )
        }

        @JvmStatic
        fun createGroupV2FrozenInvitationDialog(
            inviterIdentity: Identity?,
            obvGroupV2: ObvGroupV2?
        ): DialogType {
            return DialogType(
                GROUP_V2_FROZEN_INVITATION_DIALOG_ID,
                null,
                null,
                null,
                null,
                inviterIdentity,
                null,
                null,
                null,
                null,
                null,
                obvGroupV2,
                null,
                null
            )
        }

        @JvmStatic
        fun createSyncItemToApplyDialog(obvSyncAtom: ObvSyncAtom?): DialogType {
            return DialogType(
                SYNC_ITEM_TO_APPLY_DIALOG_ID,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                obvSyncAtom,
                null
            )
        }

        @JvmStatic
        fun createTransferDialog(obvTransferStep: ObvTransferStep?): DialogType {
            return DialogType(
                TRANSFER_DIALOG_ID,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                obvTransferStep
            )
        }
    }
    fun getId(): Int = id
    fun getContactDisplayNameOrSerializedDetails(): String? = contactDisplayNameOrSerializedDetails
    fun getContactIdentity(): Identity? = contactIdentity
    fun getSasToDisplay(): ByteArray? = sasToDisplay
    fun getSasEntered(): ByteArray? = sasEntered
    fun getMediatorOrGroupOwnerIdentity(): Identity? = mediatorOrGroupOwnerIdentity
    fun getSerializedGroupDetails(): String? = serializedGroupDetails
    fun getGroupUid(): UID? = groupUid
    fun getPendingGroupMemberIdentities(): Array<Identity?>? = pendingGroupMemberIdentities
    fun getPendingGroupMemberSerializedDetails(): Array<String?>? = pendingGroupMemberSerializedDetails
    fun getServerTimestamp(): Long? = serverTimestamp
    fun getObvGroupV2(): ObvGroupV2? = obvGroupV2
    fun getObvSyncAtom(): ObvSyncAtom? = obvSyncAtom
    fun getObvTransferStep(): ObvTransferStep? = obvTransferStep
    fun getVersion(): Long = version
}
