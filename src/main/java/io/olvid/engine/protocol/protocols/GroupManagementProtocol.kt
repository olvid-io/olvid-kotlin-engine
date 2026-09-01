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
package io.olvid.engine.protocol.protocols

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.GroupMembersChangedCallback
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.util.Arrays

class GroupManagementProtocol(
    protocolManagerSession: ProtocolManagerSession?,
    protocolInstanceUid: UID?,
    currentStateId: Int,
    encodedCurrentState: Encoded?,
    ownedIdentity: Identity,
    prng: PRNGService,
    jsonObjectMapper: ObjectMapper
) : ConcreteProtocol(
    protocolManagerSession,
    protocolInstanceUid,
    currentStateId,
    encodedCurrentState,
    ownedIdentity,
    prng,
    jsonObjectMapper
) {
    override val protocolId: Int = ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINAL_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            FINAL_STATE_ID -> return FinalState::class.java
            else -> return null
        }
    }


    class FinalState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(FINAL_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(FINAL_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    init {
        eraseReceivedMessagesAfterReachingAFinalState = false
    }

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIATE_GROUP_CREATION_MESSAGE_ID -> return InitiateGroupCreationMessage::class.java
            PROPAGATE_GROUP_CREATION_MESSAGE_ID -> return PropagateGroupCreationMessage::class.java
            GROUP_MEMBERS_CHANGED_TRIGGER_MESSAGE_ID -> return GroupMembersOrDetailsChangedTriggerMessage::class.java
            NEW_MEMBERS_MESSAGE_ID -> return NewMembersMessage::class.java
            ADD_GROUP_MEMBERS_MESSAGE_ID -> return AddGroupMembersMessage::class.java
            REMOVE_GROUP_MEMBERS_MESSAGE_ID -> return RemoveGroupMembersMessage::class.java
            KICK_FROM_GROUP_MESSAGE_ID -> return KickFromGroupMessage::class.java
            REINVITE_PENDING_MEMBER_MESSAGE_ID -> return ReinvitePendingMemberMessage::class.java
            DISBAND_GROUP_MESSAGE_ID -> return DisbandGroupMessage::class.java
            LEAVE_GROUP_MESSAGE_ID -> return LeaveGroupMessage::class.java
            NOTIFY_GROUP_LEFT_MESSAGE_ID -> return NotifyGroupLeftMessage::class.java
            INITIATE_GROUP_MEMBERS_QUERY_MESSAGE_ID -> return InitiateGroupMembersQueryMessage::class.java
            QUERY_GROUP_MEMBERS_MESSAGE_ID -> return QueryGroupMembersMessage::class.java
            TRIGGER_REINVITE_MESSAGE_ID -> return TriggerReinviteMessage::class.java
            TRIGGER_UPDATE_MEMBERS_MESSAGE_ID -> return TriggerUpdateMembersMessage::class.java
            UPLOAD_GROUP_PHOTO_MESSAGE_MESSAGE_ID -> return UploadGroupPhotoMessage::class.java
            PROPAGATE_REINVITE_PENDING_MEMBER_MESSAGE_ID -> return PropagateReinvitePendingMemberMessage::class.java
            PROPAGATE_DISBAND_GROUP_MESSAGE_ID -> return PropagateDisbandGroupMessage::class.java
            PROPAGATE_LEAVE_GROUP_MESSAGE_ID -> return PropagateLeaveGroupMessage::class.java
            else -> return null
        }
    }

    internal abstract class GroupInformationOnlyMessage : ConcreteProtocolMessage {
        @JvmField val groupInformation: GroupInformation

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
        }

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
            )
            }
    }

    class InitiateGroupCreationMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        internal val absolutePhotoUrl: String?

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            absolutePhotoUrl: String?,
            groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.groupMemberIdentitiesAndSerializedDetails =
                groupMemberIdentitiesAndSerializedDetails
            this.absolutePhotoUrl = absolutePhotoUrl
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.groupMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in receivedMessage.inputs[1].decodeList()) {
                this.groupMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
            this.absolutePhotoUrl = receivedMessage.inputs[2].decodeString()
        }

        override val protocolMessageId: Int = INITIATE_GROUP_CREATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodeds = arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodeds[i] = identityWithSerializedDetails.encode()
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodeds.requireNoNulls()),
                if (absolutePhotoUrl == null) Encoded.of("") else Encoded.of(absolutePhotoUrl),
            )
            }
    }

    class PropagateGroupCreationMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.groupMemberIdentitiesAndSerializedDetails =
                groupMemberIdentitiesAndSerializedDetails
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.groupMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in receivedMessage.inputs[1].decodeList()) {
                this.groupMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
        }

        override val protocolMessageId: Int = PROPAGATE_GROUP_CREATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodeds = arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodeds[i] = identityWithSerializedDetails.encode()
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodeds.requireNoNulls()),
            )
            }
    }

    internal class GroupMembersOrDetailsChangedTriggerMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = GROUP_MEMBERS_CHANGED_TRIGGER_MESSAGE_ID
    }

    class NewMembersMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        internal val pendingMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        internal val membersVersion: Long

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>,
            pendingMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>,
            membersVersion: Long
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.groupMemberIdentitiesAndSerializedDetails =
                groupMemberIdentitiesAndSerializedDetails
            this.pendingMemberIdentitiesAndSerializedDetails =
                pendingMemberIdentitiesAndSerializedDetails
            this.membersVersion = membersVersion
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.groupMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in receivedMessage.inputs[1].decodeList()) {
                this.groupMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
            this.pendingMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in receivedMessage.inputs[2].decodeList()) {
                this.pendingMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
            this.membersVersion = receivedMessage.inputs[3].decodeLong()
        }

        override val protocolMessageId: Int = NEW_MEMBERS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodedMembers =
                arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodedMembers[i] = identityWithSerializedDetails.encode()
                i++
            }
            val encodedPendings =
                arrayOfNulls<Encoded>(pendingMemberIdentitiesAndSerializedDetails.size)
            i = 0
            for (identityWithSerializedDetails in pendingMemberIdentitiesAndSerializedDetails) {
                encodedPendings[i] = identityWithSerializedDetails.encode()
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodedMembers.requireNoNulls()),
                Encoded.of(encodedPendings.requireNoNulls()),
                Encoded.of(membersVersion),
            )
            }
    }

    class AddGroupMembersMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val newMembersIdentity: HashSet<Identity>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            newMembersIdentity: HashSet<Identity>
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.newMembersIdentity = newMembersIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.newMembersIdentity = HashSet<Identity>()
            for (encodedIdentity in receivedMessage.inputs[1].decodeList()) {
                this.newMembersIdentity.add(encodedIdentity.decodeIdentity())
            }
        }

        override val protocolMessageId: Int = ADD_GROUP_MEMBERS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodedMembers = arrayOfNulls<Encoded>(newMembersIdentity.size)
            var i = 0
            for (identity in newMembersIdentity) {
                encodedMembers[i] = Encoded.of(identity)
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodedMembers.requireNoNulls()),
            )
            }
    }

    class RemoveGroupMembersMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val removedMemberIdentities: HashSet<Identity>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            removedMemberIdentities: HashSet<Identity>
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.removedMemberIdentities = removedMemberIdentities
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.removedMemberIdentities = HashSet<Identity>()
            for (encodedIdentity in receivedMessage.inputs[1].decodeList()) {
                this.removedMemberIdentities.add(encodedIdentity.decodeIdentity())
            }
        }

        override val protocolMessageId: Int = REMOVE_GROUP_MEMBERS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodedMembers = arrayOfNulls<Encoded>(removedMemberIdentities.size)
            var i = 0
            for (identity in removedMemberIdentities) {
                encodedMembers[i] = Encoded.of(identity)
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodedMembers.requireNoNulls()),
            )
            }
    }

    open class ReinvitePendingMemberMessage : ConcreteProtocolMessage {
        @JvmField val groupInformation: GroupInformation
        @JvmField val pendingMemberIdentity: Identity

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            pendingMemberIdentity: Identity
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.pendingMemberIdentity = pendingMemberIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.pendingMemberIdentity = receivedMessage.inputs[1].decodeIdentity()
        }

        override val protocolMessageId: Int = REINVITE_PENDING_MEMBER_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(pendingMemberIdentity),
            )
            }
    }


    internal class KickFromGroupMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = KICK_FROM_GROUP_MESSAGE_ID
    }

    internal class DisbandGroupMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = DISBAND_GROUP_MESSAGE_ID
    }

    internal class LeaveGroupMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = LEAVE_GROUP_MESSAGE_ID
    }

    internal class NotifyGroupLeftMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = NOTIFY_GROUP_LEFT_MESSAGE_ID
    }


    internal class InitiateGroupMembersQueryMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = INITIATE_GROUP_MEMBERS_QUERY_MESSAGE_ID
    }

    internal class QueryGroupMembersMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = QUERY_GROUP_MEMBERS_MESSAGE_ID
    }

    class TriggerReinviteMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val memberIdentity: Identity

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            memberIdentity: Identity
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.memberIdentity = memberIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.memberIdentity = receivedMessage.inputs[1].decodeIdentity()
        }

        override val protocolMessageId: Int = TRIGGER_REINVITE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(memberIdentity),
            )
            }
    }


    class TriggerUpdateMembersMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation
        internal val memberIdentity: Identity

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            memberIdentity: Identity
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
            this.memberIdentity = memberIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
            this.memberIdentity = receivedMessage.inputs[1].decodeIdentity()
        }

        override val protocolMessageId: Int = TRIGGER_UPDATE_MEMBERS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(memberIdentity),
            )
            }
    }

    class UploadGroupPhotoMessage : ConcreteProtocolMessage {
        internal val groupInformation: GroupInformation

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage!!) {
            this.groupInformation = groupInformation
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse != null) {
                throw Exception()
            }
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[0])
        }

        override val protocolMessageId: Int = UPLOAD_GROUP_PHOTO_MESSAGE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupInformation.encode(),
            )
            }
    }


    class PropagateReinvitePendingMemberMessage : ReinvitePendingMemberMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation,
            pendingMemberIdentity: Identity
        ) : super(coreProtocolMessage, groupInformation, pendingMemberIdentity)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATE_REINVITE_PENDING_MEMBER_MESSAGE_ID
    }

    internal class PropagateDisbandGroupMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATE_DISBAND_GROUP_MESSAGE_ID
    }

    internal class PropagateLeaveGroupMessage : GroupInformationOnlyMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInformation: GroupInformation
        ) : super(coreProtocolMessage, groupInformation)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATE_LEAVE_GROUP_MESSAGE_ID
    }


    // endregion
    // region steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        if (stateId == ConcreteProtocol.INITIAL_STATE_ID) {
            return arrayOf<Class<*>>(
                InitiateGroupCreationStep::class.java,
                ProcessPropagateGroupCreationMessage::class.java,
                NotifyMembersChangedStep::class.java,
                ProcessNewMembersStep::class.java,
                AddGroupMembersStep::class.java,
                RemoveGroupMembersStep::class.java,
                GetKickedStep::class.java,
                ReinvitePendingMemberStep::class.java,
                ProcessPropagateReinvitePendingMemberStep::class.java,
                DisbandGroupStep::class.java,
                ProcessPropagateDisbandGroupMessageStep::class.java,
                LeaveGroupStep::class.java,
                ProcessPropagateLeaveGroupMessageStep::class.java,
                ProcessGroupLeftStep::class.java,
                QueryGroupMembersStep::class.java,
                SendGroupMembersStep::class.java,
                ReinviteStep::class.java,
                UpdateMembersStep::class.java,
            )
        }
        return arrayOf<Class<*>>()
    }


    class InitiateGroupCreationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateGroupCreationMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.groupMemberIdentitiesAndSerializedDetails.contains(
                    IdentityWithSerializedDetails(ownedIdentity, "")
                )
            ) {
                Logger.w("Error: the groupMemberIdentitiesAndSerializedDetails contains the ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            var groupInformation = receivedMessage.groupInformation

            // Create the ContactGroup in database
            protocolManagerSession.identityDelegate!!.createContactGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupInformation,
                arrayOfNulls<Identity>(0),
                receivedMessage.groupMemberIdentitiesAndSerializedDetails.toTypedArray<IdentityWithSerializedDetails?>(),
                false
            )

            if (receivedMessage.absolutePhotoUrl != null && receivedMessage.absolutePhotoUrl.length > 0) {
                try {
                    protocolManagerSession.identityDelegate.updateOwnedGroupPhoto(
                        protocolManagerSession.session,
                        ownedIdentity,
                        groupInformation.getGroupOwnerAndUid(),
                        receivedMessage.absolutePhotoUrl,
                        true
                    )

                    val publishedDetails: JsonGroupDetailsWithVersionAndPhoto =
                        protocolManagerSession.identityDelegate.getGroupPublishedAndLatestOrTrustedDetails(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupInformation.getGroupOwnerAndUid()
                        )!![0]!!

                    // create what is needed to start the photo upload
                    val photoServerLabel = UID(prng)
                    val authEnc = Suite.getDefaultAuthEnc(0)
                    val photoServerKey = authEnc.generateKey(prng)!!

                    publishedDetails.setPhotoServerKey(Encoded.of(photoServerKey).bytes)
                    publishedDetails.setPhotoServerLabel(photoServerLabel.bytes)

                    val serializedGroupDetailsWithVersionAndPhoto =
                        protocol.jsonObjectMapper.writeValueAsString(publishedDetails)

                    groupInformation = GroupInformation(
                        groupInformation.groupOwnerIdentity,
                        groupInformation.groupUid,
                        serializedGroupDetailsWithVersionAndPhoto
                    )

                    // store the label and key in the details
                    protocolManagerSession.identityDelegate.setOwnedGroupDetailsServerLabelAndKey(
                        protocolManagerSession.session,
                        ownedIdentity,
                        groupInformation.getGroupOwnerAndUid(),
                        publishedDetails.getVersion(),
                        photoServerLabel,
                        photoServerKey
                    )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            PutUserDataQuery(
                                ownedIdentity,
                                photoServerLabel,
                                publishedDetails.getPhotoUrl()!!,
                                photoServerKey
                            )
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        GroupManagementProtocol.UploadGroupPhotoMessage(
                            coreProtocolMessage,
                            groupInformation
                        ).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                } catch (_: Exception) {
                    // an error occurred with the photo, this should not prevent group creation, so we do nothing
                }
            }

            run {
                // Propagate the group creation to other owned devices
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? = PropagateGroupCreationMessage(
                            coreProtocolMessage,
                            groupInformation,
                            receivedMessage.groupMemberIdentitiesAndSerializedDetails
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }


            run {
                // post an invitation to each group member by starting a child GroupInvitationProtocol
                for (identityWithSerializedDetails in receivedMessage.groupMemberIdentitiesAndSerializedDetails) {
                    val childProtocolInstanceUid = UID(prng)
                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID,
                        childProtocolInstanceUid
                    )
                    val messageToSend: ChannelMessageToSend? =
                        GroupInvitationProtocol.InitialMessage(
                            coreProtocolMessage,
                            identityWithSerializedDetails.identity,
                            groupInformation,
                            receivedMessage.groupMemberIdentitiesAndSerializedDetails
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            return FinalState()
        }
    }


    class ProcessPropagateGroupCreationMessage(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateGroupCreationMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.groupMemberIdentitiesAndSerializedDetails.contains(
                    IdentityWithSerializedDetails(ownedIdentity, "")
                )
            ) {
                Logger.w("Error: the groupMemberIdentitiesAndSerializedDetails contains the ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            // Create the ContactGroup in database
            protocolManagerSession.identityDelegate!!.createContactGroup(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupInformation,
                arrayOfNulls<Identity>(0),
                receivedMessage.groupMemberIdentitiesAndSerializedDetails.toTypedArray<IdentityWithSerializedDetails?>(),
                true
            )


            // check if a group photo needs to be downloaded
            val jsonGroupDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue(
                    receivedMessage.groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                    JsonGroupDetailsWithVersionAndPhoto::class.java
                )

            if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel() != null && jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() != null) {
                // even though another device created the group, we create a ServerUserData to ensure this photo is retained on server
                protocolManagerSession.identityDelegate.createGroupV1ServerUserData(
                    protocolManagerSession.session,
                    ownedIdentity,
                    UID(jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()!!),
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )

                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID,
                    UID(prng)
                )
                val messageToSend: ChannelMessageToSend? =
                    DownloadGroupPhotoChildProtocol.InitialMessage(
                        coreProtocolMessage,
                        receivedMessage.groupInformation
                    ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }


    class NotifyMembersChangedStep : ProtocolStep {
        @Suppress("unused")
        internal val startState: InitialProtocolState?
        internal val groupInformation: GroupInformation

        @Suppress("unused")
        internal constructor(
            startState: InitialProtocolState?,
            receivedMessage: GroupMembersOrDetailsChangedTriggerMessage,
            protocol: GroupManagementProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupInformation = receivedMessage.groupInformation
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: UploadGroupPhotoMessage,
            protocol: GroupManagementProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupInformation = receivedMessage.groupInformation
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!groupInformation.computeProtocolUid().equals(protocol.protocolInstanceUid)) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            val groupInfoDetails = protocol.jsonObjectMapper
                .readValue(
                    groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                    JsonGroupDetailsWithVersionAndPhoto::class.java
                )
            val publishedDetails: JsonGroupDetailsWithVersionAndPhoto =
                protocolManagerSession.identityDelegate!!.getGroupPublishedAndLatestOrTrustedDetails(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupInformation.getGroupOwnerAndUid()
                )!![0]!!

            if (publishedDetails.getVersion() == groupInfoDetails.getVersion() && publishedDetails.getPhotoUrl() != null && (publishedDetails.getPhotoServerLabel() == null || publishedDetails.getPhotoServerKey() == null)) {
                // we need to upload a photo
                val photoServerLabel = UID(prng)
                val authEnc = Suite.getDefaultAuthEnc(0)
                val photoServerKey = authEnc.generateKey(prng)!!

                publishedDetails.setPhotoServerKey(Encoded.of(photoServerKey).bytes)
                publishedDetails.setPhotoServerLabel(photoServerLabel.bytes)

                val serializedGroupDetailsWithVersionAndPhoto =
                    protocol.jsonObjectMapper.writeValueAsString(publishedDetails)

                val groupInformationWithKeyAndLabel = GroupInformation(
                    groupInformation.groupOwnerIdentity,
                    groupInformation.groupUid,
                    serializedGroupDetailsWithVersionAndPhoto
                )

                // store the label and key in the details
                protocolManagerSession.identityDelegate.setOwnedGroupDetailsServerLabelAndKey(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupInformation.getGroupOwnerAndUid(),
                    publishedDetails.getVersion(),
                    photoServerLabel,
                    photoServerKey
                )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        PutUserDataQuery(
                            ownedIdentity,
                            photoServerLabel,
                            publishedDetails.getPhotoUrl()!!,
                            photoServerKey
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    GroupManagementProtocol.UploadGroupPhotoMessage(
                        coreProtocolMessage,
                        groupInformationWithKeyAndLabel
                    ).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return FinalState()
            }

            // get the group members
            val group = protocolManagerSession.identityDelegate.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupInformation.getGroupOwnerAndUid()
            )

            val groupMembers = HashSet<IdentityWithSerializedDetails>()
            val pendingMembers = HashSet<IdentityWithSerializedDetails>(
                Arrays.asList<IdentityWithSerializedDetails>(*group!!.pendingGroupMembers)
            )

            for (memberIdentity in group.groupMembers) {
                groupMembers.add(
                    IdentityWithSerializedDetails(
                        memberIdentity,
                        protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            memberIdentity
                        )!!
                    )
                )
            }

            // also add yourself (group owner) to the group
            groupMembers.add(
                IdentityWithSerializedDetails(
                    ownedIdentity,
                    protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!
                )
            )

            // compute the identities to which the message should be sent (include myself in multi-device)
            val recipientIdentities: Array<Identity>
            if (!protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                ).isNullOrEmpty()
            ) {
                recipientIdentities = arrayOf(ownedIdentity) + group.groupMembers
            } else {
                @Suppress("UNCHECKED_CAST")
                recipientIdentities = group.groupMembers
            }

            run {
                if (recipientIdentities.isNotEmpty()) {
                    // notify all group members (not the pending group members) with a single message
                    val sendChannelInfos =
                        createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            recipientIdentities,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? = NewMembersMessage(
                                coreProtocolMessage,
                                groupInformation,
                                groupMembers,
                                pendingMembers,
                                group.groupMembersVersion
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                        }
                    }
                }
            }

            return FinalState()
        }
    }

    class ProcessNewMembersStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: NewMembersMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                Logger.w("Error: NewMembersMessage not received from the group owner")
                return null
            }

            val receivedFromOtherOwnedDevice =
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity() == ownedIdentity

            // get the group
            val group = protocolManagerSession.identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupInformation.getGroupOwnerAndUid()
            )

            if (group == null) {
                return null
            }

            if (!receivedFromOtherOwnedDevice && group.groupOwner == null) {
                Logger.w("Error: received a NewMembersMessage from someone else for a group you own")
                return null
            } else if (receivedFromOtherOwnedDevice && group.groupOwner != null) {
                Logger.w("Error: received a NewMembersMessage from another owned device and for a group you do not own")
                return null
            }

            if (group.groupMembersVersion > receivedMessage.membersVersion) {
                // we already have a more recent members version --> do nothing
                return FinalState()
            }

            run {
                // check if a group photo need to be downloaded
                val jsonGroupDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                    .readValue<JsonGroupDetailsWithVersionAndPhoto>(
                        receivedMessage.groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                        JsonGroupDetailsWithVersionAndPhoto::class.java
                    )
                if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel() != null && jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() != null) {
                    val publishedDetails: JsonGroupDetailsWithVersionAndPhoto =
                        protocolManagerSession.identityDelegate.getGroupPublishedAndLatestOrTrustedDetails(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.groupInformation.getGroupOwnerAndUid()
                        )!![0]!!

                    if (!(jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()
                            .contentEquals(publishedDetails.getPhotoServerLabel()) &&
                                ((jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() == null && publishedDetails.getPhotoServerKey() == null) ||
                                        (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() != null && publishedDetails.getPhotoServerKey() != null && Encoded(
                                            jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                                        ).decodeSymmetricKey() == Encoded(publishedDetails.getPhotoServerKey()!!).decodeSymmetricKey())) && publishedDetails.getPhotoUrl() != null)
                    ) {
                        // we need to download the photo

                        // if we are the owner, create a server user data

                        if (receivedFromOtherOwnedDevice) {
                            protocolManagerSession.identityDelegate.createGroupV1ServerUserData(
                                protocolManagerSession.session,
                                ownedIdentity,
                                UID(jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()!!),
                                receivedMessage.groupInformation.getGroupOwnerAndUid()
                            )
                        }

                        // we start a child protocol
                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.DOWNLOAD_GROUP_PHOTO_CHILD_PROTOCOL_ID,
                            UID(prng)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            DownloadGroupPhotoChildProtocol.InitialMessage(
                                coreProtocolMessage,
                                receivedMessage.groupInformation
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }
            }

            run {
                // update group details and members version
                protocolManagerSession.identityDelegate.updateGroupMembersAndDetails(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation,
                    @Suppress("UNCHECKED_CAST") (receivedMessage.groupMemberIdentitiesAndSerializedDetails as HashSet<IdentityWithSerializedDetails?>),
                    @Suppress("UNCHECKED_CAST") (receivedMessage.pendingMemberIdentitiesAndSerializedDetails as HashSet<IdentityWithSerializedDetails?>),
                    receivedMessage.membersVersion
                )
            }

            return FinalState()
        }
    }

    class AddGroupMembersStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: AddGroupMembersMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }


            run {
                // add pending members to the group and notify existing members (in the callback)
                val groupMembersChangedCallback = GroupMembersChangedCallback {
                    val coreProtocolMessage =
                        buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                    val messageToSend: ChannelMessageToSend? =
                        GroupMembersOrDetailsChangedTriggerMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
                protocolManagerSession.identityDelegate!!.addPendingMembersToGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    receivedMessage.newMembersIdentity.toTypedArray<Identity?>(),
                    groupMembersChangedCallback
                )
            }

            run {
                // post invitations to the new members
                val group = protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )
                if (group == null) {
                    throw Exception()
                }

                val allGroupMembers = HashSet<IdentityWithSerializedDetails>(
                    Arrays.asList<IdentityWithSerializedDetails>(*group.pendingGroupMembers)
                )
                for (identity in group.groupMembers) {
                    allGroupMembers.add(
                        IdentityWithSerializedDetails(
                            identity,
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                identity
                            )!!
                        )
                    )
                }
                for (contactIdentity in receivedMessage.newMembersIdentity) {
                    val childProtocolInstanceUid = UID(prng)
                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID,
                        childProtocolInstanceUid
                    )
                    val messageToSend: ChannelMessageToSend? =
                        GroupInvitationProtocol.InitialMessage(
                            coreProtocolMessage,
                            contactIdentity,
                            receivedMessage.groupInformation,
                            allGroupMembers
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            return FinalState()
        }
    }

    class RemoveGroupMembersStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: RemoveGroupMembersMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }


            run {
                // remove members from the group and notify remaining members (in the callback)
                val groupMembersChangedCallback = GroupMembersChangedCallback {
                    val coreProtocolMessage =
                        buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                    val messageToSend: ChannelMessageToSend? =
                        GroupMembersOrDetailsChangedTriggerMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
                protocolManagerSession.identityDelegate!!.removeMembersAndPendingFromGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    receivedMessage.removedMemberIdentities.toTypedArray<Identity?>(),
                    groupMembersChangedCallback
                )
            }

            run {
                // notify members that have been kicked
                val group = protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )
                if (group == null) {
                    throw Exception()
                }
                for (contactIdentity in receivedMessage.removedMemberIdentities) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                contactIdentity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: Exception) {
                        // after a contact delete this might fail as there are no channels with the deleted contact --> proceed
                    }
                }
            }

            return FinalState()
        }
    }

    class GetKickedStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: KickFromGroupMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!
            protocol.eraseReceivedMessagesAfterReachingAFinalState = true

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                Logger.w("Error: NewMembersMessage not received from the group owner")
                return null
            }

            run {
                // If the group exists, leave it
                val group = protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )
                if (group != null) {
                    // simply delete the group on the engine side, everything will follow!
                    protocolManagerSession.identityDelegate.leaveGroup(
                        protocolManagerSession.session,
                        receivedMessage.groupInformation.getGroupOwnerAndUid(),
                        ownedIdentity
                    )
                }
            }

            return FinalState()
        }
    }


    class ReinvitePendingMemberStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: ReinvitePendingMemberMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            run {
                // mark the pending member as "not declined"
                protocolManagerSession.identityDelegate!!.setPendingMemberDeclined(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    receivedMessage.pendingMemberIdentity,
                    false
                )
            }

            run {
                // resend an invitation
                val group = protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )
                if (group == null) {
                    throw Exception()
                }

                val allGroupMembers = HashSet<IdentityWithSerializedDetails>(
                    Arrays.asList<IdentityWithSerializedDetails>(*group.pendingGroupMembers)
                )
                for (identity in group.groupMembers) {
                    allGroupMembers.add(
                        IdentityWithSerializedDetails(
                            identity,
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                identity
                            )!!
                        )
                    )
                }

                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = GroupInvitationProtocol.InitialMessage(
                    coreProtocolMessage,
                    receivedMessage.pendingMemberIdentity,
                    receivedMessage.groupInformation,
                    allGroupMembers
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            run {
                // Propagate the group re-invite to other owned devices
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            PropagateReinvitePendingMemberMessage(
                                coreProtocolMessage,
                                receivedMessage.groupInformation,
                                receivedMessage.pendingMemberIdentity
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            return FinalState()
        }
    }


    class ProcessPropagateReinvitePendingMemberStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateReinvitePendingMemberMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            run {
                // mark the pending member as "not declined"
                protocolManagerSession.identityDelegate!!.setPendingMemberDeclined(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    receivedMessage.pendingMemberIdentity,
                    false
                )
            }

            return FinalState()
        }
    }


    class DisbandGroupStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: DisbandGroupMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }


            run {
                // send all members and pending members of the group a KickFromGroupMessage
                val group = protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                )
                if (group == null) {
                    throw Exception()
                }

                if (group.groupMembers.isNotEmpty()) {
                    val sendChannelInfos =
                        SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            group.groupMembers,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                                coreProtocolMessage,
                                receivedMessage.groupInformation
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                            // ignore exceptions that may be thrown if there is no channel with all contacts on a server
                        }
                    }
                }
                if (group.pendingGroupMembers.isNotEmpty()) {
                    val pendingMemberIdentities = group.pendingGroupMembers.map { it.identity }.toTypedArray()

                    val sendChannelInfos =
                        createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            pendingMemberIdentities,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                                coreProtocolMessage,
                                receivedMessage.groupInformation
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                            // ignore exceptions that may be thrown if there is no channel with all contacts on a server
                        }
                    }
                }
            }

            run {
                // Propagate the disband to other owned devices
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? = PropagateDisbandGroupMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            run {
                // delete the group
                protocolManagerSession.identityDelegate!!.deleteGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity
                )
            }

            return FinalState()
        }
    }

    class ProcessPropagateDisbandGroupMessageStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateDisbandGroupMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: the groupInformation contains a different Identity than ownedIdentity")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            run {
                // delete the group
                protocolManagerSession.identityDelegate!!.deleteGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity
                )
            }

            return FinalState()
        }
    }

    class LeaveGroupStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: LeaveGroupMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: cannot leave a group you own")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            try {
                // notify the group owner
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.groupInformation.groupOwnerIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = NotifyGroupLeftMessage(
                    coreProtocolMessage,
                    receivedMessage.groupInformation
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: Exception) {
                Logger.w("LeaveGroupStep: Error notifying group owner. Probably no channel with him.")
            }

            run {
                // Propagate the disband to other owned devices
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? = PropagateLeaveGroupMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            run {
                // simply delete the group on the engine side, everything will follow!
                protocolManagerSession.identityDelegate!!.leaveGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity
                )
            }

            return FinalState()
        }
    }

    class ProcessPropagateLeaveGroupMessageStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateLeaveGroupMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: cannot leave a group you own")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            run {
                // simply delete the group on the engine side, everything will follow!
                protocolManagerSession.identityDelegate!!.leaveGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity
                )
            }

            return FinalState()
        }
    }

    class ProcessGroupLeftStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: NotifyGroupLeftMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: you are not the group owner")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            run {
                // remove members from the group and notify remaining members (in the callback)
                val groupMembersChangedCallback = GroupMembersChangedCallback {
                    val coreProtocolMessage =
                        buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                    val messageToSend: ChannelMessageToSend? =
                        GroupMembersOrDetailsChangedTriggerMessage(
                            coreProtocolMessage,
                            receivedMessage.groupInformation
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
                protocolManagerSession.identityDelegate!!.removeMembersAndPendingFromGroup(
                    protocolManagerSession.session,
                    receivedMessage.groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    arrayOf<Identity?>(
                        receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                    ),
                    groupMembersChangedCallback
                )
            }
            return FinalState()
        }
    }


    class QueryGroupMembersStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateGroupMembersQueryMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: you are the group owner")
                return null
            }

            run {
                // send query members message to group owner
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.groupInformation.groupOwnerIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = QueryGroupMembersMessage(
                    coreProtocolMessage,
                    receivedMessage.groupInformation
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }


    class SendGroupMembersStep internal constructor(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: QueryGroupMembersMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: you are not the group owner")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }

            val contactIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()

            // get the group members
            val group = protocolManagerSession.identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupInformation.getGroupOwnerAndUid()
            )

            if (group != null && group.isPendingMember(contactIdentity)) {
                // if we receive a query from someone who is pending we do nothing, it's probably because we not yet received his "accept" invitation message
                return FinalState()
            }

            if (group == null || !group.isMember(contactIdentity)) {
                // group not found or member not in the group --> kick him
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                    coreProtocolMessage,
                    receivedMessage.groupInformation
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
                return FinalState()
            }

            val groupMembers = HashSet<IdentityWithSerializedDetails>()
            val pendingMembers = HashSet<IdentityWithSerializedDetails>(
                Arrays.asList<IdentityWithSerializedDetails>(*group.pendingGroupMembers)
            )

            for (memberIdentity in group.groupMembers) {
                groupMembers.add(
                    IdentityWithSerializedDetails(
                        memberIdentity,
                        protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            memberIdentity
                        )!!
                    )
                )
            }

            // also add yourself (group owner) to the group
            groupMembers.add(
                IdentityWithSerializedDetails(
                    ownedIdentity,
                    protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!
                )
            )

            run {
                // send group members to receivedMessage sender
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = NewMembersMessage(
                    coreProtocolMessage,
                    protocolManagerSession.identityDelegate.getGroupInformation(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupInformation.getGroupOwnerAndUid()
                    )!!,
                    groupMembers,
                    pendingMembers,
                    group.groupMembersVersion
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }
            return FinalState()
        }
    }


    class ReinviteStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: TriggerReinviteMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.memberIdentity.equals(ownedIdentity)) {
                Logger.w("Error: trying to reinvite yourself to a group")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: you are not the group owner")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }


            // get the group members
            val group = protocolManagerSession.identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupInformation.getGroupOwnerAndUid()
            )

            if (group == null) {
                Logger.w("Error: group not found")
                return null
            }

            if (!group.isMember(receivedMessage.memberIdentity) && !group.isPendingMember(
                    receivedMessage.memberIdentity
                )
            ) {
                Logger.w("Error in ReinviteStep: member is neither member, nor pending")
                return null
            }

            run {
                val allGroupMembers = HashSet<IdentityWithSerializedDetails>(
                    Arrays.asList<IdentityWithSerializedDetails>(*group.pendingGroupMembers)
                )
                for (identity in group.groupMembers) {
                    allGroupMembers.add(
                        IdentityWithSerializedDetails(
                            identity,
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                identity
                            )!!
                        )
                    )
                }

                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = GroupInvitationProtocol.InitialMessage(
                    coreProtocolMessage,
                    receivedMessage.memberIdentity,
                    receivedMessage.groupInformation,
                    allGroupMembers
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }


    class UpdateMembersStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: TriggerUpdateMembersMessage,
        protocol: GroupManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.memberIdentity.equals(ownedIdentity)) {
                Logger.w("Error: trying to reinvite yourself to a group")
                return null
            }

            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(ownedIdentity)) {
                Logger.w("Error: you are not the group owner")
                return null
            }

            if (!receivedMessage.groupInformation.computeProtocolUid()
                    .equals(protocol.protocolInstanceUid)
            ) {
                Logger.w("Error: protocolUid mismatch")
                return null
            }


            // get the group members
            val group = protocolManagerSession.identityDelegate!!.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupInformation.getGroupOwnerAndUid()
            )

            if (group == null) {
                Logger.w("Error: group not found")
                return null
            }

            if (!group.isMember(receivedMessage.memberIdentity)) {
                Logger.w("Error in UpdateMembersStep: contact is not member")
                return null
            }

            run {
                val groupMembers = HashSet<IdentityWithSerializedDetails>()
                val pendingMembers = HashSet<IdentityWithSerializedDetails>(
                    Arrays.asList<IdentityWithSerializedDetails>(*group.pendingGroupMembers)
                )

                for (memberIdentity in group.groupMembers) {
                    groupMembers.add(
                        IdentityWithSerializedDetails(
                            memberIdentity,
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                memberIdentity
                            )!!
                        )
                    )
                }

                // also add yourself (group owner) to the group
                groupMembers.add(
                    IdentityWithSerializedDetails(
                        ownedIdentity,
                        protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )!!
                    )
                )


                // send group members to memberIdentity (in the receivedMessage)
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.memberIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = NewMembersMessage(
                    coreProtocolMessage,
                    receivedMessage.groupInformation,
                    groupMembers,
                    pendingMembers,
                    group.groupMembersVersion
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    } // endregion

    companion object {
        // region states
        const val FINAL_STATE_ID: Int = 1


        // endregion
        // region messages
        private const val INITIATE_GROUP_CREATION_MESSAGE_ID = 0
        private const val PROPAGATE_GROUP_CREATION_MESSAGE_ID = 1
        private const val GROUP_MEMBERS_CHANGED_TRIGGER_MESSAGE_ID = 2
        private const val NEW_MEMBERS_MESSAGE_ID =
            3 // update to members, group details (including photo). Sent to members, pending (and owner's other devices ??)
        private const val ADD_GROUP_MEMBERS_MESSAGE_ID = 4
        private const val REMOVE_GROUP_MEMBERS_MESSAGE_ID = 5
        private const val KICK_FROM_GROUP_MESSAGE_ID = 6
        private const val NOTIFY_GROUP_LEFT_MESSAGE_ID = 7
        private const val REINVITE_PENDING_MEMBER_MESSAGE_ID = 8
        private const val DISBAND_GROUP_MESSAGE_ID = 9
        private const val LEAVE_GROUP_MESSAGE_ID = 10
        private const val INITIATE_GROUP_MEMBERS_QUERY_MESSAGE_ID = 11
        private const val QUERY_GROUP_MEMBERS_MESSAGE_ID = 12
        private const val TRIGGER_REINVITE_MESSAGE_ID = 13
        private const val TRIGGER_UPDATE_MEMBERS_MESSAGE_ID = 14
        private const val UPLOAD_GROUP_PHOTO_MESSAGE_MESSAGE_ID = 15
        private const val PROPAGATE_REINVITE_PENDING_MEMBER_MESSAGE_ID = 16
        private const val PROPAGATE_DISBAND_GROUP_MESSAGE_ID = 17
        private const val PROPAGATE_LEAVE_GROUP_MESSAGE_ID = 18
    }
}
