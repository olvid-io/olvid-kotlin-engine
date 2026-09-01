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
import io.olvid.engine.datatypes.GroupMembersChangedCallback
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createAcceptGroupInviteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.GroupInformation.Companion.computeProtocolUid
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.GroupMembersOrDetailsChangedTriggerMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.KickFromGroupMessage
import io.olvid.engine.protocol.protocols.GroupManagementProtocol.TriggerUpdateMembersMessage
import java.util.UUID

class GroupInvitationProtocol(
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
    override val protocolId: Int = ConcreteProtocol.GROUP_INVITATION_PROTOCOL_ID

    override val finalStateIds: IntArray? get() = intArrayOf(
            INVITATION_SENT_STATE_ID,
            RESPONSE_SENT_STATE_ID,
            RESPONSE_RECEIVED_STATE_ID
        )

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            INVITATION_SENT_STATE_ID -> return InvitationSentState::class.java
            INVITATION_RECEIVED_STATE_ID -> return InvitationReceivedState::class.java
            RESPONSE_SENT_STATE_ID -> return ResponseSentState::class.java
            RESPONSE_RECEIVED_STATE_ID -> return ResponseReceivedState::class.java
            else -> return null
        }
    }


    class InvitationReceivedState : ConcreteProtocolState {
        internal val groupInformation: GroupInformation
        internal val dialogUuid: UUID?
        internal val groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>

        internal constructor(
            groupInformation: GroupInformation,
            dialogUuid: UUID?,
            groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        ) : super(
            INVITATION_RECEIVED_STATE_ID
        ) {
            this.groupInformation = groupInformation
            this.dialogUuid = dialogUuid
            this.groupMemberIdentitiesAndSerializedDetails =
                groupMemberIdentitiesAndSerializedDetails
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 3) {
                throw Exception()
            }
            this.groupInformation = GroupInformation.of(list[0])
            this.dialogUuid = list[1].decodeUuid()
            this.groupMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in list[2].decodeList()) {
                this.groupMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
        }

        override fun encode(): Encoded {
            val encodedGroupMembers =
                arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodedGroupMembers[i] = identityWithSerializedDetails.encode()
                i++
            }
            return Encoded.of(
                arrayOf<Encoded>(
                    groupInformation.encode(),
                    Encoded.of(dialogUuid),
                    Encoded.of(encodedGroupMembers.requireNoNulls()),
                )
            )
        }
    }


    class InvitationSentState : ConcreteProtocolState {
        internal constructor() : super(INVITATION_SENT_STATE_ID)

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class ResponseSentState : ConcreteProtocolState {
        internal constructor() : super(RESPONSE_SENT_STATE_ID)

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(RESPONSE_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class ResponseReceivedState : ConcreteProtocolState {
        internal constructor() : super(RESPONSE_RECEIVED_STATE_ID)

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(RESPONSE_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    //    private static final int TRUST_LEVEL_INCREASED_MESSAGE_ID = 5;
    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            GROUP_INVITATION_MESSAGE_ID -> return GroupInvitationMessage::class.java
            DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID -> return DialogAcceptGroupInvitationMessage::class.java
            ACCEPT_INVITATION_MESSAGE_ID -> return InvitationResponseMessage::class.java
            PROPAGATE_INVITATION_RESPONSE_MESSAGE_ID -> return PropagateInvitationResponseMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val groupInformation: GroupInformation
        internal val groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            groupInformation: GroupInformation,
            groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails>
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.groupInformation = groupInformation
            this.groupMemberIdentitiesAndSerializedDetails =
                groupMemberIdentitiesAndSerializedDetails
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.groupInformation = GroupInformation.of(receivedMessage.inputs[1])
            this.groupMemberIdentitiesAndSerializedDetails =
                HashSet<IdentityWithSerializedDetails>()
            for (encodedIdentityAndDisplayName in receivedMessage.inputs[2].decodeList()) {
                this.groupMemberIdentitiesAndSerializedDetails.add(
                    IdentityWithSerializedDetails.of(
                        encodedIdentityAndDisplayName
                    )
                )
            }
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodeds = arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodeds[i] = identityWithSerializedDetails.encode()
                i++
            }
            return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                groupInformation.encode(),
                Encoded.of(encodeds.requireNoNulls()),
            )
            }
    }


    class GroupInvitationMessage : ConcreteProtocolMessage {
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

        override val protocolMessageId: Int = GROUP_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodedGroupMembers =
                arrayOfNulls<Encoded>(groupMemberIdentitiesAndSerializedDetails.size)
            var i = 0
            for (identityWithSerializedDetails in groupMemberIdentitiesAndSerializedDetails) {
                encodedGroupMembers[i] = identityWithSerializedDetails.encode()
                i++
            }
            return arrayOf<Encoded>(
                groupInformation.encode(),
                Encoded.of(encodedGroupMembers.requireNoNulls()),
            )
            }
    }


    class DialogAcceptGroupInvitationMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean
        internal val dialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            invitationAccepted = false
            dialogUuid = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            invitationAccepted = receivedMessage.encodedResponse.decodeBoolean()
            dialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class InvitationResponseMessage : ConcreteProtocolMessage {
        internal val groupUid: UID
        internal val invitationAccepted: Boolean

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupUid: UID,
            invitationAccepted: Boolean
        ) : super(coreProtocolMessage!!) {
            this.groupUid = groupUid
            this.invitationAccepted = invitationAccepted
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.groupUid = receivedMessage.inputs[0].decodeUid()
            this.invitationAccepted = receivedMessage.inputs[1].decodeBoolean()
        }

        override val protocolMessageId: Int = ACCEPT_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(invitationAccepted),
            )
            }
    }


    class PropagateInvitationResponseMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            invitationAccepted: Boolean
        ) : super(coreProtocolMessage!!) {
            this.invitationAccepted = invitationAccepted
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.invitationAccepted = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = PROPAGATE_INVITATION_RESPONSE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted),
            )
            }
    }


    // endregion
    // region steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                SendInvitationStep::class.java,
                ProcessInvitationStep::class.java,
                ProcessResponseStep::class.java
            )

            INVITATION_RECEIVED_STATE_ID -> return arrayOf<Class<*>>(
                ProcessInvitationDialogResponseStep::class.java,
                ProcessPropagatedInvitationResponseStep::class.java
            )

            else -> return arrayOf<Class<*>>()
        }
    }


    class SendInvitationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: GroupInvitationProtocol?
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

            if (!receivedMessage.groupMemberIdentitiesAndSerializedDetails.contains(
                    IdentityWithSerializedDetails(receivedMessage.contactIdentity, "")
                )
            ) {
                Logger.w("Error: the groupMemberIdentitiesAndSerializedDetails does not contain the contactIdentity")
                return null
            }

            run {
                // post an invitation to contactIdentity
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = GroupInvitationMessage(
                    coreProtocolMessage,
                    receivedMessage.groupInformation,
                    receivedMessage.groupMemberIdentitiesAndSerializedDetails
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return InvitationSentState()
        }
    }


    class ProcessInvitationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: GroupInvitationMessage,
        protocol: GroupInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.groupMemberIdentitiesAndSerializedDetails.contains(
                    IdentityWithSerializedDetails(ownedIdentity, "")
                )
            ) {
                Logger.w("Error: you received an invitation to a group without being part of groupMemberIdentitiesAndSerializedDetails")
                return null
            }

            val groupOwnerIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()

            // check the message was received from the groupOwnerIdentity
            if (!receivedMessage.groupInformation.groupOwnerIdentity.equals(groupOwnerIdentity)) {
                Logger.w("Error: you received an invitation to a group from someone who is not the group owner")
                return null
            }

            // check you are not already part of the group
            if (protocolManagerSession.identityDelegate!!.getGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupInformation.getGroupOwnerAndUid()
                ) != null
            ) {
                Logger.w("Received an invitation to a group you already belong to: accepting it :)")
                run {
                    // notify groupOwner that you accepted the groupInvitation
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            groupOwnerIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? = InvitationResponseMessage(
                        coreProtocolMessage,
                        receivedMessage.groupInformation.groupUid,
                        true
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
                run {
                    // Propagate the accept to other owned devices
                    val numberOfOtherDevices =
                        protocolManagerSession.identityDelegate.getOtherDeviceUidsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )!!.size
                    if (numberOfOtherDevices > 0) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(
                                createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(
                                    ownedIdentity
                                )
                            )
                            val messageToSend: ChannelMessageToSend? =
                                PropagateInvitationResponseMessage(
                                    coreProtocolMessage,
                                    true
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
                    // reset the group members version to 0 and the published group details to those contained in the group information
                    protocolManagerSession.identityDelegate.resetGroupMembersAndPublishedDetailsVersions(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupInformation
                    )
                }
                return ResponseSentState()
            }


            val jsonGroupDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                .readValue<JsonGroupDetailsWithVersionAndPhoto>(
                    receivedMessage.groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                    JsonGroupDetailsWithVersionAndPhoto::class.java
                )
            val jsonGroupDetails = jsonGroupDetailsWithVersionAndPhoto.getGroupDetails()
            val serializedGroupDetails =
                protocol.jsonObjectMapper.writeValueAsString(jsonGroupDetails)

            // prompt user to accept
            val dialogUuid = UUID.randomUUID()
            run {
                val identities =
                    arrayOfNulls<Identity>(receivedMessage.groupMemberIdentitiesAndSerializedDetails.size)
                val serializedDetails = arrayOfNulls<String>(identities.size)
                var i = 0
                for (identityWithSerializedDetails in receivedMessage.groupMemberIdentitiesAndSerializedDetails) {
                    if (identityWithSerializedDetails.identity.equals(ownedIdentity)) {
                        identities[i] = groupOwnerIdentity
                        serializedDetails[i] =
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                groupOwnerIdentity
                            )
                    } else {
                        identities[i] = identityWithSerializedDetails.identity
                        serializedDetails[i] = identityWithSerializedDetails.serializedDetails
                    }
                    i++
                }

                // display group invite dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createAcceptGroupInviteDialog(
                            serializedGroupDetails,
                            receivedMessage.groupInformation.groupUid,
                            receivedMessage.groupInformation.groupOwnerIdentity,
                            identities,
                            serializedDetails,
                            receivedMessage.serverTimestamp
                        ),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DialogAcceptGroupInvitationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return InvitationReceivedState(
                receivedMessage.groupInformation,
                dialogUuid,
                receivedMessage.groupMemberIdentitiesAndSerializedDetails
            )
        }
    }


    class ProcessInvitationDialogResponseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: DialogAcceptGroupInvitationMessage,
        protocol: GroupInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (startState.dialogUuid != receivedMessage.dialogUuid) {
                Logger.e("ObvDialog uuid mismatch in DialogAcceptGroupInvitationMessage.")
                return null
            }


            val invitationAccepted = receivedMessage.invitationAccepted
            val groupOwnerIdentity = startState.groupInformation.groupOwnerIdentity

            run {
                // Propagate the accept to other owned devices
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
                            PropagateInvitationResponseMessage(
                                coreProtocolMessage,
                                invitationAccepted
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

            if (!protocolManagerSession.identityDelegate!!.isIdentityAnActiveContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupOwnerIdentity
                )
            ) {
                // the groupOwner was deleted, abort the protocol
                // remove any dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return ResponseSentState()
            }

            run {
                // notify groupOwner that you accepted the groupInvitation
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        groupOwnerIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = InvitationResponseMessage(
                    coreProtocolMessage,
                    startState.groupInformation.groupUid,
                    invitationAccepted
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }





            if (invitationAccepted) {
                // create the group
                val pendingGroupMembers =
                    arrayOfNulls<IdentityWithSerializedDetails>(startState.groupMemberIdentitiesAndSerializedDetails.size - 1)
                var i = 0
                for (identityWithSerializedDetails in startState.groupMemberIdentitiesAndSerializedDetails) {
                    if (identityWithSerializedDetails.identity.equals(ownedIdentity)) {
                        continue
                    }
                    pendingGroupMembers[i] = identityWithSerializedDetails
                    i++
                }

                protocolManagerSession.identityDelegate.createContactGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupInformation,
                    arrayOf<Identity?>(groupOwnerIdentity),
                    pendingGroupMembers,
                    false
                )
            }

            // remove the dialog
            val coreProtocolMessage = buildCoreProtocolMessage(
                createUserInterfaceChannelInfo(
                    ownedIdentity,
                    createDeleteDialog(),
                    startState.dialogUuid
                )
            )
            val messageToSend: ChannelMessageToSend? =
                OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return ResponseSentState()
        }
    }


    class ProcessPropagatedInvitationResponseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: PropagateInvitationResponseMessage,
        protocol: GroupInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // remove the dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            val invitationAccepted = receivedMessage.invitationAccepted
            val groupOwnerIdentity = startState.groupInformation.groupOwnerIdentity

            if (!protocolManagerSession.identityDelegate!!.isIdentityAnActiveContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupOwnerIdentity
                )
            ) {
                // the groupOwner was deleted, abort the protocol
                return ResponseSentState()
            }

            if (invitationAccepted) {
                // create the group
                val pendingGroupMembers =
                    arrayOfNulls<IdentityWithSerializedDetails>(startState.groupMemberIdentitiesAndSerializedDetails.size - 1)
                var i = 0
                for (identityWithSerializedDetails in startState.groupMemberIdentitiesAndSerializedDetails) {
                    if (identityWithSerializedDetails.identity.equals(ownedIdentity)) {
                        continue
                    }
                    pendingGroupMembers[i] = identityWithSerializedDetails
                    i++
                }

                protocolManagerSession.identityDelegate.createContactGroup(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupInformation,
                    arrayOf<Identity?>(groupOwnerIdentity),
                    pendingGroupMembers,
                    false
                )
            }

            return ResponseSentState()
        }
    }


    class ProcessResponseStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InvitationResponseMessage,
        protocol: GroupInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val contactIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()

            val groupOwnerAndUid = ByteArray(ownedIdentity.getBytes().size + UID.UID_LENGTH)
            System.arraycopy(
                ownedIdentity.getBytes(),
                0,
                groupOwnerAndUid,
                0,
                ownedIdentity.getBytes().size
            )
            System.arraycopy(
                receivedMessage.groupUid.bytes,
                0,
                groupOwnerAndUid,
                ownedIdentity.getBytes().size,
                UID.UID_LENGTH
            )


            val groupMembersChangedCallback: GroupMembersChangedCallback =
                object : GroupMembersChangedCallback {
                    internal val groupInformation =
                        protocolManagerSession.identityDelegate!!.getGroupInformation(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupOwnerAndUid
                        )

                    @Throws(Exception::class)
                    override fun callback() {
                        val childProtocolUid = groupInformation!!.computeProtocolUid()
                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                            childProtocolUid
                        )
                        val messageToSend: ChannelMessageToSend? =
                            GroupMembersOrDetailsChangedTriggerMessage(
                                coreProtocolMessage,
                                groupInformation
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }


            val group = protocolManagerSession.identityDelegate.getGroup(
                protocolManagerSession.session,
                ownedIdentity,
                groupOwnerAndUid
            )
            if (group == null || !group.isPendingMember(contactIdentity)) {
                // received a response from someone not in the group or already member --> if they are not already member, kick them
                if (receivedMessage.invitationAccepted && (group == null || !group.isMember(
                        contactIdentity
                    ))
                ) {
                    // the guy accepted, but he is neither pending, nor member --> send a KickFromGroupMessage message
                    val groupManagementProtocolUid = computeProtocolUid(
                        ownedIdentity.getBytes(),
                        receivedMessage.groupUid.bytes
                    )
                    val coreProtocolMessage = CoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            contactIdentity,
                            ownedIdentity
                        ),
                        ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                        groupManagementProtocolUid
                    )
                    val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                        coreProtocolMessage,
                        GroupInformation(
                            ownedIdentity,
                            receivedMessage.groupUid,
                            JsonGroupDetailsWithVersionAndPhoto.DUMMY_GROUP_DETAILS
                        )
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                } else if (!receivedMessage.invitationAccepted && group != null && group.isMember(
                        contactIdentity
                    )
                ) {
                    // the guy declined, but he is a member --> demote him to declined PendingMember
                    protocolManagerSession.identityDelegate.demoteGroupMemberToDeclinedPendingMember(
                        protocolManagerSession.session,
                        groupOwnerAndUid,
                        ownedIdentity,
                        contactIdentity,
                        groupMembersChangedCallback
                    )

                    val groupManagementProtocolUid = computeProtocolUid(
                        ownedIdentity.getBytes(),
                        receivedMessage.groupUid.bytes
                    )
                    val coreProtocolMessage = CoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            contactIdentity,
                            ownedIdentity
                        ),
                        ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                        groupManagementProtocolUid
                    )
                    val messageToSend: ChannelMessageToSend? = KickFromGroupMessage(
                        coreProtocolMessage,
                        GroupInformation(
                            ownedIdentity,
                            receivedMessage.groupUid,
                            JsonGroupDetailsWithVersionAndPhoto.DUMMY_GROUP_DETAILS
                        )
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                } else if (receivedMessage.invitationAccepted && group!!.isMember(contactIdentity)) {
                    // the contact accepted an invite but was already member --> send him an up to date members list and group details
                    val groupManagementProtocolUid = computeProtocolUid(
                        ownedIdentity.getBytes(),
                        receivedMessage.groupUid.bytes
                    )

                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.GROUP_MANAGEMENT_PROTOCOL_ID,
                        groupManagementProtocolUid
                    )
                    val messageToSend: ChannelMessageToSend? = TriggerUpdateMembersMessage(
                        coreProtocolMessage,
                        protocolManagerSession.identityDelegate.getGroupInformation(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupOwnerAndUid
                        )!!,
                        contactIdentity!!
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
                return ResponseReceivedState()
            }

            if (receivedMessage.invitationAccepted) {
                protocolManagerSession.identityDelegate.addGroupMemberFromPendingMember(
                    protocolManagerSession.session,
                    groupOwnerAndUid,
                    ownedIdentity,
                    contactIdentity,
                    groupMembersChangedCallback
                )
            } else {
                protocolManagerSession.identityDelegate.setPendingMemberDeclined(
                    protocolManagerSession.session,
                    groupOwnerAndUid,
                    ownedIdentity,
                    contactIdentity,
                    true
                )
            }

            return ResponseReceivedState()
        }
    } // endregion

    companion object {
        // region states
        private const val INVITATION_SENT_STATE_ID = 1
        private const val INVITATION_RECEIVED_STATE_ID = 2
        private const val RESPONSE_SENT_STATE_ID = 3
        private const val RESPONSE_RECEIVED_STATE_ID = 4

        // endregion
        // region messages
        private const val INITIAL_MESSAGE_ID = 0
        private const val GROUP_INVITATION_MESSAGE_ID = 1
        private const val DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID = 2
        private const val ACCEPT_INVITATION_MESSAGE_ID = 3
        private const val PROPAGATE_INVITATION_RESPONSE_MESSAGE_ID = 4
    }
}
