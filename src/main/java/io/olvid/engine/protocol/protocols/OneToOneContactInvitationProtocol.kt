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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createAcceptOneToOneInvitationDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createOneToOneInvitationSentDialog
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ProtocolInstance
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.databases.WaitingForOneToOneContactProtocolInstance
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.ContactManagementProtocol.InitiateContactDowngradeMessage
import java.sql.SQLException
import java.util.UUID

class OneToOneContactInvitationProtocol(
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
    override val protocolId: Int = ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            INVITATION_SENT_STATE_ID -> return InvitationSentState::class.java
            INVITATION_RECEIVED_STATE_ID -> return InvitationReceivedState::class.java
            FINISHED_STATE_ID -> return FinishedState::class.java
            else -> return null
        }
    }


    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATE_ID)


    class InvitationSentState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val dialogUuid: UUID?

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            contactIdentity = list[0].decodeIdentity()
            dialogUuid = list[1].decodeUuid()
        }

        constructor(
            contactIdentity: Identity,
            dialogUuid: UUID?
        ) : super(INVITATION_SENT_STATE_ID) {
            this.contactIdentity = contactIdentity
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }


    class InvitationReceivedState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val dialogUuid: UUID?

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            contactIdentity = list[0].decodeIdentity()
            dialogUuid = list[1].decodeUuid()
        }

        constructor(contactIdentity: Identity, dialogUuid: UUID?) : super(
            INVITATION_RECEIVED_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }


    class FinishedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(FINISHED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(FINISHED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    init {
        requiresProtocolInstanceToBeInsertedBeforeInitialStep = true
    }

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            ONE_TO_ONE_INVITATION_MESSAGE_ID -> return OneToOneInvitationMessage::class.java
            DIALOG_INVITATION_SENT_MESSAGE_ID -> return DialogInvitationSentMessage::class.java
            PROPAGATE_ONE_TO_ONE_INVITATION_MESSAGE_ID -> return PropagateOneToOneInvitationMessage::class.java
            DIALOG_ACCEPT_ONE_TO_ONE_INVITATION_MESSAGE_ID -> return DialogAcceptOneToOneInvitationMessage::class.java
            ONE_TO_ONE_RESPONSE_MESSAGE_ID -> return OneToOneResponseMessage::class.java
            PROPAGATE_ONE_TO_ONE_RESPONSE_MESSAGE_ID -> return PropagateOneToOneResponseMessage::class.java
            ABORT_MESSAGE_ID -> return AbortMessage::class.java
            CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID -> return ContactUpgradedToOneToOneMessage::class.java
            PROPAGATE_ABORT_MESSAGE_ID -> return PropagateAbortMessage::class.java
            INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ALL_CONTACTS_MESSAGE_ID -> return InitiateOneToOneStatusSyncWithAllContactsMessage::class.java
            ONE_TO_ONE_STATUS_SYNC_REQUEST_MESSAGE_ID -> return OneToOneStatusSyncRequestMessage::class.java
            INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ONE_CONTACT_MESSAGE_ID -> return InitiateOneToOneStatusSyncWithOneContactMessage::class.java
            else -> return null
        }
    }


    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity)
            )
            }
    }

    class OneToOneInvitationMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = ONE_TO_ONE_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class DialogInvitationSentMessage : ConcreteProtocolMessage {
        internal val abort: Boolean
        internal val dialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            abort = false
            dialogUuid = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            abort = receivedMessage.encodedResponse.decodeBoolean()
            dialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = DIALOG_INVITATION_SENT_MESSAGE_ID

        // not used for this type of message
        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class PropagateOneToOneInvitationMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = PROPAGATE_ONE_TO_ONE_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity)
            )
            }
    }

    class DialogAcceptOneToOneInvitationMessage : ConcreteProtocolMessage {
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

        override val protocolMessageId: Int = DIALOG_ACCEPT_ONE_TO_ONE_INVITATION_MESSAGE_ID

        // not used for this type of message
        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class OneToOneResponseMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?, invitationAccepted: Boolean) : super(
            coreProtocolMessage!!
        ) {
            this.invitationAccepted = invitationAccepted
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.invitationAccepted = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = ONE_TO_ONE_RESPONSE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted)
            )
            }
    }


    class PropagateOneToOneResponseMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?, invitationAccepted: Boolean) : super(
            coreProtocolMessage!!
        ) {
            this.invitationAccepted = invitationAccepted
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.invitationAccepted = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = PROPAGATE_ONE_TO_ONE_RESPONSE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted)
            )
            }
    }


    class AbortMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = ABORT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class ContactUpgradedToOneToOneMessage @Suppress("unused") constructor(receivedMessage: ReceivedMessage) :
        ConcreteProtocolMessage(CoreProtocolMessage(receivedMessage)) {
        var trustLevelIncreasedIdentity: Identity?

        init {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.trustLevelIncreasedIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class PropagateAbortMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = PROPAGATE_ABORT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class InitiateOneToOneStatusSyncWithAllContactsMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ALL_CONTACTS_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class OneToOneStatusSyncRequestMessage : ConcreteProtocolMessage {
        internal val aliceConsidersBobAsOneToOne: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            aliceConsidersBobAsOneToOne: Boolean
        ) : super(coreProtocolMessage!!) {
            this.aliceConsidersBobAsOneToOne = aliceConsidersBobAsOneToOne
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.aliceConsidersBobAsOneToOne = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = ONE_TO_ONE_STATUS_SYNC_REQUEST_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(aliceConsidersBobAsOneToOne),
            )
            }
    }

    class InitiateOneToOneStatusSyncWithOneContactMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, contactIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.contactIdentity = contactIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ONE_CONTACT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
            )
            }
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                AliceInvitesBobStep::class.java,
                BobProcessesAlicesInvitationStep::class.java,
                AliceProcessesPropagatedInvitationStep::class.java,
                AliceAbortsHerInvitationToBobStep::class.java,
                AliceProcessesUnexpectedBobResponseStep::class.java,
                AliceInitiatesOneToOneStatusSyncWithAllContactsStep::class.java,
                AliceInitiatesOneToOneStatusSyncWithOneContactStep::class.java,
                BobProcessesSyncRequestStep::class.java
            )

            INVITATION_SENT_STATE_ID -> return arrayOf<Class<*>>(
                AliceReceivesBobsResponseStep::class.java,
                AliceAbortsHerInvitationToBobStep::class.java,
                ProcessContactUpgradedToOneToOneStep::class.java,
                AliceProcessesPropagatedAbortStep::class.java
            )

            INVITATION_RECEIVED_STATE_ID -> return arrayOf<Class<*>>(
                BobRespondsToAlicesInvitationStep::class.java,
                BobProcessesAbortStep::class.java,
                BobProcessesPropagatedResponseStep::class.java,
                ProcessContactUpgradedToOneToOneStep::class.java
            )

            FINISHED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class AliceInvitesBobStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // we do not check:
            //  - whether Bob is already oneToOne --> we send the invitation anyways
            //  - whether there is a channel with Bob --> if not, protocol will be retried a few times
            val dialogUuid = UUID.randomUUID()
            run {
                // create a dialog to allow Alice to abort the protocol (only if Bob is not one to one)
                if (!protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentity
                    )
                ) {
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createOneToOneInvitationSentDialog(receivedMessage.contactIdentity),
                            dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogInvitationSentMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // send invitation to all of Bob's devices
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneToOneInvitationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // create WaitingForOneToOneContactProtocolInstance
                WaitingForOneToOneContactProtocolInstance.create(
                    protocolManagerSession,
                    protocolInstanceUid,
                    ownedIdentity,
                    receivedMessage.contactIdentity,
                    protocolId,
                    CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID
                )
            }

            run {
                // propagate invitation to you other owned devices (if any)
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
                            PropagateOneToOneInvitationMessage(
                                coreProtocolMessage,
                                receivedMessage.contactIdentity
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

            return InvitationSentState(receivedMessage.contactIdentity, dialogUuid)
        }
    }


    class BobProcessesAlicesInvitationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: OneToOneInvitationMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // first check whether the remote identity is already a oneToOne contact
                if (protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                    )
                ) {
                    // directly confirm to Alice that we accepted the invitation
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? = OneToOneResponseMessage(
                        coreProtocolMessage,
                        true
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )

                    return FinishedState()
                }
            }


            run {
                // check whether there is another protocol instance where Bob invited Alice to become oneToOne
                // detect this by looking at the WaitingForOneToOneContactProtocolInstance db
                val waitingForOneToOneContactProtocolInstances: Array<WaitingForOneToOneContactProtocolInstance> =
                    WaitingForOneToOneContactProtocolInstance.getAllForContact(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                    )
                for (waitingForOneToOneContactProtocolInstance in waitingForOneToOneContactProtocolInstances) {
                    // for each WaitingForOneToOneContactProtocolInstance, check whether the corresponding protocol instance is in the INVITATION_SENT_STATE_ID
                    if (waitingForOneToOneContactProtocolInstance.protocolId == protocolId) {
                        val protocolInstance: ProtocolInstance? = ProtocolInstance.get(
                            protocolManagerSession,
                            waitingForOneToOneContactProtocolInstance.protocolUid,
                            ownedIdentity
                        )
                        if (protocolInstance != null && protocolInstance.currentStateId == INVITATION_SENT_STATE_ID) {
                            // we indeed already invited Alice --> accept the invite and mark her as oneToOne

                            val coreProtocolMessage = buildCoreProtocolMessage(
                                createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                                    ownedIdentity
                                )
                            )
                            val messageToSend: ChannelMessageToSend? = OneToOneResponseMessage(
                                coreProtocolMessage,
                                true
                            ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )

                            protocolManagerSession.identityDelegate!!.setContactOneToOne(
                                protocolManagerSession.session,
                                ownedIdentity,
                                receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                                true
                            )

                            return FinishedState()
                        }
                    }
                }
            }


            /**////// */
            // Alice is not yet oneToOne, and we have not invited her already --> prompt Bob to accept
            /**////// */
            val dialogUuid = UUID.randomUUID()
            run {
                // create the accept invitation dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createAcceptOneToOneInvitationDialog(
                            receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                            receivedMessage.serverTimestamp
                        ),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DialogAcceptOneToOneInvitationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            run {
                // create a WaitingForOneToOneContactProtocolInstance just in case
                WaitingForOneToOneContactProtocolInstance.create(
                    protocolManagerSession,
                    protocolInstanceUid,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                    protocolId,
                    CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID
                )
            }

            return OneToOneContactInvitationProtocol.InvitationReceivedState(
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!, dialogUuid
            )
        }
    }


    class BobRespondsToAlicesInvitationStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: DialogAcceptOneToOneInvitationMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // only send the response if Alice is still a contact
            if (protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            ) {
                run {
                    // send response to Alice
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            startState.contactIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? = OneToOneResponseMessage(
                        coreProtocolMessage,
                        receivedMessage.invitationAccepted
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                run {
                    // update Alice's oneToOne status
                    protocolManagerSession.identityDelegate.setContactOneToOne(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.contactIdentity,
                        receivedMessage.invitationAccepted
                    )
                }
            }

            run {
                // remove the dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        receivedMessage.dialogUuid
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

            run {
                // Propagate the answer to Bob's other devices
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
                        val messageToSend: ChannelMessageToSend? = PropagateOneToOneResponseMessage(
                            coreProtocolMessage,
                            receivedMessage.invitationAccepted
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

            return FinishedState()
        }
    }


    class AliceReceivesBobsResponseStep(
        internal val startState: InvitationSentState,
        internal val receivedMessage: OneToOneResponseMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (!startState.contactIdentity.equals(
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                Logger.e("Contact identity mismatch in AliceReceivesBobsResponseStep: ignoring message.")
                return startState
            }

            run {
                // update Bob's oneToOne status
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity,
                    receivedMessage.invitationAccepted
                )
            }

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

            return FinishedState()
        }
    }


    class AliceAbortsHerInvitationToBobStep(
        internal val startState: InvitationSentState,
        internal val receivedMessage: DialogInvitationSentMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // do nothing if the response is not an abort!
            if (!receivedMessage.abort) {
                return startState
            }

            // only send a response if Bob is still a contact
            if (protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            ) {
                run {
                    // send an abort message to Bob
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            startState.contactIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        AbortMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // remove the dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        receivedMessage.dialogUuid
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

            run {
                // Propagate the abort to Alice's other devices
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
                        val messageToSend: ChannelMessageToSend? =
                            PropagateAbortMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }
            }

            return FinishedState()
        }
    }


    class BobProcessesAbortStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: AbortMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (!startState.contactIdentity.equals(
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                Logger.e("Contact identity mismatch in BobProcessesAbortStep: ignoring message.")
                return startState
            }

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

            return FinishedState()
        }
    }


    class ProcessContactUpgradedToOneToOneStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val contactIdentity: Identity?
        internal val dialogUuid: UUID?

        @Suppress("unused")
        internal val receivedMessage: ContactUpgradedToOneToOneMessage?

        @Suppress("unused")
        constructor(
            startState: InvitationSentState,
            receivedMessage: ContactUpgradedToOneToOneMessage?,
            protocol: OneToOneContactInvitationProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.contactIdentity = startState.contactIdentity
            this.dialogUuid = startState.dialogUuid
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: ContactUpgradedToOneToOneMessage?,
            protocol: OneToOneContactInvitationProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.contactIdentity = startState.contactIdentity
            this.dialogUuid = startState.dialogUuid
            this.receivedMessage = receivedMessage
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check that the contact is indeed oneToOne now --> otherwise do nothing
                if (!protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        contactIdentity
                    )
                ) {
                    return startState
                }
            }

            run {
                // remove the dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        dialogUuid
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

            return FinishedState()
        }
    }


    class AliceProcessesPropagatedInvitationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateOneToOneInvitationMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val dialogUuid = UUID.randomUUID()
            run {
                // create a dialog to allow Alice to abort the protocol (only if Bob is not one to one)
                if (!protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentity
                    )
                ) {
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createOneToOneInvitationSentDialog(receivedMessage.contactIdentity),
                            dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogInvitationSentMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // create WaitingForOneToOneContactProtocolInstance
                WaitingForOneToOneContactProtocolInstance.create(
                    protocolManagerSession,
                    protocolInstanceUid,
                    ownedIdentity,
                    receivedMessage.contactIdentity,
                    protocolId,
                    CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID
                )
            }

            return InvitationSentState(receivedMessage.contactIdentity, dialogUuid)
        }
    }


    class BobProcessesPropagatedResponseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: PropagateOneToOneResponseMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // update Alice's oneToOne status
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity,
                    receivedMessage.invitationAccepted
                )
            }

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

            return FinishedState()
        }
    }


    class AliceProcessesPropagatedAbortStep(
        internal val startState: InvitationSentState,
        @field:Suppress(
            "unused"
        ) internal val receivedMessage: PropagateAbortMessage?,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage!!, protocol!!
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

            return FinishedState()
        }
    }


    class AliceProcessesUnexpectedBobResponseStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: OneToOneResponseMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            run {
                // if Bob accepted the invitation, there is nothing to do: we never upgrade him for now reason, and won't tell him to downgrade.
                if (receivedMessage.invitationAccepted) {
                    return FinishedState()
                }
            }

            // Bob sent us an invitation rejected response, we downgrade him
            run {
                // mark Bob as not oneToOne
                protocolManagerSession.identityDelegate!!.setContactOneToOne(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                    false
                )
            }

            run {
                // start a downgrade protocol
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitiateContactDowngradeMessage(
                    coreProtocolMessage,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinishedState()
        }
    }

    class AliceInitiatesOneToOneStatusSyncWithAllContactsStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        @field:Suppress(
            "unused"
        ) internal val receivedMessage: InitiateOneToOneStatusSyncWithAllContactsMessage?,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            run {
                val contactIdentities =
                    protocolManagerSession.identityDelegate!!.getContactsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                // send a sync message to all contacts, within a try as some contacts without channel may fail
                for (contactIdentity in contactIdentities!!) {
                    try {
                        val oneToOne: Boolean
                        if (protocolManagerSession.identityDelegate.isIdentityAOneToOneContactOfOwnedIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                contactIdentity
                            )
                        ) {
                            oneToOne = true
                        } else if (protocolManagerSession.identityDelegate.isIdentityANotOneToOneContactOfOwnedIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                contactIdentity
                            )
                        ) {
                            oneToOne = false
                        } else {
                            // if oneToOne status is unknown, do nothing
                            continue
                        }
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                contactIdentity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? = OneToOneStatusSyncRequestMessage(
                            coreProtocolMessage,
                            oneToOne
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: SQLException) {
                        // in case of SQLException we fail --> allows to retry the step
                        return null
                    } catch (_: Exception) {
                        // ignore exceptions during the post operation
                    }
                }
            }

            return FinishedState()
        }
    }

    class AliceInitiatesOneToOneStatusSyncWithOneContactStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateOneToOneStatusSyncWithOneContactMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // send a sync message to specific contact. He should have a channel, so fail in case of Exception
                val oneToOne: Boolean
                if (protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentity
                    )
                ) {
                    oneToOne = true
                } else if (protocolManagerSession.identityDelegate.isIdentityANotOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentity
                    )
                ) {
                    oneToOne = false
                } else {
                    // if oneToOne status is unknown, do nothing
                    return FinishedState()
                }

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = OneToOneStatusSyncRequestMessage(
                    coreProtocolMessage,
                    oneToOne
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinishedState()
        }
    }

    class BobProcessesSyncRequestStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: OneToOneStatusSyncRequestMessage,
        protocol: OneToOneContactInvitationProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val aliceIsOneToOne: Boolean
            if (protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                aliceIsOneToOne = true
            } else if (protocolManagerSession.identityDelegate.isIdentityANotOneToOneContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                )
            ) {
                aliceIsOneToOne = false
            } else {
                // if oneToOne status is unknown, do nothing
                return FinishedState()
            }

            if (aliceIsOneToOne != receivedMessage.aliceConsidersBobAsOneToOne) {
                if (aliceIsOneToOne) {
                    // we consider Alice as oneToOne, but she does not --> we downgrade her
                    protocolManagerSession.identityDelegate.setContactOneToOne(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                        false
                    )
                } else {
                    // Alice considers us as oneToOne, but we don't --> we check if we have a pending invitation for her

                    val waitingForOneToOneContactProtocolInstances: Array<WaitingForOneToOneContactProtocolInstance> =
                        WaitingForOneToOneContactProtocolInstance.getAllForContact(
                            protocolManagerSession,
                            ownedIdentity,
                            receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
                        )
                    for (waitingForOneToOneContactProtocolInstance in waitingForOneToOneContactProtocolInstances) {
                        // for each WaitingForOneToOneContactProtocolInstance, check whether the corresponding protocol instance is in the INVITATION_SENT_STATE_ID
                        if (waitingForOneToOneContactProtocolInstance.protocolId == protocolId) {
                            val protocolInstance: ProtocolInstance? =
                                ProtocolInstance.get(
                                    protocolManagerSession,
                                    waitingForOneToOneContactProtocolInstance.protocolUid,
                                    ownedIdentity
                                )
                            if (protocolInstance != null && protocolInstance.currentStateId == INVITATION_SENT_STATE_ID) {
                                // we indeed already invited Alice --> mark her as oneToOne, this will trigger the other waiting instance and finish the protocol

                                protocolManagerSession.identityDelegate.setContactOneToOne(
                                    protocolManagerSession.session,
                                    ownedIdentity,
                                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                                    true
                                )

                                return FinishedState()
                            }
                        }
                    }

                    // we did not find an invitation, so we tell Alice to downgrade us with an unexpected response
                    // we generate a new random UID as her protocol instance already reached a final state (and she may receive other responses for the same protocol Uid)
                    val coreProtocolMessage = CoreProtocolMessage(
                        createAllConfirmedObliviousChannelsOrPreKeysInfo(
                            receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                            ownedIdentity
                        ),
                        protocolId,
                        UID(prng)
                    )
                    val messageToSend: ChannelMessageToSend? = OneToOneStatusSyncRequestMessage(
                        coreProtocolMessage,
                        false
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            return FinishedState()
        }
    } // endregion

    companion object {
        // region States
        const val INVITATION_SENT_STATE_ID: Int = 1
        const val INVITATION_RECEIVED_STATE_ID: Int = 2
        const val FINISHED_STATE_ID: Int = 3

        // endregion
        // region Messages
        private const val INITIAL_MESSAGE_ID = 0
        private const val ONE_TO_ONE_INVITATION_MESSAGE_ID = 1
        private const val DIALOG_INVITATION_SENT_MESSAGE_ID = 2
        private const val PROPAGATE_ONE_TO_ONE_INVITATION_MESSAGE_ID = 3
        private const val DIALOG_ACCEPT_ONE_TO_ONE_INVITATION_MESSAGE_ID = 4
        private const val ONE_TO_ONE_RESPONSE_MESSAGE_ID = 5
        private const val PROPAGATE_ONE_TO_ONE_RESPONSE_MESSAGE_ID = 6
        private const val ABORT_MESSAGE_ID = 7
        private const val CONTACT_UPGRADED_TO_ONE_TO_ONE_MESSAGE_ID = 8
        private const val PROPAGATE_ABORT_MESSAGE_ID = 9
        private const val INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ALL_CONTACTS_MESSAGE_ID = 10
        private const val ONE_TO_ONE_STATUS_SYNC_REQUEST_MESSAGE_ID = 11
        private const val INITIATE_ONE_TO_ONE_STATUS_SYNC_WITH_ONE_CONTACT_MESSAGE_ID = 12
    }
}
