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
import io.olvid.engine.crypto.Signature
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createAcceptMediatorInviteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createMediatorInviteAcceptedDialog
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAsymmetricBroadcastChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createIntroductionTrustOrigin
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.databases.WaitingForOneToOneContactProtocolInstance
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.EmptyProtocolMessage
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.util.UUID

class ContactMutualIntroductionProtocol(
    protocolManagerSession: ProtocolManagerSession?,
    protocolInstanceUid: UID?,
    currentStateId: Int,
    encodedCurrentState: Encoded?,
    ownedIdentity: Identity?,
    prng: PRNGService,
    jsonObjectMapper: ObjectMapper
) : ConcreteProtocol(
    protocolManagerSession,
    protocolInstanceUid,
    currentStateId,
    encodedCurrentState,
    ownedIdentity!!,
    prng,
    jsonObjectMapper
) {
    override val protocolId: Int = ConcreteProtocol.CONTACT_MUTUAL_INTRODUCTION_PROTOCOL_ID


    override val finalStateIds: IntArray? get() = intArrayOf(
            CONTACTS_INTRODUCED_STATE_ID,
            INVITATION_REJECTED_STATE_ID,
            MUTUAL_TRUST_ESTABLISHED_STATE_ID
        )

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            CONTACTS_INTRODUCED_STATE_ID -> return ContactsIntroducedState::class.java
            INVITATION_RECEIVED_STATE_ID -> return InvitationReceivedState::class.java
            INVITATION_ACCEPTED_STATE_ID -> return InvitationAcceptedState::class.java
            INVITATION_REJECTED_STATE_ID -> return InvitationRejectedState::class.java
            WAITING_FOR_ACK_STATE_ID -> return WaitingForAckState::class.java
            MUTUAL_TRUST_ESTABLISHED_STATE_ID -> return MutualTrustEstablishedState::class.java
            else -> return null
        }
    }


    class ContactsIntroducedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CONTACTS_INTRODUCED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(CONTACTS_INTRODUCED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class InvitationReceivedState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val mediatorIdentity: Identity
        internal val dialogUuid: UUID?

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.mediatorIdentity = list[2].decodeIdentity()
            this.dialogUuid = list[3].decodeUuid()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            mediatorIdentity: Identity,
            dialogUuid: UUID?
        ) : super(
            INVITATION_RECEIVED_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.mediatorIdentity = mediatorIdentity
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(mediatorIdentity),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }


    class InvitationAcceptedState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val mediatorIdentity: Identity
        internal val dialogUuid: UUID?
        internal val acceptType: Int

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_ACCEPTED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.mediatorIdentity = list[2].decodeIdentity()
            this.dialogUuid = list[3].decodeUuid()
            this.acceptType = list[4].decodeLong().toInt()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            mediatorIdentity: Identity,
            dialogUuid: UUID?,
            acceptType: Int
        ) : super(
            INVITATION_ACCEPTED_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.mediatorIdentity = mediatorIdentity
            this.dialogUuid = dialogUuid
            this.acceptType = acceptType
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(mediatorIdentity),
                    Encoded.of(dialogUuid),
                    Encoded.of(acceptType.toLong()),
                )
            )
        }
    }


    class InvitationRejectedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_REJECTED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(INVITATION_REJECTED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class WaitingForAckState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val mediatorIdentity: Identity
        internal val dialogUuid: UUID?
        internal val acceptType: Int

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_ACK_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.mediatorIdentity = list[2].decodeIdentity()
            this.dialogUuid = list[3].decodeUuid()
            this.acceptType = list[4].decodeLong().toInt()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            mediatorIdentity: Identity,
            dialogUuid: UUID?,
            acceptType: Int
        ) : super(
            WAITING_FOR_ACK_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.mediatorIdentity = mediatorIdentity
            this.dialogUuid = dialogUuid
            this.acceptType = acceptType
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(mediatorIdentity),
                    Encoded.of(dialogUuid),
                    Encoded.of(acceptType.toLong()),
                )
            )
        }
    }


    class MutualTrustEstablishedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(MUTUAL_TRUST_ESTABLISHED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(MUTUAL_TRUST_ESTABLISHED_STATE_ID)

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
            MEDIATOR_INVITATION_MESSAGE_ID -> return MediatorInvitationMessage::class.java
            DIALOG_ACCEPT_MEDIATOR_INVITE_MESSAGE_ID -> return DialogAcceptMediatorInviteMessage::class.java
            PROPAGATE_CONFIRMATION_MESSAGE_ID -> return PropagateConfirmationMessage::class.java
            NOTIFY_CONTACT_OF_ACCEPTED_INVITATION_MESSAGE_ID -> return NotifyContactOfAcceptedInvitationMessage::class.java
            PROPAGATE_NOTIFICATION_MESSAGE_ID -> return PropagateNotificationMessage::class.java
            ACK_MESSAGE_ID -> return AckMessage::class.java
            TRUST_LEVEL_INCREASED_MESSAGE_ID -> return TrustLevelIncreasedMessage::class.java
            PROPAGATED_INITIAL_MESSAGE -> return PropagatedInitialMessage::class.java
            else -> return null
        }
    }


    open class InitialMessage : ConcreteProtocolMessage {
        @JvmField val contactIdentityA: Identity
        @JvmField val contactIdentityB: Identity

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentityA: Identity,
            contactIdentityB: Identity
        ) : super(coreProtocolMessage!!) {
            this.contactIdentityA = contactIdentityA
            this.contactIdentityB = contactIdentityB
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentityA = receivedMessage.inputs[0].decodeIdentity()
            this.contactIdentityB = receivedMessage.inputs[1].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentityA),
                Encoded.of(contactIdentityB),
            )
            }
    }


    class MediatorInvitationMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactSerializedDetails: String
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactSerializedDetails = receivedMessage.inputs[1].decodeString()
        }

        override val protocolMessageId: Int = MEDIATOR_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactSerializedDetails),
            )
            }
    }


    class DialogAcceptMediatorInviteMessage : ConcreteProtocolMessage {
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

        override val protocolMessageId: Int = DIALOG_ACCEPT_MEDIATOR_INVITE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class PropagateConfirmationMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val mediatorIdentity: Identity

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            invitationAccepted: Boolean,
            contactIdentity: Identity,
            contactSerializedDetails: String,
            mediatorIdentity: Identity
        ) : super(coreProtocolMessage!!) {
            this.invitationAccepted = invitationAccepted
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.mediatorIdentity = mediatorIdentity
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.invitationAccepted = receivedMessage.inputs[0].decodeBoolean()
            this.contactIdentity = receivedMessage.inputs[1].decodeIdentity()
            this.contactSerializedDetails = receivedMessage.inputs[2].decodeString()
            this.mediatorIdentity = receivedMessage.inputs[3].decodeIdentity()
        }

        override val protocolMessageId: Int = PROPAGATE_CONFIRMATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted),
                Encoded.of(contactIdentity),
                Encoded.of(contactSerializedDetails),
                Encoded.of(mediatorIdentity),
            )
            }
    }

    class NotifyContactOfAcceptedInvitationMessage : ConcreteProtocolMessage {
        internal val contactDeviceUids: Array<UID?>?
        internal val signature: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactDeviceUids: Array<UID?>,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.contactDeviceUids = contactDeviceUids
            this.signature = signature
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactDeviceUids = receivedMessage.inputs[0].decodeUidArray()
            this.signature = receivedMessage.inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = NOTIFY_CONTACT_OF_ACCEPTED_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactDeviceUids!!),
                Encoded.of(signature),
            )
            }
    }


    class PropagateNotificationMessage : ConcreteProtocolMessage {
        internal val contactDeviceUids: Array<UID?>?

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactDeviceUids: Array<UID?>
        ) : super(coreProtocolMessage!!) {
            this.contactDeviceUids = contactDeviceUids
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.contactDeviceUids = receivedMessage.inputs[0].decodeUidArray()
        }

        override val protocolMessageId: Int = PROPAGATE_NOTIFICATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactDeviceUids!!),
            )
            }
    }


    class AckMessage : EmptyProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = ACK_MESSAGE_ID
    }


    class TrustLevelIncreasedMessage(receivedMessage: ReceivedMessage) :
        ConcreteProtocolMessage(CoreProtocolMessage(receivedMessage)) {
        @JvmField var trustLevelIncreasedIdentity: Identity?

        // no other constructor needed here. Instances are created by WaitingForOneToOneContactProtocolInstance.getGenericProtocolMessageToSendWhenTrustLevelIncreased()
        init {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.trustLevelIncreasedIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = TRUST_LEVEL_INCREASED_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class PropagatedInitialMessage : InitialMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentityA: Identity,
            contactIdentityB: Identity
        ) : super(coreProtocolMessage, contactIdentityA, contactIdentityB)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATED_INITIAL_MESSAGE
    }


    // endregion
    // region steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                IntroduceContactsStep::class.java,
                ProcessPropagatedInitialMessageStep::class.java,
                CheckTrustLevelsAndShowDialogStep::class.java
            )

            INVITATION_RECEIVED_STATE_ID -> return arrayOf<Class<*>>(
                PropagateInviteResponseStep::class.java,
                ProcessPropagatedInviteResponseStep::class.java,
                ReCheckTrustLevelsAfterTrustLevelIncreaseStep::class.java
            )

            INVITATION_ACCEPTED_STATE_ID -> return arrayOf<Class<*>>(
                PropagateNotificationAddTrustAndSendAckStep::class.java,
                ProcessPropagatedNotificationAndAddTrustStep::class.java
            )

            WAITING_FOR_ACK_STATE_ID -> return arrayOf<Class<*>>(NotifyMutualTrustEstablishedStep::class.java)
            CONTACTS_INTRODUCED_STATE_ID, INVITATION_REJECTED_STATE_ID, MUTUAL_TRUST_ESTABLISHED_STATE_ID -> return arrayOf<Class<*>>()

            else -> return arrayOf<Class<*>>()
        }
    }

    class IntroduceContactsStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check that both contacts are active and oneToOne
                if (!protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityA
                    ) || !protocolManagerSession.identityDelegate.isIdentityAOneToOneContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityB
                    ) || !protocolManagerSession.identityDelegate.isIdentityAnActiveContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityA
                    ) || !protocolManagerSession.identityDelegate.isIdentityAnActiveContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityB
                    )
                ) {
                    return ContactsIntroducedState()
                }
            }

            run {
                // post an invitation message to contact A
                val serializedDetailsB =
                    protocolManagerSession.identityDelegate!!.getSerializedPublishedDetailsOfContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityB
                    )
                val coreProtocolMessage = CoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentityA,
                        ownedIdentity
                    ), protocolId, protocolInstanceUid, true
                )
                val messageToSend: ChannelMessageToSend? = MediatorInvitationMessage(
                    coreProtocolMessage,
                    receivedMessage.contactIdentityB,
                    serializedDetailsB!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // post an invitation message to contact B
                val serializedDetailsA =
                    protocolManagerSession.identityDelegate!!.getSerializedPublishedDetailsOfContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentityA
                    )
                val coreProtocolMessage = CoreProtocolMessage(
                    createAllConfirmedObliviousChannelsOrPreKeysInfo(
                        receivedMessage.contactIdentityB,
                        ownedIdentity
                    ), protocolId, protocolInstanceUid, true
                )
                val messageToSend: ChannelMessageToSend? = MediatorInvitationMessage(
                    coreProtocolMessage,
                    receivedMessage.contactIdentityA,
                    serializedDetailsA!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // if we have other devices, propagate the invite so the invitation sent messages can be inserted in the relevant discussion
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
                        val messageToSend: ChannelMessageToSend? = PropagatedInitialMessage(
                            coreProtocolMessage,
                            receivedMessage.contactIdentityA,
                            receivedMessage.contactIdentityB
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

            // send a notification to insert invitation sent messages in relevant discussions
            protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                val userInfo = HashMap<String, Any>()
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_A_KEY] = receivedMessage.contactIdentityA
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_B_KEY] = receivedMessage.contactIdentityB
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT,
                    userInfo
                )
            })

            return ContactsIntroducedState()
        }
    }


    class ProcessPropagatedInitialMessageStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagatedInitialMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // send a notification to insert invitation sent messages in relevant discussions
            protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                val userInfo = HashMap<String, Any>()
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_A_KEY] = receivedMessage.contactIdentityA
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_B_KEY] = receivedMessage.contactIdentityB
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT,
                    userInfo
                )
            })

            return ContactsIntroducedState()
        }
    }

    class CheckTrustLevelsAndShowDialogStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: MediatorInvitationMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val mediatorIdentity = receivedMessage.receptionChannelInfo!!.getRemoteIdentity()

            // check that the mediator is a one to one contact --> reject if not
            if (!protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    mediatorIdentity
                )
            ) {
                return InvitationRejectedState()
            }

            // check if presented contact is already oneToOne
            val contactAlreadyOneToOne =
                protocolManagerSession.identityDelegate.isIdentityAOneToOneContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.contactIdentity
                )
            if (contactAlreadyOneToOne) {
                // auto-accept
                val deviceUids =
                    protocolManagerSession.identityDelegate.getDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )

                val signature = protocolManagerSession.identityDelegate.signIdentities(
                    protocolManagerSession.session,
                    Constants.SignatureContext.MUTUAL_INTRODUCTION,
                    arrayOf<Identity?>(
                        mediatorIdentity,
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    ),
                    ownedIdentity,
                    prng
                )

                // notify contact and send him the deviceUids to send ACK to
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAsymmetricBroadcastChannelInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = NotifyContactOfAcceptedInvitationMessage(
                    coreProtocolMessage,
                    deviceUids!!,
                    signature!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                val dialogUuid = UUID.randomUUID()

                return InvitationAcceptedState(
                    receivedMessage.contactIdentity,
                    receivedMessage.contactSerializedDetails,
                    mediatorIdentity!!,
                    dialogUuid,
                    ACCEPT_TYPE_ALREADY_TRUSTED
                )
            } else {
                // prompt user to accept
                val dialogUuid = UUID.randomUUID()

                run {
                    // display mediator invite dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createAcceptMediatorInviteDialog(
                                receivedMessage.contactSerializedDetails,
                                receivedMessage.contactIdentity,
                                mediatorIdentity,
                                receivedMessage.serverTimestamp
                            ),
                            dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogAcceptMediatorInviteMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                // also insert a WaitingForTrustLevelIncrease to re-evaluate if needed.
                WaitingForOneToOneContactProtocolInstance.create(
                    protocolManagerSession,
                    protocolInstanceUid,
                    ownedIdentity,
                    receivedMessage.contactIdentity,
                    protocolId,
                    TRUST_LEVEL_INCREASED_MESSAGE_ID
                )

                return ContactMutualIntroductionProtocol.InvitationReceivedState(
                    receivedMessage.contactIdentity,
                    receivedMessage.contactSerializedDetails,
                    mediatorIdentity!!,
                    dialogUuid
                )
            }
        }
    }


    class ReCheckTrustLevelsAfterTrustLevelIncreaseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: TrustLevelIncreasedMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // check if presented contact is already oneToOne
            val contactAlreadyTrusted =
                protocolManagerSession.identityDelegate!!.isIdentityAOneToOneContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            if (contactAlreadyTrusted) {
                // auto-accept
                run {
                    val deviceUids =
                        protocolManagerSession.identityDelegate.getDeviceUidsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )
                    val signature = protocolManagerSession.identityDelegate.signIdentities(
                        protocolManagerSession.session,
                        Constants.SignatureContext.MUTUAL_INTRODUCTION,
                        arrayOf<Identity?>(
                            startState.mediatorIdentity,
                            startState.contactIdentity,
                            ownedIdentity
                        ),
                        ownedIdentity,
                        prng
                    )

                    // notify contact and send him the deviceUids to send ACK to
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(
                            startState.contactIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        NotifyContactOfAcceptedInvitationMessage(
                            coreProtocolMessage,
                            deviceUids!!,
                            signature!!
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                // remove the old dialog
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

                return InvitationAcceptedState(
                    startState.contactIdentity,
                    startState.contactSerializedDetails,
                    startState.mediatorIdentity,
                    startState.dialogUuid,
                    ACCEPT_TYPE_ALREADY_TRUSTED
                )
            } else {
                // prompt user to accept
                run {
                    // display mediator invite dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createAcceptMediatorInviteDialog(
                                startState.contactSerializedDetails,
                                startState.contactIdentity,
                                startState.mediatorIdentity,
                                System.currentTimeMillis()
                            ),
                            startState.dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogAcceptMediatorInviteMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }


                run {
                    // also insert a WaitingForTrustLevelIncrease to re-evaluate if needed (and delete the previous one)
                    val instance: WaitingForOneToOneContactProtocolInstance? =
                        WaitingForOneToOneContactProtocolInstance.get(
                            protocolManagerSession,
                            protocolInstanceUid,
                            ownedIdentity,
                            receivedMessage.trustLevelIncreasedIdentity
                        )
                    if (instance != null) {
                        instance.delete()
                    }
                    WaitingForOneToOneContactProtocolInstance.create(
                        protocolManagerSession,
                        protocolInstanceUid,
                        ownedIdentity,
                        startState.contactIdentity,
                        protocolId,
                        TRUST_LEVEL_INCREASED_MESSAGE_ID
                    )
                }

                return startState
            }
        }
    }


    class PropagateInviteResponseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: DialogAcceptMediatorInviteMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (startState.dialogUuid != receivedMessage.dialogUuid) {
                Logger.e("ObvDialog uuid mismatch in DialogAcceptMediatorInviteMessage.")
                return null
            }

            run {
                // Propagate the accept/reject to other owned devices
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
                        val messageToSend: ChannelMessageToSend? = PropagateConfirmationMessage(
                            coreProtocolMessage,
                            receivedMessage.invitationAccepted,
                            startState.contactIdentity,
                            startState.contactSerializedDetails,
                            startState.mediatorIdentity
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

            // send a notification to insert invitation accepted/ignored messages in the discussion
            protocolManagerSession.session.addSessionCommitListener {
                val userInfo = HashMap<String, Any>()
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_MEDIATOR_IDENTITY_KEY] = startState.mediatorIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_IDENTITY_KEY] = startState.contactIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY] = startState.contactSerializedDetails
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY] = receivedMessage.invitationAccepted
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE,
                    userInfo
                )
            }

            if (receivedMessage.invitationAccepted) {
                run {
                    // Display invitation accepted dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createMediatorInviteAcceptedDialog(
                                startState.contactSerializedDetails,
                                startState.contactIdentity,
                                startState.mediatorIdentity
                            ),
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

                run {
                    val deviceUids =
                        protocolManagerSession.identityDelegate!!.getDeviceUidsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )
                    val signature = protocolManagerSession.identityDelegate.signIdentities(
                        protocolManagerSession.session,
                        Constants.SignatureContext.MUTUAL_INTRODUCTION,
                        arrayOf<Identity?>(
                            startState.mediatorIdentity,
                            startState.contactIdentity,
                            ownedIdentity
                        ),
                        ownedIdentity,
                        prng
                    )

                    // notify contact and send him the deviceUids to send ACK to
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(
                            startState.contactIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        NotifyContactOfAcceptedInvitationMessage(
                            coreProtocolMessage,
                            deviceUids!!,
                            signature!!
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                return InvitationAcceptedState(
                    startState.contactIdentity,
                    startState.contactSerializedDetails,
                    startState.mediatorIdentity,
                    startState.dialogUuid,
                    ACCEPT_TYPE_MANUAL
                )
            } else {
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

                return InvitationRejectedState()
            }
        }
    }


    class ProcessPropagatedInviteResponseStep(
        internal val startState: InvitationReceivedState,
        internal val receivedMessage: PropagateConfirmationMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // send a notification to insert invitation accepted/ignored messages in the discussion
            protocolManagerSession.session.addSessionCommitListener {
                val userInfo = HashMap<String, Any>()
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_OWNED_IDENTITY_KEY] = ownedIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_MEDIATOR_IDENTITY_KEY] = startState.mediatorIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_IDENTITY_KEY] = startState.contactIdentity
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY] = startState.contactSerializedDetails
                userInfo[ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY] = receivedMessage.invitationAccepted
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE,
                    userInfo
                )
            }

            if (receivedMessage.invitationAccepted) {
                run {
                    // Display invitation accepted dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createMediatorInviteAcceptedDialog(
                                receivedMessage.contactSerializedDetails,
                                receivedMessage.contactIdentity,
                                receivedMessage.mediatorIdentity
                            ),
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

                return InvitationAcceptedState(
                    receivedMessage.contactIdentity,
                    receivedMessage.contactSerializedDetails,
                    receivedMessage.mediatorIdentity,
                    startState.dialogUuid,
                    ACCEPT_TYPE_MANUAL
                )
            } else {
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

                return InvitationRejectedState()
            }
        }
    }


    class PropagateNotificationAddTrustAndSendAckStep(
        internal val startState: InvitationAcceptedState,
        internal val receivedMessage: NotifyContactOfAcceptedInvitationMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            val signatureIsValid = Signature.verify(
                Constants.SignatureContext.MUTUAL_INTRODUCTION,
                arrayOf<Identity?>(
                    startState.mediatorIdentity,
                    ownedIdentity,
                    startState.contactIdentity
                ),
                startState.contactIdentity,
                receivedMessage.signature
            )

            if (!signatureIsValid) {
                Logger.w("Received a NotifyContactOfAcceptedInvitationMessage with an invalid signature")
                return null
            }

            // only create the contact if it does not already exist
            if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            ) {
                protocolManagerSession.identityDelegate.addContactIdentity(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    startState.contactSerializedDetails,
                    ownedIdentity,
                    createIntroductionTrustOrigin(
                        System.currentTimeMillis(), startState.mediatorIdentity
                    ),
                    true
                )
            } else {
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    createIntroductionTrustOrigin(
                        System.currentTimeMillis(), startState.mediatorIdentity
                    ),
                    true
                )
            }

            var triggerDeviceDiscovery = false
            for (contactDeviceUid in receivedMessage.contactDeviceUids!!) {
                triggerDeviceDiscovery =
                    triggerDeviceDiscovery or protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.contactIdentity,
                        contactDeviceUid,
                        null,
                        false
                    )
            }
            if (triggerDeviceDiscovery) {
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,
                    UID(prng)
                )
                val messageToSend: ChannelMessageToSend? = DeviceDiscoveryProtocol.InitialMessage(
                    coreProtocolMessage,
                    startState.contactIdentity
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            run {
                // Propagate the notification to other owned devices
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
                        val messageToSend: ChannelMessageToSend? = PropagateNotificationMessage(
                            coreProtocolMessage,
                            receivedMessage.contactDeviceUids!!
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
                // send ack to contact
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        receivedMessage.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AckMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForAckState(
                startState.contactIdentity,
                startState.contactSerializedDetails,
                startState.mediatorIdentity,
                startState.dialogUuid,
                startState.acceptType
            )
        }
    }


    class ProcessPropagatedNotificationAndAddTrustStep(
        internal val startState: InvitationAcceptedState,
        internal val receivedMessage: PropagateNotificationMessage,
        protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // only create the contact if it does not already exist
            if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            ) {
                protocolManagerSession.identityDelegate.addContactIdentity(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    startState.contactSerializedDetails,
                    ownedIdentity,
                    createIntroductionTrustOrigin(
                        System.currentTimeMillis(), startState.mediatorIdentity
                    ),
                    true
                )
            } else {
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    createIntroductionTrustOrigin(
                        System.currentTimeMillis(), startState.mediatorIdentity
                    ),
                    true
                )
            }

            var triggerDeviceDiscovery = false
            for (contactDeviceUid in receivedMessage.contactDeviceUids!!) {
                triggerDeviceDiscovery =
                    triggerDeviceDiscovery or protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.contactIdentity,
                        contactDeviceUid,
                        null,
                        false
                    )
            }
            if (triggerDeviceDiscovery) {
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID,
                    UID(prng)
                )
                val messageToSend: ChannelMessageToSend? = DeviceDiscoveryProtocol.InitialMessage(
                    coreProtocolMessage,
                    startState.contactIdentity
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForAckState(
                startState.contactIdentity,
                startState.contactSerializedDetails,
                startState.mediatorIdentity,
                startState.dialogUuid,
                startState.acceptType
            )
        }
    }


    class NotifyMutualTrustEstablishedStep(
        internal val startState: WaitingForAckState, @field:Suppress(
            "unused"
        ) internal val receivedMessage: AckMessage?, protocol: ContactMutualIntroductionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // display the mutual trust established dialog
                when (startState.acceptType) {
                    ACCEPT_TYPE_MANUAL -> {
                        // delete dialog
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

                    ACCEPT_TYPE_ALREADY_TRUSTED -> {}
                    else -> {}
                }
            }

            return MutualTrustEstablishedState()
        }
    } // endregion

    companion object {
        private const val ACCEPT_TYPE_ALREADY_TRUSTED = 0
        private const val ACCEPT_TYPE_MANUAL = 2

        // region states
        private const val CONTACTS_INTRODUCED_STATE_ID = 1
        private const val INVITATION_RECEIVED_STATE_ID = 2
        private const val INVITATION_ACCEPTED_STATE_ID = 3
        private const val INVITATION_REJECTED_STATE_ID = 4
        private const val WAITING_FOR_ACK_STATE_ID = 5
        private const val MUTUAL_TRUST_ESTABLISHED_STATE_ID = 6


        // endregion
        // region messages
        private const val INITIAL_MESSAGE_ID = 0
        private const val MEDIATOR_INVITATION_MESSAGE_ID = 1
        private const val DIALOG_ACCEPT_MEDIATOR_INVITE_MESSAGE_ID = 2
        private const val PROPAGATE_CONFIRMATION_MESSAGE_ID = 3
        private const val NOTIFY_CONTACT_OF_ACCEPTED_INVITATION_MESSAGE_ID = 4
        private const val PROPAGATE_NOTIFICATION_MESSAGE_ID = 5
        private const val ACK_MESSAGE_ID = 6
        private const val TRUST_LEVEL_INCREASED_MESSAGE_ID = 7
        private const val PROPAGATED_INITIAL_MESSAGE = 9 // we skip 8 to stay in sync with iOS
    }
}
