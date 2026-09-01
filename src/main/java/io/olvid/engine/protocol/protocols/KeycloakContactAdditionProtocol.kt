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
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.CheckKeycloakRevocationQuery
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createKeycloakTrustOrigin
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.LinkBetweenProtocolInstances
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.ChildToParentProtocolMessageInputs
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.DeviceDiscoveryChildProtocol.DeviceUidsReceivedState


class KeycloakContactAdditionProtocol(
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
    ownedIdentity,
    prng,
    jsonObjectMapper
) {
    override val protocolId: Int = ConcreteProtocol.KEYCLOAK_CONTACT_ADDITION_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            WAITING_FOR_DEVICE_DISCOVERY_STATED_ID -> return WaitingForDeviceDiscoveryState::class.java
            WAITING_FOR_CONFIRMATION_STATE_ID -> return WaitingForConfirmationState::class.java
            CHECKING_FOR_REVOCATION_STATE_ID -> return CheckingForRevocationState::class.java
            FINISHED_STATE_ID -> return FinishedProtocolState::class.java
            else -> return null
        }
    }

    class WaitingForDeviceDiscoveryState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String // this is a serialized JsonIdentityDetails
        internal val keycloakServerUrl: String
        internal val signedOwnedDetails: String // this is a JWT

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_DEVICE_DISCOVERY_STATED_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            contactIdentity = list[0].decodeIdentity()
            contactSerializedDetails = list[1].decodeString()
            keycloakServerUrl = list[2].decodeString()
            signedOwnedDetails = list[3].decodeString()
        }

        constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            keycloakServerUrl: String,
            signedOwnedDetails: String
        ) : super(
            WAITING_FOR_DEVICE_DISCOVERY_STATED_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.keycloakServerUrl = keycloakServerUrl
            this.signedOwnedDetails = signedOwnedDetails
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(keycloakServerUrl),
                    Encoded.of(signedOwnedDetails),
                )
            )
        }
    }

    class WaitingForConfirmationState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val keycloakServerUrl: String

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_CONFIRMATION_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.keycloakServerUrl = list[1].decodeString()
        }

        constructor(contactIdentity: Identity, keycloakServerUrl: String) : super(
            WAITING_FOR_CONFIRMATION_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.keycloakServerUrl = keycloakServerUrl
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(keycloakServerUrl),
                )
            )
        }
    }

    class CheckingForRevocationState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String // serialized JsonIdentityDetails containing the signed JWT
        internal val contactDeviceUids: Array<UID?>?
        internal val keycloakServerUrl: String

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CHECKING_FOR_REVOCATION_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            contactIdentity = list[0].decodeIdentity()
            contactSerializedDetails = list[1].decodeString()
            contactDeviceUids = list[2].decodeUidArray()
            keycloakServerUrl = list[3].decodeString()
        }

        constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            keycloakServerUrl: String
        ) : super(
            CHECKING_FOR_REVOCATION_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.keycloakServerUrl = keycloakServerUrl
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactDeviceUids!!),
                    Encoded.of(keycloakServerUrl),
                )
            )
        }
    }


    class FinishedProtocolState : ConcreteProtocolState {
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
            DEVICE_DISCOVERY_DONE_MESSAGE_ID -> return DeviceDiscoveryDoneMessage::class.java
            PROPAGATE_CONTACT_ADDITION_TO_OTHER_DEVICES_MESSAGE_ID -> return PropagateContactAdditionToOtherDevicesMessage::class.java
            INVITE_KEYCLOAK_CONTACT_MESSAGE_ID -> return InviteKeycloakContactMessage::class.java
            CHECK_FOR_REVOCATION_SERVER_QUERY_MESSAGE_ID -> return CheckForRevocationServerQueryMessage::class.java
            CONFIRMATION_MESSAGE_ID -> return ConfirmationMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val signedContactDetails: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            signedContactDetails: String
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.signedContactDetails = signedContactDetails
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signedContactDetails = receivedMessage.inputs[1].decodeString()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(signedContactDetails)
            )
            }
    }

    class DeviceDiscoveryDoneMessage : ConcreteProtocolMessage {
        internal val childToParentProtocolMessageInputs: ChildToParentProtocolMessageInputs

        @Suppress("unused")
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            childToParentProtocolMessageInputs: ChildToParentProtocolMessageInputs
        ) : super(coreProtocolMessage!!) {
            this.childToParentProtocolMessageInputs = childToParentProtocolMessageInputs
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            childToParentProtocolMessageInputs =
                ChildToParentProtocolMessageInputs(receivedMessage.inputs)
        }

        override val protocolMessageId: Int = DEVICE_DISCOVERY_DONE_MESSAGE_ID

        // not used for this type of message
        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()

        val deviceUidsReceivedState: DeviceUidsReceivedState?
            get() {
                try {
                    return DeviceUidsReceivedState(childToParentProtocolMessageInputs.childProtocolEncodedState!!)
                } catch (_: Exception) {
                    return null
                }
            }
    }


    class PropagateContactAdditionToOtherDevicesMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val keycloakServerUrl: String
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val trustTimestamp: Long

        @Suppress("unused")
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            keycloakServerUrl: String,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            trustTimestamp: Long
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.keycloakServerUrl = keycloakServerUrl
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.trustTimestamp = trustTimestamp
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 5) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.keycloakServerUrl = receivedMessage.inputs[1].decodeString()
            this.contactSerializedDetails = receivedMessage.inputs[2].decodeString()
            this.contactDeviceUids = receivedMessage.inputs[3].decodeUidArray()
            this.trustTimestamp = receivedMessage.inputs[4].decodeLong()
        }

        override val protocolMessageId: Int = PROPAGATE_CONTACT_ADDITION_TO_OTHER_DEVICES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(keycloakServerUrl),
                Encoded.of(contactSerializedDetails),
                Encoded.of(contactDeviceUids!!),
                Encoded.of(trustTimestamp),
            )
            }
    }


    class InviteKeycloakContactMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val signedContactDetails: String // this is a JWT
        internal val contactDeviceUids: Array<UID?>?
        internal val keycloakServerUrl: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            ownedIdentity: Identity,
            signedOwnedDetails: String,
            ownedDeviceUids: Array<UID?>,
            keycloakServerUrl: String
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = ownedIdentity
            this.signedContactDetails = signedOwnedDetails
            this.contactDeviceUids = ownedDeviceUids
            this.keycloakServerUrl = keycloakServerUrl
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signedContactDetails = receivedMessage.inputs[1].decodeString()
            this.contactDeviceUids = receivedMessage.inputs[2].decodeUidArray()
            this.keycloakServerUrl = receivedMessage.inputs[3].decodeString()
        }

        override val protocolMessageId: Int = INVITE_KEYCLOAK_CONTACT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(signedContactDetails),
                Encoded.of(contactDeviceUids!!),
                Encoded.of(keycloakServerUrl),
            )
            }
    }

    class CheckForRevocationServerQueryMessage : ConcreteProtocolMessage {
        internal val userNotRevoked: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            userNotRevoked = false
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
            this.userNotRevoked = receivedMessage.encodedResponse!!.decodeBoolean()
        }

        override val protocolMessageId: Int = CHECK_FOR_REVOCATION_SERVER_QUERY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class ConfirmationMessage : ConcreteProtocolMessage {
        internal val accepted: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?, accepted: Boolean) : super(
            coreProtocolMessage!!
        ) {
            this.accepted = accepted
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.accepted = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = CONFIRMATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(accepted),
            )
            }
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                VerifyContactAndStartDeviceDiscoveryStep::class.java,
                ProcessPropagatedContactAdditionStep::class.java,
                ProcessReceivedKeycloakInviteStep::class.java
            )

            WAITING_FOR_DEVICE_DISCOVERY_STATED_ID -> return arrayOf<Class<*>>(
                AddContactAndSendRequestStep::class.java
            )

            WAITING_FOR_CONFIRMATION_STATE_ID -> return arrayOf<Class<*>>(ProcessConfirmationStep::class.java)
            CHECKING_FOR_REVOCATION_STATE_ID -> return arrayOf<Class<*>>(
                AddContactAndSendConfirmationStep::class.java
            )

            FINISHED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class VerifyContactAndStartDeviceDiscoveryStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            /**////// */
            // first verify the contact signature
            /**////// */
            val keycloakServerUrl =
                protocolManagerSession.identityDelegate!!.getOwnedIdentityKeycloakServerUrl(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            val ownedIdentityDetailsWithVersionAndPhoto =
                protocolManagerSession.identityDelegate.getOwnedIdentityPublishedDetails(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            val ownedIdentityDetails = ownedIdentityDetailsWithVersionAndPhoto!!.identityDetails
            if (keycloakServerUrl == null || ownedIdentityDetails
                    ?.getSignedUserDetails() == null
            ) {
                return FinishedProtocolState()
            }

            val ownUserDetails =
                protocolManagerSession.identityDelegate.verifyKeycloakIdentitySignature(
                    protocolManagerSession.session,
                    ownedIdentity,
                    ownedIdentityDetails.getSignedUserDetails()
                )
            val contactUserDetails =
                protocolManagerSession.identityDelegate.verifyKeycloakIdentitySignature(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.signedContactDetails
                )
            if (ownUserDetails == null || contactUserDetails == null) {
                return FinishedProtocolState()
            }

            val contactSerializedDetails: String
            try {
                val contactDetails =
                    contactUserDetails.getIdentityDetails(receivedMessage.signedContactDetails)
                contactSerializedDetails =
                    protocol.jsonObjectMapper.writeValueAsString(contactDetails)
            } catch (_: Exception) {
                return FinishedProtocolState()
            }


            /**////// */
            // signatures are valid --> launch a deviceDiscovery before adding the contact
            /**////// */
            val childProtocolInstanceUid = UID(prng)
            LinkBetweenProtocolInstances.create(
                protocolManagerSession,
                childProtocolInstanceUid,
                ownedIdentity,
                DeviceDiscoveryChildProtocol.DEVICE_UIDS_RECEIVED_STATE_ID,
                protocolInstanceUid,
                protocolId,
                DEVICE_DISCOVERY_DONE_MESSAGE_ID
            )
            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                ConcreteProtocol.DEVICE_DISCOVERY_CHILD_PROTOCOL_ID,
                childProtocolInstanceUid
            )
            val messageToSend: ChannelMessageToSend? = DeviceDiscoveryChildProtocol.InitialMessage(
                coreProtocolMessage,
                receivedMessage.contactIdentity
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return WaitingForDeviceDiscoveryState(
                receivedMessage.contactIdentity,
                contactSerializedDetails,
                keycloakServerUrl,
                ownedIdentityDetails.getSignedUserDetails()!!
            )
        }
    }


    class AddContactAndSendRequestStep(
        internal val startState: WaitingForDeviceDiscoveryState,
        internal val receivedMessage: DeviceDiscoveryDoneMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val deviceUidsReceivedState =
                receivedMessage.deviceUidsReceivedState


            /**/////// */
            // Abort protocol if deviceDiscovery failed...
            /**/////// */
            if (deviceUidsReceivedState!!.deviceUidsAndPreKeys.size == 0 && deviceUidsReceivedState.serverTimestamp == 0L) {
                return FinishedProtocolState()
            }

            val contactDeviceUidList: MutableList<UID?> = ArrayList<UID?>()


            /**/////// */
            // actually create the contact
            /**/////// */
            val contactCreated: Boolean
            val trustTimestamp = System.currentTimeMillis()
            if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity
                )
            ) {
                contactCreated = true
                // create contact
                protocolManagerSession.identityDelegate.addContactIdentity(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    startState.contactSerializedDetails,
                    ownedIdentity,
                    createKeycloakTrustOrigin(trustTimestamp, startState.keycloakServerUrl),
                    true
                )

                // set recently online
                protocolManagerSession.identityDelegate.setContactRecentlyOnline(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    deviceUidsReceivedState.isRecentlyOnline
                )

                // handle devices and preKeys
                for (deviceUidAndPreKey in deviceUidsReceivedState.deviceUidsAndPreKeys) {
                    val encodedDeviceUid = deviceUidAndPreKey.get(DictionaryKey("uid"))
                    val encodedSignedPreKey = deviceUidAndPreKey.get(DictionaryKey("prk"))
                    if (encodedDeviceUid != null) {
                        val deviceUid = encodedDeviceUid.decodeUid()
                        contactDeviceUidList.add(deviceUid)
                        val preKeyBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
                            encodedSignedPreKey!!,
                            startState.contactIdentity,
                            deviceUid,
                            deviceUidsReceivedState.serverTimestamp
                        )
                        protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            startState.contactIdentity,
                            deviceUid,
                            preKeyBlob,
                            false
                        )
                    }
                }
            } else {
                contactCreated = false
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    createKeycloakTrustOrigin(trustTimestamp, startState.keycloakServerUrl),
                    true
                )

                // set recently online
                protocolManagerSession.identityDelegate.setContactRecentlyOnline(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    deviceUidsReceivedState.isRecentlyOnline
                )

                // no need to add devices, they should be in sync already, but still build the list of contact deviceUid
                for (deviceUidAndPreKey in deviceUidsReceivedState.deviceUidsAndPreKeys) {
                    val encodedDeviceUid = deviceUidAndPreKey.get(DictionaryKey("uid"))
                    if (encodedDeviceUid != null) {
                        contactDeviceUidList.add(encodedDeviceUid.decodeUid())
                    }
                }
            }

            val contactDeviceUids = contactDeviceUidList.toTypedArray<UID?>()

            /**////// */
            // propagate the message to other known devices
            /**////// */
            run {
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
                            PropagateContactAdditionToOtherDevicesMessage(
                                coreProtocolMessage,
                                startState.contactIdentity,
                                startState.keycloakServerUrl,
                                startState.contactSerializedDetails,
                                contactDeviceUids,
                                trustTimestamp
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


            /**////// */
            // send an "invitation" to all contact devices
            /**////// */
            run {
                val ownedDeviceUids =
                    protocolManagerSession.identityDelegate.getDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        contactDeviceUids
                    )
                )
                val messageToSend: ChannelMessageToSend? = InviteKeycloakContactMessage(
                    coreProtocolMessage,
                    ownedIdentity,
                    startState.signedOwnedDetails,
                    ownedDeviceUids!!,
                    startState.keycloakServerUrl
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            if (contactCreated) {
                return WaitingForConfirmationState(
                    startState.contactIdentity,
                    startState.keycloakServerUrl
                )
            } else {
                return FinishedProtocolState()
            }
        }
    }


    class ProcessPropagatedContactAdditionStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateContactAdditionToOtherDevicesMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.contactIdentity
                )
            ) {
                protocolManagerSession.identityDelegate.addContactIdentity(
                    protocolManagerSession.session,
                    receivedMessage.contactIdentity,
                    receivedMessage.contactSerializedDetails,
                    ownedIdentity,
                    createKeycloakTrustOrigin(
                        receivedMessage.trustTimestamp,
                        receivedMessage.keycloakServerUrl
                    ),
                    true
                )
            } else {
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    receivedMessage.contactIdentity,
                    ownedIdentity,
                    createKeycloakTrustOrigin(
                        receivedMessage.trustTimestamp,
                        receivedMessage.keycloakServerUrl
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
                        receivedMessage.contactIdentity,
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
                    receivedMessage.contactIdentity
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinishedProtocolState()
        }
    }


    class ProcessReceivedKeycloakInviteStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InviteKeycloakContactMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            /**///// */
            // verify the received contact signature
            /**///// */
            val contactUserDetails =
                protocolManagerSession.identityDelegate!!.verifyKeycloakIdentitySignature(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.signedContactDetails
                )

            if (contactUserDetails == null) {
                // respond "rejected"
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity,
                        receivedMessage.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? = ConfirmationMessage(
                    coreProtocolMessage,
                    false
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return FinishedProtocolState()
            }


            val contactSerializedDetails: String
            try {
                val contactDetails =
                    contactUserDetails.getIdentityDetails(receivedMessage.signedContactDetails)
                contactSerializedDetails =
                    protocol.jsonObjectMapper.writeValueAsString(contactDetails)
            } catch (_: Exception) {
                // respond "rejected"
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity,
                        receivedMessage.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? = ConfirmationMessage(
                    coreProtocolMessage,
                    false
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return FinishedProtocolState()
            }

            /**///// */
            // perform the server query to check for revoked identity
            /**//// */
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    CheckKeycloakRevocationQuery(
                        receivedMessage.keycloakServerUrl,
                        receivedMessage.signedContactDetails
                    )
                )
            )
            val messageToSend: ChannelMessageToSend? =
                CheckForRevocationServerQueryMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )


            return CheckingForRevocationState(
                receivedMessage.contactIdentity,
                contactSerializedDetails,
                receivedMessage.contactDeviceUids!!,
                receivedMessage.keycloakServerUrl
            )
        }
    }

    class AddContactAndSendConfirmationStep(
        internal val startState: CheckingForRevocationState,
        internal val receivedMessage: CheckForRevocationServerQueryMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (!receivedMessage.userNotRevoked) {
                // respond "rejected"
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        startState.contactDeviceUids
                    )
                )
                val messageToSend: ChannelMessageToSend? = ConfirmationMessage(
                    coreProtocolMessage,
                    false
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return FinishedProtocolState()
            }

            /**/////// */
            // add the contact and devices
            /**/////// */
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
                    createKeycloakTrustOrigin(
                        System.currentTimeMillis(), startState.keycloakServerUrl
                    ),
                    true
                )
            } else {
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    createKeycloakTrustOrigin(
                        System.currentTimeMillis(), startState.keycloakServerUrl
                    ),
                    true
                )
            }

            var triggerDeviceDiscovery = false
            for (contactDeviceUid in startState.contactDeviceUids!!) {
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


            /**/////// */
            // send confirmation message
            /**/////// */
            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createAsymmetricChannelInfo(
                    startState.contactIdentity,
                    ownedIdentity,
                    startState.contactDeviceUids
                )
            )
            val messageToSend: ChannelMessageToSend? = ConfirmationMessage(
                coreProtocolMessage,
                true
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return FinishedProtocolState()
        }
    }


    class ProcessConfirmationStep(
        internal val startState: WaitingForConfirmationState,
        internal val receivedMessage: ConfirmationMessage,
        protocol: KeycloakContactAdditionProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            /**/////// */
            // if rejected --> delete the contact
            // if accepted --> everything is fine, do nothing
            /**/////// */
            if (!receivedMessage.accepted) {
                // check all the contact trust origins --> if one is not the keycloak current addition, do nothing
                @Suppress("UNCHECKED_CAST")
                val trustOrigins: Array<TrustOrigin>? =
                    protocolManagerSession.identityDelegate!!.getTrustOriginsOfContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.contactIdentity
                    ) as Array<TrustOrigin>?
                for (trustOrigin in trustOrigins!!) {
                    if (trustOrigin.getType() != TrustOrigin.TYPE.KEYCLOAK || trustOrigin.getKeycloakServer() != startState.keycloakServerUrl) {
                        return FinishedProtocolState()
                    }
                }
                // the contact is only trusted through the keycloakServer which he just rejected --> delete the contact
                protocolManagerSession.identityDelegate.deleteContactIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.contactIdentity,
                    false
                )
            }

            return FinishedProtocolState()
        }
    } // endregion


    companion object {
        // region States
        const val WAITING_FOR_DEVICE_DISCOVERY_STATED_ID: Int = 1
        const val WAITING_FOR_CONFIRMATION_STATE_ID: Int = 2
        const val CHECKING_FOR_REVOCATION_STATE_ID: Int = 3
        const val FINISHED_STATE_ID: Int = 4

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val DEVICE_DISCOVERY_DONE_MESSAGE_ID: Int = 1
        const val PROPAGATE_CONTACT_ADDITION_TO_OTHER_DEVICES_MESSAGE_ID: Int = 2
        const val INVITE_KEYCLOAK_CONTACT_MESSAGE_ID: Int = 3
        const val CHECK_FOR_REVOCATION_SERVER_QUERY_MESSAGE_ID: Int = 4
        const val CONFIRMATION_MESSAGE_ID: Int = 5
    }
}
