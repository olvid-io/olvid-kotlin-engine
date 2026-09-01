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
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createObliviousChannelOrPreKeyInfo
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.OneToOneContactInvitationProtocol.InitiateOneToOneStatusSyncWithAllContactsMessage

class DeviceCapabilitiesDiscoveryProtocol(
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
    override val protocolId: Int = ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            FINISHED_STATE_ID -> return FinishedProtocolState::class.java
            else -> return null
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


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_FOR_ADDING_OWN_CAPABILITIES_MESSAGE_ID -> return InitialForAddingOwnCapabilitiesMessage::class.java
            INITIAL_SINGLE_CONTACT_DEVICE_MESSAGE_ID -> return InitialSingleContactDeviceMessage::class.java
            INITIAL_SINGLE_OWNED_DEVICE_MESSAGE_ID -> return InitialSingleOwnedDeviceMessage::class.java
            OWN_CAPABILITIES_TO_CONTACT_MESSAGE_ID -> return OwnCapabilitiesToContactMessage::class.java
            OWN_CAPABILITIES_TO_SELF_MESSAGE_ID -> return OwnCapabilitiesToSelfMessage::class.java
            else -> return null
        }
    }


    @Suppress("unused")
    class InitialForAddingOwnCapabilitiesMessage : ConcreteProtocolMessage {
        internal val newOwnCapabilities: MutableList<ObvCapability>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            newOwnCapabilities: MutableList<ObvCapability>
        ) : super(coreProtocolMessage!!) {
            this.newOwnCapabilities = newOwnCapabilities
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            val rawCapabilities = receivedMessage.inputs[0].decodeStringArray()
            newOwnCapabilities = ArrayList()
            for (rawCapability in rawCapabilities) {
                val capability = ObvCapability.fromString(rawCapability)
                if (capability != null) {
                    newOwnCapabilities.add(capability)
                } else {
                    throw Exception("Unknown capability: " + rawCapability)
                }
            }
        }

        override val protocolMessageId: Int = INITIAL_FOR_ADDING_OWN_CAPABILITIES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf(
                    Encoded.of(ObvCapability.capabilityListToStringArray(newOwnCapabilities)),
                )
            }
    }


    @Suppress("unused")
    class InitialSingleContactDeviceMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactDeviceUid: UID
        internal val isResponse: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactDeviceUid: UID,
            isResponse: Boolean
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactDeviceUid = contactDeviceUid
            this.isResponse = isResponse
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactDeviceUid = receivedMessage.inputs[1].decodeUid()
            this.isResponse = receivedMessage.inputs[2].decodeBoolean()
        }

        override val protocolMessageId: Int = INITIAL_SINGLE_CONTACT_DEVICE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactDeviceUid),
                Encoded.of(isResponse),
            )
            }
    }


    @Suppress("unused")
    class InitialSingleOwnedDeviceMessage : ConcreteProtocolMessage {
        internal val otherOwnedDeviceUid: UID
        internal val isResponse: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            otherOwnedDeviceUid: UID,
            isResponse: Boolean
        ) : super(coreProtocolMessage!!) {
            this.otherOwnedDeviceUid = otherOwnedDeviceUid
            this.isResponse = isResponse
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.otherOwnedDeviceUid = receivedMessage.inputs[0].decodeUid()
            this.isResponse = receivedMessage.inputs[1].decodeBoolean()
        }

        override val protocolMessageId: Int = INITIAL_SINGLE_OWNED_DEVICE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(otherOwnedDeviceUid),
                Encoded.of(isResponse),
            )
            }
    }


    @Suppress("unused")
    class OwnCapabilitiesToContactMessage : ConcreteProtocolMessage {
        internal val rawContactDeviceCapabilities: Array<String>
        internal val isResponse: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            rawContactDeviceCapabilities: Array<String>,
            isResponse: Boolean
        ) : super(coreProtocolMessage!!) {
            this.rawContactDeviceCapabilities = rawContactDeviceCapabilities
            this.isResponse = isResponse
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.rawContactDeviceCapabilities = receivedMessage.inputs[0].decodeStringArray()
            this.isResponse = receivedMessage.inputs[1].decodeBoolean()
        }

        override val protocolMessageId: Int = OWN_CAPABILITIES_TO_CONTACT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(rawContactDeviceCapabilities),
                Encoded.of(isResponse),
            )
            }
    }


    @Suppress("unused")
    class OwnCapabilitiesToSelfMessage : ConcreteProtocolMessage {
        internal val rawOtherOwnedDeviceCapabilities: Array<String>
        internal val isResponse: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            rawOtherOwnedDeviceCapabilities: Array<String>,
            isResponse: Boolean
        ) : super(coreProtocolMessage!!) {
            this.rawOtherOwnedDeviceCapabilities = rawOtherOwnedDeviceCapabilities
            this.isResponse = isResponse
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.rawOtherOwnedDeviceCapabilities =
                receivedMessage.inputs[0].decodeStringArray()
            this.isResponse = receivedMessage.inputs[1].decodeBoolean()
        }

        override val protocolMessageId: Int = OWN_CAPABILITIES_TO_SELF_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(rawOtherOwnedDeviceCapabilities),
                Encoded.of(isResponse),
            )
            }
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                AddOwnCapabilitiesAndSendThemToAllContactsAndOwnedDevicesStep::class.java,
                SendOwnCapabilitiesToContactDeviceStep::class.java,
                SendOwnCapabilitiesToOtherOwnedDeviceStep::class.java,
                ProcessReceivedContactDeviceCapabilitiesStep::class.java,
                ProcessReceivedOwnedDeviceCapabilitiesStep::class.java,
            )

            FINISHED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class AddOwnCapabilitiesAndSendThemToAllContactsAndOwnedDevicesStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialForAddingOwnCapabilitiesMessage,
        protocol: DeviceCapabilitiesDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val gainedOneToOneCapability: Boolean
            run {
                // check whether the current device has different capabilities and update them
                val currentCapabilities =
                    protocolManagerSession.identityDelegate!!.getCurrentDevicePublishedCapabilities(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                // convert to HashSet for comparison
                val currentSet = HashSet(currentCapabilities)
                val newSet = HashSet(receivedMessage.newOwnCapabilities)
                if (currentSet == newSet) {
                    // nothing changed, nothing to do:)
                    return FinishedProtocolState()
                }

                gainedOneToOneCapability =
                    newSet.contains(ObvCapability.ONE_TO_ONE_CONTACTS) && !currentSet.contains(
                        ObvCapability.ONE_TO_ONE_CONTACTS
                    )

                // something changed --> update the device
                protocolManagerSession.identityDelegate.setCurrentDevicePublishedCapabilities(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.newOwnCapabilities
                )
            }

            run {
                // if we just gained the oneToOne capability, notify all contacts of their status
                if (gainedOneToOneCapability) {
                    val childProtocolInstanceUid = UID(prng)
                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.ONE_TO_ONE_CONTACT_INVITATION_PROTOCOL_ID,
                        childProtocolInstanceUid
                    )
                    val messageToSend: ChannelMessageToSend? =
                        InitiateOneToOneStatusSyncWithAllContactsMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // notify all contacts
                val contactIdentities =
                    protocolManagerSession.identityDelegate!!.getContactsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (!contactIdentities.isNullOrEmpty()) {
                    val sendChannelInfos =
                        SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            contactIdentities,
                            ownedIdentity
                        )
                    for (sendChannelInfo in sendChannelInfos!!) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                            val messageToSend: ChannelMessageToSend? =
                                OwnCapabilitiesToContactMessage(
                                    coreProtocolMessage,
                                    ObvCapability.capabilityListToStringArray(receivedMessage.newOwnCapabilities),
                                    false
                                ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        } catch (_: Exception) {
                            Logger.d("One contact with no channel during DeviceCapabilitiesDiscoveryProtocol.AddOwnCapabilitiesAndSendThemToAllContactsAndOwnedDevicesStep")
                        }
                    }
                }
            }

            run {
                // notify other owned devices
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
                        val messageToSend: ChannelMessageToSend? = OwnCapabilitiesToSelfMessage(
                            coreProtocolMessage,
                            ObvCapability.capabilityListToStringArray(receivedMessage.newOwnCapabilities),
                            false
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

            return FinishedProtocolState()
        }
    }


    class SendOwnCapabilitiesToContactDeviceStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialSingleContactDeviceMessage,
        protocol: DeviceCapabilitiesDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val currentCapabilities =
                protocolManagerSession.identityDelegate!!.getCurrentDevicePublishedCapabilities(
                    protocolManagerSession.session,
                    ownedIdentity
                )


            val coreProtocolMessage = buildCoreProtocolMessage(
                createObliviousChannelOrPreKeyInfo(
                    receivedMessage.contactIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(receivedMessage.contactDeviceUid),
                    true
                )
            )
            val messageToSend: ChannelMessageToSend? = OwnCapabilitiesToContactMessage(
                coreProtocolMessage,
                ObvCapability.capabilityListToStringArray(currentCapabilities),
                receivedMessage.isResponse
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return FinishedProtocolState()
        }
    }


    class SendOwnCapabilitiesToOtherOwnedDeviceStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialSingleOwnedDeviceMessage,
        protocol: DeviceCapabilitiesDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val currentCapabilities =
                protocolManagerSession.identityDelegate!!.getCurrentDevicePublishedCapabilities(
                    protocolManagerSession.session,
                    ownedIdentity
                )


            val coreProtocolMessage = buildCoreProtocolMessage(
                createObliviousChannelOrPreKeyInfo(
                    ownedIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(receivedMessage.otherOwnedDeviceUid),
                    true
                )
            )
            val messageToSend: ChannelMessageToSend? = OwnCapabilitiesToSelfMessage(
                coreProtocolMessage,
                ObvCapability.capabilityListToStringArray(currentCapabilities),
                receivedMessage.isResponse
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return FinishedProtocolState()
        }
    }


    class ProcessReceivedContactDeviceCapabilitiesStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: OwnCapabilitiesToContactMessage,
        protocol: DeviceCapabilitiesDiscoveryProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val initialContactDeviceCapabilities =
                protocolManagerSession.identityDelegate!!.getContactDeviceCapabilities(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                    receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()
                )


            if (!receivedMessage.isResponse && initialContactDeviceCapabilities!!.size == 0) {
                // this is the first time this contact sends us some capabilities --> we send them our own capabilities

                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialSingleContactDeviceMessage(
                    coreProtocolMessage,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!,
                    receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()!!,
                    true
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            protocolManagerSession.identityDelegate.setContactDeviceCapabilities(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid(),
                receivedMessage.rawContactDeviceCapabilities
            )

            return FinishedProtocolState()
        }
    }


    class ProcessReceivedOwnedDeviceCapabilitiesStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: OwnCapabilitiesToSelfMessage,
        protocol: DeviceCapabilitiesDiscoveryProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val initialOtherOwnedDeviceCapabilities =
                protocolManagerSession.identityDelegate!!.getOtherOwnedDeviceCapabilities(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()
                )


            if (!receivedMessage.isResponse && initialOtherOwnedDeviceCapabilities!!.isEmpty()) {
                // this is the first time this other owned device sends us some capabilities --> we send it our own capabilities

                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialSingleOwnedDeviceMessage(
                    coreProtocolMessage,
                    receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()!!,
                    true
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            protocolManagerSession.identityDelegate.setOtherOwnedDeviceCapabilities(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid(),
                receivedMessage.rawOtherOwnedDeviceCapabilities
            )

            return FinishedProtocolState()
        }
    } // endregion

    companion object {
        // region States
        const val FINISHED_STATE_ID: Int = 1

        // endregion
        // region Messages
        const val INITIAL_FOR_ADDING_OWN_CAPABILITIES_MESSAGE_ID: Int = 0
        const val INITIAL_SINGLE_CONTACT_DEVICE_MESSAGE_ID: Int = 1
        const val INITIAL_SINGLE_OWNED_DEVICE_MESSAGE_ID: Int = 2
        const val OWN_CAPABILITIES_TO_CONTACT_MESSAGE_ID: Int = 3
        const val OWN_CAPABILITIES_TO_SELF_MESSAGE_ID: Int = 4
    }
}
