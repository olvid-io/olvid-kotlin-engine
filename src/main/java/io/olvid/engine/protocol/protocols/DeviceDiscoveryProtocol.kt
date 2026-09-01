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
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
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

class DeviceDiscoveryProtocol(
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
    override val protocolId: Int = ConcreteProtocol.DEVICE_DISCOVERY_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(CANCELLED_STATE_ID, CHILD_PROTOCOL_OUTPUT_PROCESSED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            WAITING_FOR_CHILD_PROTOCOL_STATE_ID -> return WaitingForChildProtocolState::class.java
            CHILD_PROTOCOL_OUTPUT_PROCESSED_STATE_ID -> return ChildProtocolStateProcessedState::class.java
            CANCELLED_STATE_ID -> return CancelledState::class.java
            else -> return null
        }
    }

    class WaitingForChildProtocolState : ConcreteProtocolState {
        internal val contactIdentity: Identity

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_CHILD_PROTOCOL_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
        }

        constructor(contactIdentity: Identity) : super(WAITING_FOR_CHILD_PROTOCOL_STATE_ID) {
            this.contactIdentity = contactIdentity
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity)
                )
            )
        }
    }

    class ChildProtocolStateProcessedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CANCELLED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(CHILD_PROTOCOL_OUTPUT_PROCESSED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class CancelledState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CANCELLED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(CANCELLED_STATE_ID)

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
            CHILD_PROTOCOL_REACHED_EXPECTED_STATE_MESSAGE_ID -> return ChildProtocolReachedExpectedStateMessage::class.java
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

    class ChildProtocolReachedExpectedStateMessage : ConcreteProtocolMessage {
        internal val childToParentProtocolMessageInputs: ChildToParentProtocolMessageInputs

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            childToParentProtocolMessageInputs: ChildToParentProtocolMessageInputs
        ) : super(coreProtocolMessage!!) {
            this.childToParentProtocolMessageInputs = childToParentProtocolMessageInputs
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            childToParentProtocolMessageInputs =
                ChildToParentProtocolMessageInputs(receivedMessage.inputs)
        }

        override val protocolMessageId: Int = CHILD_PROTOCOL_REACHED_EXPECTED_STATE_MESSAGE_ID

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


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                StartChildProtocolStep::class.java
            )

            WAITING_FOR_CHILD_PROTOCOL_STATE_ID -> return arrayOf<Class<*>>(
                ProcessChildProtocolStateStep::class.java
            )

            CHILD_PROTOCOL_OUTPUT_PROCESSED_STATE_ID, CANCELLED_STATE_ID -> return arrayOf<Class<*>>()

            else -> return arrayOf<Class<*>>()
        }
    }

    class StartChildProtocolStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: DeviceDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (!protocolManagerSession.identityDelegate!!.isIdentityAnActiveContactOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.contactIdentity
                )
            ) {
                Logger.i("Trying to run a DeviceDiscoveryProtocol with an unknown or revoked contactIdentity")
                return CancelledState()
            }

            val childProtocolInstanceUid = UID(prng)
            LinkBetweenProtocolInstances.create(
                protocolManagerSession,
                childProtocolInstanceUid,
                ownedIdentity,
                DeviceDiscoveryChildProtocol.DEVICE_UIDS_RECEIVED_STATE_ID,
                protocolInstanceUid,
                protocolId,
                CHILD_PROTOCOL_REACHED_EXPECTED_STATE_MESSAGE_ID
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

            return WaitingForChildProtocolState(receivedMessage.contactIdentity)
        }
    }

    class ProcessChildProtocolStateStep(
        internal val startState: WaitingForChildProtocolState,
        internal val receivedMessage: ChildProtocolReachedExpectedStateMessage,
        protocol: DeviceDiscoveryProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val deviceUidsReceivedState =
                receivedMessage.deviceUidsReceivedState

            val receivedContactIdentity = deviceUidsReceivedState!!.remoteIdentity
            if (!receivedContactIdentity.equals(startState.contactIdentity)) {
                Logger.w("Received UID from another remoteIdentity!")
                return CancelledState()
            }

            if (deviceUidsReceivedState.deviceUidsAndPreKeys.size == 0 && deviceUidsReceivedState.serverTimestamp == 0L) {
                Logger.w("Device discovery query expired.")
                return CancelledState()
            }

            val newContactDevicesAndPreKeys = HashMap<UID?, Encoded?>()
            for (deviceUidAndPreKey in deviceUidsReceivedState.deviceUidsAndPreKeys) {
                try {
                    val encodedDeviceUid = deviceUidAndPreKey.get(DictionaryKey("uid"))
                    val encodedSignedPreKey = deviceUidAndPreKey.get(DictionaryKey("prk"))
                    if (encodedDeviceUid != null) {
                        val deviceUid = encodedDeviceUid.decodeUid()
                        newContactDevicesAndPreKeys.put(deviceUid, encodedSignedPreKey)
                    }
                } catch (e: Exception) {
                    Logger.i("Malformed server response id device discovery")
                    Logger.x(e)
                }
            }

            for (oldUidAndPreKey in protocolManagerSession.identityDelegate!!.getDeviceUidsAndPreKeysOfContactIdentity(
                protocolManagerSession.session,
                ownedIdentity,
                receivedContactIdentity
            )!!) {
                val stillExists = newContactDevicesAndPreKeys.containsKey(oldUidAndPreKey!!.uid)
                val encodedSignedPreKey = newContactDevicesAndPreKeys.remove(oldUidAndPreKey.uid)
                if (stillExists) {
                    // check if the preKey should be updated

                    val newPreKey: PreKeyBlobOnServer?
                    val preKeyChanged: Boolean

                    if (encodedSignedPreKey != null) {
                        // there is a preKey on the server, check if it changed and has a valid signature
                        val preKeyBlob = PreKeyBlobOnServer.verifySignatureAndDecode(
                            encodedSignedPreKey,
                            receivedContactIdentity,
                            oldUidAndPreKey.uid!!,
                            deviceUidsReceivedState.serverTimestamp
                        )
                        if (preKeyBlob != null &&
                            (oldUidAndPreKey.preKey == null || (!preKeyBlob.preKey.keyId!!.equals(
                                oldUidAndPreKey.preKey.keyId
                            ) && oldUidAndPreKey.preKey.expirationTimestamp < preKeyBlob.preKey.expirationTimestamp))
                        ) {
                            newPreKey = preKeyBlob
                            preKeyChanged = true
                        } else {
                            newPreKey = null
                            preKeyChanged = false
                        }
                    } else if (oldUidAndPreKey.preKey != null) {
                        // the preKey was removed!
                        Logger.w("A contact preKey was removed from the server, this should never happen...")
                        newPreKey = null
                        preKeyChanged = true
                    } else {
                        newPreKey = null
                        preKeyChanged = false
                    }

                    if (preKeyChanged) {
                        protocolManagerSession.identityDelegate.updateContactDevicePreKey(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedContactIdentity,
                            oldUidAndPreKey.uid,
                            newPreKey
                        )
                    }
                } else {
                    // a deviceUid was removed --> delete the channel and the deviceUid
                    protocolManagerSession.channelDelegate!!.deleteObliviousChannelIfItExists(
                        protocolManagerSession.session,
                        ownedIdentity,
                        oldUidAndPreKey.uid,
                        receivedContactIdentity
                    )
                    protocolManagerSession.identityDelegate.removeDeviceForContactIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedContactIdentity,
                        oldUidAndPreKey.uid
                    )
                }
            }

            for (entry in newContactDevicesAndPreKeys.entries) {
                // a new deviceUid was found --> add it, this will trigger the channel creation
                val preKeyBlob =
                    if (entry.value == null) null else PreKeyBlobOnServer.verifySignatureAndDecode(
                        entry.value!!,
                        receivedContactIdentity,
                        entry.key!!,
                        deviceUidsReceivedState.serverTimestamp
                    )
                protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedContactIdentity,
                    entry.key,
                    preKeyBlob,
                    false
                )
            }

            // update the recently online status of the contact
            protocolManagerSession.identityDelegate.setContactRecentlyOnline(
                protocolManagerSession.session,
                ownedIdentity,
                receivedContactIdentity,
                deviceUidsReceivedState.isRecentlyOnline
            )

            if (deviceUidsReceivedState.serverTimestamp != 0L) {
                // delete expired pre keys (for the contact's server)
                protocolManagerSession.identityDelegate.expireContactAndOwnedPreKeys(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedContactIdentity.server,
                    deviceUidsReceivedState.serverTimestamp
                )
            }

            return ChildProtocolStateProcessedState()
        }
    } // endregion

    companion object {
        // region States
        const val WAITING_FOR_CHILD_PROTOCOL_STATE_ID: Int = 1
        const val CHILD_PROTOCOL_OUTPUT_PROCESSED_STATE_ID: Int = 2
        const val CANCELLED_STATE_ID: Int = 3

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val CHILD_PROTOCOL_REACHED_EXPECTED_STATE_MESSAGE_ID: Int = 1
    }
}
