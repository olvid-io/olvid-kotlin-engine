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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementDeactivateDeviceQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementSetNicknameQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementSetUnexpiringDeviceQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvDeviceManagementRequest
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.ContactManagementProtocol.PerformContactDeviceDiscoveryMessage
import java.nio.charset.StandardCharsets

class OwnedDeviceManagementProtocol(
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
    override val protocolId: Int = ConcreteProtocol.OWNED_DEVICE_MANAGEMENT_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(RESPONSE_PROCESSED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            REQUEST_SENT_STATE_ID -> return RequestSentState::class.java
            RESPONSE_PROCESSED_STATE_ID -> return ResponseProcessedState::class.java
            else -> return null
        }
    }

    class RequestSentState : ConcreteProtocolState {
        @JvmField val deviceManagementRequest: ObvDeviceManagementRequest

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(REQUEST_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.deviceManagementRequest = ObvDeviceManagementRequest.of(list[0])
        }

        constructor(deviceManagementRequest: ObvDeviceManagementRequest) : super(
            REQUEST_SENT_STATE_ID
        ) {
            this.deviceManagementRequest = deviceManagementRequest
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    deviceManagementRequest.encode()!!,
                )
            )
        }
    }

    class ResponseProcessedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(RESPONSE_PROCESSED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        constructor() : super(RESPONSE_PROCESSED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SERVER_QUERY_MESSAGE_ID -> return ServerQueryMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        @JvmField val deviceManagementRequest: ObvDeviceManagementRequest

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            deviceManagementRequest: ObvDeviceManagementRequest
        ) : super(coreProtocolMessage!!) {
            this.deviceManagementRequest = deviceManagementRequest
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            deviceManagementRequest = ObvDeviceManagementRequest.of(receivedMessage.inputs[0])
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                deviceManagementRequest.encode()!!,
            )
            }
    }


    class ServerQueryMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!))

        override val protocolMessageId: Int = SERVER_QUERY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                SendRequestStep::class.java
            )

            REQUEST_SENT_STATE_ID -> return arrayOf<Class<*>>(ProcessResponseStateStep::class.java)
            RESPONSE_PROCESSED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class SendRequestStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: OwnedDeviceManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val serverQueryType: ServerQuery.Type?
            when (receivedMessage.deviceManagementRequest.action) {
                ObvDeviceManagementRequest.ACTION_SET_NICKNAME -> {
                    // pad and encrypt the nickname
                    val encodedDeviceName = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(
                                receivedMessage.deviceManagementRequest.nickname!!.toByteArray(
                                    StandardCharsets.UTF_8
                                )
                            )
                        )
                    ).bytes

                    val plaintext = ByteArray(((encodedDeviceName.size - 1) or 127) + 1)
                    System.arraycopy(encodedDeviceName, 0, plaintext, 0, encodedDeviceName.size)

                    val encryptedDeviceName =
                        Suite.getPublicKeyEncryption(ownedIdentity.encryptionPublicKey)!!
                            .encrypt(
                                ownedIdentity.encryptionPublicKey,
                                plaintext,
                                Suite.getDefaultPRNGService(0)
                            )!!

                    val currentDeviceUid =
                        protocolManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )
                    serverQueryType = DeviceManagementSetNicknameQuery(
                        ownedIdentity,
                        receivedMessage.deviceManagementRequest.getDeviceUid()!!,
                        encryptedDeviceName,
                        currentDeviceUid!!.equals(receivedMessage.deviceManagementRequest.getDeviceUid())
                    )
                }

                ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE -> {
                    serverQueryType = DeviceManagementDeactivateDeviceQuery(
                        ownedIdentity,
                        receivedMessage.deviceManagementRequest.getDeviceUid()!!
                    )
                }

                ObvDeviceManagementRequest.ACTION_SET_UNEXPIRING_DEVICE -> {
                    serverQueryType = DeviceManagementSetUnexpiringDeviceQuery(
                        ownedIdentity,
                        receivedMessage.deviceManagementRequest.getDeviceUid()!!
                    )
                }

                else -> {
                    Logger.e("OwnedDeviceManagementProtocol received an invalid ObvDeviceManagementRequest: unknown action")
                    throw Exception()
                }
            }
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    serverQueryType
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ServerQueryMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return RequestSentState(receivedMessage.deviceManagementRequest)
        }
    }


    class ProcessResponseStateStep(
        @field:Suppress("unused") internal val startState: RequestSentState, @field:Suppress(
            "unused"
        ) internal val receivedMessage: ServerQueryMessage?, protocol: OwnedDeviceManagementProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // after a query is processed by the server, start an OwnedDeviceDiscoveryProtocol
                val protocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.OWNED_DEVICE_DISCOVERY_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val message: ChannelMessageToSend? =
                    OwnedDeviceDiscoveryProtocol.InitialMessage(coreProtocolMessage)
                        .generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    message,
                    prng
                )
            }

            // if the user deactivated a device --> notify all contacts that a device discovery is needed
            if (startState.deviceManagementRequest.action == ObvDeviceManagementRequest.ACTION_DEACTIVATE_DEVICE) {
                val sendChannelInfos =
                    SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                        protocolManagerSession.identityDelegate!!.getContactsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )!!, ownedIdentity
                    )
                for (sendChannelInfo in sendChannelInfos!!) {
                    try {
                        val coreProtocolMessage = CoreProtocolMessage(
                            sendChannelInfo,
                            ConcreteProtocol.CONTACT_MANAGEMENT_PROTOCOL_ID,
                            UID(prng)
                        )
                        val message: ChannelMessageToSend? =
                            PerformContactDeviceDiscoveryMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            message,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                        Logger.d("One SendChannelInfo with no channel during OwnedDeviceManagementProtocol.ProcessResponseStateStep")
                    }
                }
            }

            return ResponseProcessedState()
        }
    } // endregion

    companion object {
        // region States
        const val REQUEST_SENT_STATE_ID: Int = 1
        const val RESPONSE_PROCESSED_STATE_ID: Int = 2

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val SERVER_QUERY_MESSAGE_ID: Int = 1
    }
}
