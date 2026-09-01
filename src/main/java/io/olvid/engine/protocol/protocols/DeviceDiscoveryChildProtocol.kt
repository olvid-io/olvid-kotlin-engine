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
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceDiscoveryQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep


class DeviceDiscoveryChildProtocol(
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
    override val protocolId: Int = ConcreteProtocol.DEVICE_DISCOVERY_CHILD_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(DEVICE_UIDS_RECEIVED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            DEVICE_UIDS_RECEIVED_STATE_ID -> return DeviceUidsReceivedState::class.java
            SERVER_REQUEST_SENT_STATE_ID -> return ServerRequestSentState::class.java
            else -> return null
        }
    }

    class DeviceUidsReceivedState : ConcreteProtocolState {
        @JvmField val remoteIdentity: Identity
        @JvmField val isRecentlyOnline: Boolean
        @JvmField val serverTimestamp: Long
        val deviceUidsAndPreKeys: Array<HashMap<DictionaryKey, Encoded>>

        constructor(encodedState: Encoded) : super(DEVICE_UIDS_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size == 2) {
                // backward compatibility with previous encoding
                this.remoteIdentity = list[0].decodeIdentity()
                this.isRecentlyOnline = true
                this.serverTimestamp = 0
                val deviceUids = list[1].decodeUidArray()
                @Suppress("UNCHECKED_CAST")
                this.deviceUidsAndPreKeys = arrayOfNulls<HashMap<DictionaryKey, Encoded>>(deviceUids.size) as Array<HashMap<DictionaryKey, Encoded>>
                for (i in deviceUids.indices) {
                    deviceUidsAndPreKeys[i] = HashMap<DictionaryKey, Encoded>()
                    deviceUidsAndPreKeys[i].put(DictionaryKey("uid"), Encoded.of(deviceUids[i]!!))
                }
            } else if (list.size == 4) {
                this.remoteIdentity = list[0].decodeIdentity()
                this.isRecentlyOnline = list[1].decodeBoolean()
                this.serverTimestamp = list[2].decodeLong()
                this.deviceUidsAndPreKeys = list[3].decodeDictionaryArray()
            } else {
                throw Exception()
            }
        }

        constructor(
            remoteIdentity: Identity,
            recentlyOnline: Boolean,
            serverTimestamp: Long,
            deviceUidsAndPreKeys: Array<HashMap<DictionaryKey, Encoded>>
        ) : super(
            DEVICE_UIDS_RECEIVED_STATE_ID
        ) {
            this.remoteIdentity = remoteIdentity
            this.isRecentlyOnline = recentlyOnline
            this.serverTimestamp = serverTimestamp
            this.deviceUidsAndPreKeys = deviceUidsAndPreKeys
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteIdentity),
                    Encoded.of(this.isRecentlyOnline),
                    Encoded.of(serverTimestamp),
                    Encoded.of(deviceUidsAndPreKeys),
                )
            )
        }
    }

    class ServerRequestSentState : ConcreteProtocolState {
        internal val remoteIdentity: Identity

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(SERVER_REQUEST_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.remoteIdentity = list[0].decodeIdentity()
        }

        constructor(remoteIdentity: Identity) : super(SERVER_REQUEST_SENT_STATE_ID) {
            this.remoteIdentity = remoteIdentity
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteIdentity)
                )
            )
        }
    }


    init {
        mayBeRunAsLinkedChildProtocol = true
    }

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SERVER_QUERY_MESSAGE_ID -> return ServerQueryMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val remoteIdentity: Identity

        constructor(coreProtocolMessage: CoreProtocolMessage?, remoteIdentity: Identity) : super(
            coreProtocolMessage!!
        ) {
            this.remoteIdentity = remoteIdentity
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.remoteIdentity = receivedMessage.inputs[0].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>(Encoded.of(remoteIdentity))
    }

    class ServerQueryMessage : ConcreteProtocolMessage {
        internal val recentlyOnline: Boolean
        internal var decodedServerTimestamp: Long
        internal val deviceUidsAndPreKeys: Array<HashMap<DictionaryKey, Encoded>>?

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            recentlyOnline = false
            decodedServerTimestamp = 0
            deviceUidsAndPreKeys = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            val dict: HashMap<DictionaryKey, Encoded> =
                receivedMessage.encodedResponse.decodeDictionary()
            if (dict.isEmpty()) {
                // request has expired
                recentlyOnline = false
                decodedServerTimestamp = 0
                @Suppress("UNCHECKED_CAST")
                deviceUidsAndPreKeys = arrayOfNulls<HashMap<DictionaryKey, Encoded>>(0) as Array<HashMap<DictionaryKey, Encoded>>
            } else {
                val encodedRecentlyOnline = dict.get(DictionaryKey("ro"))
                recentlyOnline =
                    encodedRecentlyOnline == null || encodedRecentlyOnline.decodeBoolean()
                val encodedServerTimestamp = dict.get(DictionaryKey("st"))
                decodedServerTimestamp =
                    if (encodedServerTimestamp == null) 0 else encodedServerTimestamp.decodeLong()
                val encodedDeviceUidsAndPreKeys = dict.get(DictionaryKey("dev"))
                if (encodedDeviceUidsAndPreKeys == null) {
                    @Suppress("UNCHECKED_CAST")
                    deviceUidsAndPreKeys = arrayOfNulls<HashMap<DictionaryKey, Encoded>>(0) as Array<HashMap<DictionaryKey, Encoded>>
                } else {
                    deviceUidsAndPreKeys = encodedDeviceUidsAndPreKeys.decodeDictionaryArray()
                }
            }
        }

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

            SERVER_REQUEST_SENT_STATE_ID -> return arrayOf<Class<*>>(ProcessDeviceUidsStep::class.java)
            DEVICE_UIDS_RECEIVED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class SendRequestStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: DeviceDiscoveryChildProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ServerRequestSentState {
            val protocolManagerSession = protocolManagerSession!!

            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    DeviceDiscoveryQuery(receivedMessage.remoteIdentity)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ServerQueryMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return ServerRequestSentState(receivedMessage.remoteIdentity)
        }
    }

    class ProcessDeviceUidsStep(
        internal val startState: ServerRequestSentState,
        internal val receivedMessage: ServerQueryMessage,
        protocol: DeviceDiscoveryChildProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            return DeviceUidsReceivedState(
                startState.remoteIdentity,
                receivedMessage.recentlyOnline,
                receivedMessage.decodedServerTimestamp,
                receivedMessage.deviceUidsAndPreKeys!!
            )
        }
    } // endregion

    companion object {
        // region States
        //    public static final int REQUEST_SENT_STATE_ID = 1;
        const val DEVICE_UIDS_RECEIVED_STATE_ID: Int = 2

        //    public static final int DEVICE_UIDS_SENT_STATE_ID = 3;
        const val SERVER_REQUEST_SENT_STATE_ID: Int = 4

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0

        //    public static final int FROM_ALICE_MESSAGE_ID = 1;
        //    public static final int FROM_BOB_MESSAGE_ID = 2;
        const val SERVER_QUERY_MESSAGE_ID: Int = 3
    }
}