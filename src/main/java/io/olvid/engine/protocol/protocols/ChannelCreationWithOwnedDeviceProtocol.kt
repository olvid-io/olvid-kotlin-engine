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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.protocol.databases.ChannelCreationPingSignatureReceived
import io.olvid.engine.protocol.databases.ChannelCreationProtocolInstance
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import io.olvid.engine.protocol.protocols.DeviceCapabilitiesDiscoveryProtocol.InitialSingleOwnedDeviceMessage
import java.sql.SQLException


class ChannelCreationWithOwnedDeviceProtocol(
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
    override val protocolId: Int = ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(CANCELLED_STATE_ID, CHANNEL_CONFIRMED_STATE_ID, PING_SENT_STATE_ID)

    public override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            CANCELLED_STATE_ID -> return CancelledState::class.java
            PING_SENT_STATE_ID -> return PingSentState::class.java
            WAITING_FOR_K1_STATE_ID -> return WaitingForK1State::class.java
            WAITING_FOR_K2_STATE_ID -> return WaitingForK2State::class.java
            WAIT_FOR_FIRST_ACK_STATE_ID -> return WaitForFirstAckState::class.java
            WAIT_FOR_SECOND_ACK_STATE_ID -> return WaitForSecondAckState::class.java
            CHANNEL_CONFIRMED_STATE_ID -> return ChannelConfirmedState::class.java
            else -> return null
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

        internal constructor() : super(CANCELLED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class PingSentState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(PING_SENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(PING_SENT_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class WaitingForK1State : ConcreteProtocolState {
        internal val remoteDeviceUid: UID
        internal val ephemeralPrivateKey: EncryptionPrivateKey?

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_K1_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.remoteDeviceUid = list[0].decodeUid()
            this.ephemeralPrivateKey = list[1].decodePrivateKey() as EncryptionPrivateKey?
        }

        internal constructor(
            remoteDeviceUid: UID,
            ephemeralPrivateKey: EncryptionPrivateKey?
        ) : super(
            WAITING_FOR_K1_STATE_ID
        ) {
            this.remoteDeviceUid = remoteDeviceUid
            this.ephemeralPrivateKey = ephemeralPrivateKey
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteDeviceUid),
                    Encoded.of(ephemeralPrivateKey!!),
                )
            )
        }
    }


    class WaitingForK2State : ConcreteProtocolState {
        internal val remoteDeviceUid: UID
        internal val ephemeralPrivateKey: EncryptionPrivateKey?
        internal val k1: AuthEncKey?

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_K2_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 3) {
                throw Exception()
            }
            this.remoteDeviceUid = list[0].decodeUid()
            this.ephemeralPrivateKey = list[1].decodePrivateKey() as EncryptionPrivateKey?
            this.k1 = list[2].decodeSymmetricKey() as AuthEncKey?
        }

        internal constructor(
            remoteDeviceUid: UID,
            ephemeralPrivateKey: EncryptionPrivateKey?,
            k1: AuthEncKey?
        ) : super(
            WAITING_FOR_K2_STATE_ID
        ) {
            this.remoteDeviceUid = remoteDeviceUid
            this.ephemeralPrivateKey = ephemeralPrivateKey
            this.k1 = k1
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteDeviceUid),
                    Encoded.of(ephemeralPrivateKey!!),
                    Encoded.of(k1!!),
                )
            )
        }
    }


    class WaitForFirstAckState : ConcreteProtocolState {
        internal val remoteDeviceUid: UID

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAIT_FOR_FIRST_ACK_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.remoteDeviceUid = list[0].decodeUid()
        }

        internal constructor(remoteDeviceUid: UID) : super(WAIT_FOR_FIRST_ACK_STATE_ID) {
            this.remoteDeviceUid = remoteDeviceUid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteDeviceUid),
                )
            )
        }
    }

    class WaitForSecondAckState : ConcreteProtocolState {
        internal val remoteDeviceUid: UID

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAIT_FOR_SECOND_ACK_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.remoteDeviceUid = list[0].decodeUid()
        }

        internal constructor(remoteDeviceUid: UID) : super(WAIT_FOR_SECOND_ACK_STATE_ID) {
            this.remoteDeviceUid = remoteDeviceUid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(remoteDeviceUid),
                )
            )
        }
    }


    class ChannelConfirmedState : ConcreteProtocolState {
        @Suppress("unused")
        constructor(encodedState: Encoded) : super(CHANNEL_CONFIRMED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(CHANNEL_CONFIRMED_STATE_ID)

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
            PING_MESSAGE_ID -> return PingMessage::class.java
            ALICE_IDENTITY_AND_EPHEMERAL_KEY_MESSAGE_ID -> return AliceIdentityAndEphemeralKeyMessage::class.java
            BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID -> return BobEphemeralKeyAndK1Message::class.java
            K2_MESSAGE_ID -> return K2Message::class.java
            FIRST_ACK_MESSAGE_ID -> return FirstAckMessage::class.java
            SECOND_ACK_MESSAGE_ID -> return SecondAckMessage::class.java
            else -> return null
        }
    }


    class InitialMessage : ConcreteProtocolMessage {
        internal val remoteDeviceUid: UID

        constructor(coreProtocolMessage: CoreProtocolMessage?, remoteDeviceUid: UID) : super(
            coreProtocolMessage!!
        ) {
            this.remoteDeviceUid = remoteDeviceUid
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.remoteDeviceUid = receivedMessage.inputs[0].decodeUid()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteDeviceUid),
            )
            }
    }


    class PingMessage : ConcreteProtocolMessage {
        internal val remoteDeviceUid: UID
        internal val signature: ByteArray

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            remoteDeviceUid: UID,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.remoteDeviceUid = remoteDeviceUid
            this.signature = signature
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.remoteDeviceUid = receivedMessage.inputs[0].decodeUid()
            this.signature = receivedMessage.inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = PING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteDeviceUid),
                Encoded.of(signature),
            )
            }
    }


    class AliceIdentityAndEphemeralKeyMessage : ConcreteProtocolMessage {
        internal val remoteDeviceUid: UID
        internal val signature: ByteArray
        internal val remoteEphemeralPublicKey: EncryptionPublicKey?

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            remoteDeviceUid: UID,
            signature: ByteArray,
            remoteEphemeralPublicKey: EncryptionPublicKey?
        ) : super(coreProtocolMessage!!) {
            this.remoteDeviceUid = remoteDeviceUid
            this.signature = signature
            this.remoteEphemeralPublicKey = remoteEphemeralPublicKey
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.remoteDeviceUid = receivedMessage.inputs[0].decodeUid()
            this.signature = receivedMessage.inputs[1].decodeBytes()
            this.remoteEphemeralPublicKey =
                receivedMessage.inputs[2].decodePublicKey() as EncryptionPublicKey?
        }

        override val protocolMessageId: Int = ALICE_IDENTITY_AND_EPHEMERAL_KEY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteDeviceUid),
                Encoded.of(signature),
                Encoded.of(remoteEphemeralPublicKey!!),
            )
            }
    }


    class BobEphemeralKeyAndK1Message : ConcreteProtocolMessage {
        internal val remoteEphemeralPublicKey: EncryptionPublicKey?
        internal val c1: EncryptedBytes

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            remoteEphemeralPublicKey: EncryptionPublicKey?,
            c1: EncryptedBytes
        ) : super(coreProtocolMessage!!) {
            this.remoteEphemeralPublicKey = remoteEphemeralPublicKey
            this.c1 = c1
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.remoteEphemeralPublicKey =
                receivedMessage.inputs[0].decodePublicKey() as EncryptionPublicKey?
            this.c1 = receivedMessage.inputs[1].decodeEncryptedData()
        }

        override val protocolMessageId: Int = BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteEphemeralPublicKey!!),
                Encoded.of(c1),
            )
            }
    }


    class K2Message : ConcreteProtocolMessage {
        internal val c2: EncryptedBytes

        internal constructor(coreProtocolMessage: CoreProtocolMessage?, c2: EncryptedBytes) : super(
            coreProtocolMessage!!
        ) {
            this.c2 = c2
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.c2 = receivedMessage.inputs[0].decodeEncryptedData()
        }

        override val protocolMessageId: Int = K2_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(c2),
            )
            }
    }


    class FirstAckMessage : ConcreteProtocolMessage {
        internal val remoteSerializedIdentityWithVersionAndPhoto: String

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            remoteSerializedIdentityWithVersionAndPhoto: String
        ) : super(coreProtocolMessage!!) {
            this.remoteSerializedIdentityWithVersionAndPhoto =
                remoteSerializedIdentityWithVersionAndPhoto
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.remoteSerializedIdentityWithVersionAndPhoto =
                receivedMessage.inputs[0].decodeString()
        }

        override val protocolMessageId: Int = FIRST_ACK_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteSerializedIdentityWithVersionAndPhoto),
            )
            }
    }


    class SecondAckMessage : ConcreteProtocolMessage {
        internal val remoteSerializedIdentityWithVersionAndPhoto: String

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            remoteSerializedIdentityWithVersionAndPhoto: String
        ) : super(coreProtocolMessage!!) {
            this.remoteSerializedIdentityWithVersionAndPhoto =
                remoteSerializedIdentityWithVersionAndPhoto
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.remoteSerializedIdentityWithVersionAndPhoto =
                receivedMessage.inputs[0].decodeString()
        }

        override val protocolMessageId: Int = SECOND_ACK_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(remoteSerializedIdentityWithVersionAndPhoto),
            )
            }
    }


    //endregion
    //region Steps
    public override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                SendPingStep::class.java,
                SendPingOrEphemeralKeyStep::class.java,
                SendEphemeralKeyAndK1Step::class.java
            )

            WAITING_FOR_K1_STATE_ID -> return arrayOf<Class<*>>(
                RecoverK1AndSendK2AndCreateChannelStep::class.java
            )

            WAITING_FOR_K2_STATE_ID -> return arrayOf<Class<*>>(RecoverK2CreateChannelAndSendAckStep::class.java)
            WAIT_FOR_FIRST_ACK_STATE_ID -> return arrayOf<Class<*>>(ConfirmChannelAndSendAckStep::class.java)
            WAIT_FOR_SECOND_ACK_STATE_ID -> return arrayOf<Class<*>>(ConfirmChannelStep::class.java)
            CANCELLED_STATE_ID, PING_SENT_STATE_ID, CHANNEL_CONFIRMED_STATE_ID -> return arrayOf<Class<*>>()

            else -> return arrayOf<Class<*>>()
        }
    }

    class SendPingStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: ChannelCreationWithOwnedDeviceProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // check that the remoteDeviceUid in the receivedMessage is not our currentDeviceUid
            val currentDeviceUid =
                protocolManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            if (currentDeviceUid == null) {
                return CancelledState()
            }
            if (currentDeviceUid == receivedMessage.remoteDeviceUid) {
                Logger.w("Trying to run a ChannelCreationWithOwnedDeviceProtocol with our currentDeviceUid")
                return CancelledState()
            }

            // clean any ongoing instance of this protocol
            var channelCreationProtocolInstance: ChannelCreationProtocolInstance? = null
            try {
                channelCreationProtocolInstance = ChannelCreationProtocolInstance.get(
                    protocolManagerSession,
                    receivedMessage.remoteDeviceUid,
                    ownedIdentity,
                    ownedIdentity
                )
            } catch (_: SQLException) {
            }
            if (channelCreationProtocolInstance != null) {
                channelCreationProtocolInstance.delete()
                protocolManagerSession.protocolDelegate!!.abortProtocol(
                    protocolManagerSession.session,
                    channelCreationProtocolInstance.protocolInstanceUid,
                    ownedIdentity
                )
            }

            // clear any already created ObliviousChannel
            protocolManagerSession.channelDelegate!!.deleteObliviousChannelIfItExists(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.remoteDeviceUid,
                ownedIdentity
            )

            // send a signed ping
            val signature = protocolManagerSession.identityDelegate.signChannel(
                protocolManagerSession.session,
                Constants.SignatureContext.CHANNEL_CREATION,
                ownedIdentity,
                receivedMessage.remoteDeviceUid,
                ownedIdentity,
                currentDeviceUid,
                prng
            )


            // send the ping containing the signature
            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createAsymmetricChannelInfo(
                    ownedIdentity,
                    ownedIdentity,
                    arrayOf(receivedMessage.remoteDeviceUid)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ChannelCreationWithOwnedDeviceProtocol.PingMessage(
                    coreProtocolMessage,
                    currentDeviceUid,
                    signature!!
                ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            protocolManagerSession.identityDelegate.setLatestChannelCreationPingTimestampForOwnedDevice(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.remoteDeviceUid,
                System.currentTimeMillis()
            )

            return PingSentState()
        }
    }


    class SendPingOrEphemeralKeyStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: PingMessage,
        protocol: ChannelCreationWithOwnedDeviceProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // check that the remoteDeviceUid in the receivedMessage is not our currentDeviceUid
            val currentDeviceUid =
                protocolManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            if (currentDeviceUid == null) {
                return CancelledState()
            }
            if (currentDeviceUid == receivedMessage.remoteDeviceUid) {
                Logger.w("Received a ping for a ChannelCreationWithOwnedDeviceProtocol with our currentDeviceUid")
                return CancelledState()
            }

            // verify the signature in the PingMessage
            val signatureIsValid = Signature.verify(
                Constants.SignatureContext.CHANNEL_CREATION,
                currentDeviceUid,
                receivedMessage.remoteDeviceUid,
                ownedIdentity,
                ownedIdentity,
                ownedIdentity,
                receivedMessage.signature
            )

            if (!signatureIsValid) {
                return CancelledState()
            }

            if (ChannelCreationPingSignatureReceived.exists(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.signature
                )
            ) {
                // we already received a ping with the same signature!
                return CancelledState()
            } else {
                // store the signature to prevent future replay
                ChannelCreationPingSignatureReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.signature
                )
            }

            // Signature is valid! The other device does not have a channel
            run {
                // clean any ongoing instance of this protocol
                var channelCreationProtocolInstance: ChannelCreationProtocolInstance? = null
                try {
                    channelCreationProtocolInstance = ChannelCreationProtocolInstance.get(
                        protocolManagerSession,
                        receivedMessage.remoteDeviceUid,
                        ownedIdentity,
                        ownedIdentity
                    )
                } catch (_: SQLException) {
                }
                if (channelCreationProtocolInstance != null) {
                    channelCreationProtocolInstance.delete()
                    protocolManagerSession.protocolDelegate!!.abortProtocol(
                        protocolManagerSession.session,
                        channelCreationProtocolInstance.protocolInstanceUid,
                        ownedIdentity
                    )
                }

                // clear any already created ObliviousChannel
                protocolManagerSession.channelDelegate!!.deleteObliviousChannelIfItExists(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.remoteDeviceUid,
                    ownedIdentity
                )
            }


            // Compute a signature to prove we don't have any channel/ongoing protocol with the other device
            val signature = protocolManagerSession.identityDelegate.signChannel(
                protocolManagerSession.session,
                Constants.SignatureContext.CHANNEL_CREATION,
                ownedIdentity,
                receivedMessage.remoteDeviceUid,
                ownedIdentity,
                currentDeviceUid,
                prng
            )


            // If we are in charge (small deviceUid), send an ephemeral key
            // otherwise simply send a ping back
            val compare = currentDeviceUid.compareTo(receivedMessage.remoteDeviceUid)
            if (compare >= 0) {
                // Not in charge

                // send the ping containing the signature

                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        ownedIdentity,
                        ownedIdentity,
                        arrayOf<UID?>(receivedMessage.remoteDeviceUid)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    ChannelCreationWithOwnedDeviceProtocol.PingMessage(
                        coreProtocolMessage,
                        currentDeviceUid,
                        signature!!
                    ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                protocolManagerSession.identityDelegate.setLatestChannelCreationPingTimestampForOwnedDevice(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.remoteDeviceUid,
                    System.currentTimeMillis()
                )

                return PingSentState()
            } else {
                // In charge
                // Create a new ChannelCreationProtocolInstance
                val channelCreationProtocolInstance: ChannelCreationProtocolInstance? =
                    ChannelCreationProtocolInstance.create(
                        protocolManagerSession,
                        receivedMessage.remoteDeviceUid,
                        ownedIdentity,
                        ownedIdentity,
                        protocolInstanceUid
                    )
                if (channelCreationProtocolInstance == null) {
                    throw Exception()
                }

                val keyPair = Suite.generateEncryptionKeyPair(
                    ownedIdentity.encryptionPublicKey.algorithmImplementation,
                    prng
                )
                if (keyPair == null) {
                    throw Exception()
                }

                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        ownedIdentity,
                        ownedIdentity,
                        arrayOf<UID?>(receivedMessage.remoteDeviceUid)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    ChannelCreationWithOwnedDeviceProtocol.AliceIdentityAndEphemeralKeyMessage(
                        coreProtocolMessage,
                        currentDeviceUid,
                        signature!!,
                        keyPair.getPublicKey() as EncryptionPublicKey
                    ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return WaitingForK1State(
                    receivedMessage.remoteDeviceUid,
                    keyPair.getPrivateKey() as EncryptionPrivateKey
                )
            }
        }
    }


    class SendEphemeralKeyAndK1Step(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: AliceIdentityAndEphemeralKeyMessage,
        protocol: ChannelCreationWithOwnedDeviceProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check that the remoteDeviceUid in the receivedMessage is not our currentDeviceUid
                val currentDeviceUid =
                    protocolManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (currentDeviceUid == null) {
                    return CancelledState()
                }
                if (currentDeviceUid == receivedMessage.remoteDeviceUid) {
                    Logger.w("Received a ping for a ChannelCreationWithOwnedDeviceProtocol with our currentDeviceUid")
                    return CancelledState()
                }

                val signatureIsValid = Signature.verify(
                    Constants.SignatureContext.CHANNEL_CREATION,
                    currentDeviceUid,
                    receivedMessage.remoteDeviceUid,
                    ownedIdentity,
                    ownedIdentity,
                    ownedIdentity,
                    receivedMessage.signature
                )

                if (!signatureIsValid) {
                    return CancelledState()
                }
                if (ChannelCreationPingSignatureReceived.exists(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    // we already received a ping with the same signature!
                    return CancelledState()
                } else {
                    // store the signature to prevent future replay
                    ChannelCreationPingSignatureReceived.create(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                }
            }


            run {
                // check whether there already is an instance of this protocol running
                var channelCreationProtocolInstance: ChannelCreationProtocolInstance? = null
                try {
                    channelCreationProtocolInstance = ChannelCreationProtocolInstance.get(
                        protocolManagerSession,
                        receivedMessage.remoteDeviceUid,
                        ownedIdentity,
                        ownedIdentity
                    )
                } catch (_: SQLException) {
                }
                if (channelCreationProtocolInstance != null) {
                    // an instance already exists, abort it, terminate this protocol, and restart it with a fresh ping
                    channelCreationProtocolInstance.delete()
                    protocolManagerSession.protocolDelegate!!.abortProtocol(
                        protocolManagerSession.session,
                        channelCreationProtocolInstance.protocolInstanceUid,
                        ownedIdentity
                    )


                    val childProtocolInstanceUid = UID(prng)
                    val coreProtocolMessage = CoreProtocolMessage(
                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                        ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID,
                        childProtocolInstanceUid
                    )
                    val messageToSend: ChannelMessageToSend? = InitialMessage(
                        coreProtocolMessage,
                        receivedMessage.remoteDeviceUid
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )

                    return CancelledState()
                } else {
                    // No previous instance of the protocol exists, create one
                    channelCreationProtocolInstance =
                        ChannelCreationProtocolInstance.create(
                            protocolManagerSession,
                            receivedMessage.remoteDeviceUid,
                            ownedIdentity,
                            ownedIdentity,
                            protocolInstanceUid
                        )
                    if (channelCreationProtocolInstance == null) {
                        throw Exception()
                    }
                }
            }

            val keyPair = Suite.generateEncryptionKeyPair(
                ownedIdentity.encryptionPublicKey.algorithmImplementation,
                prng
            )
            if (keyPair == null) {
                throw Exception()
            }

            // compute k1
            val publicKeyEncryption =
                Suite.getPublicKeyEncryption(receivedMessage.remoteEphemeralPublicKey)!!
            val ciphertextAndKey =
                publicKeyEncryption.kemEncrypt(receivedMessage.remoteEphemeralPublicKey, prng)!!
            val k1 = ciphertextAndKey.getKey()
            val c1 = ciphertextAndKey.getCiphertext()

            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createAsymmetricChannelInfo(
                    ownedIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(receivedMessage.remoteDeviceUid)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ChannelCreationWithOwnedDeviceProtocol.BobEphemeralKeyAndK1Message(
                    coreProtocolMessage,
                    keyPair.getPublicKey() as EncryptionPublicKey,
                    c1!!
                ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return WaitingForK2State(
                receivedMessage.remoteDeviceUid,
                keyPair.getPrivateKey() as EncryptionPrivateKey,
                k1
            )
        }
    }


    class RecoverK1AndSendK2AndCreateChannelStep(
        internal val startState: WaitingForK1State,
        internal val receivedMessage: BobEphemeralKeyAndK1Message,
        protocol: ChannelCreationWithOwnedDeviceProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            var publicKeyEncryption = Suite.getPublicKeyEncryption(startState.ephemeralPrivateKey)!!
            val k1 =
                publicKeyEncryption.kemDecrypt(startState.ephemeralPrivateKey, receivedMessage.c1)
            if (k1 == null) {
                Logger.e("Could not recover k1.")
                return CancelledState()
            }

            // compute k2
            publicKeyEncryption =
                Suite.getPublicKeyEncryption(receivedMessage.remoteEphemeralPublicKey)!!
            val ciphertextAndKey =
                publicKeyEncryption.kemEncrypt(receivedMessage.remoteEphemeralPublicKey, prng)!!
            val k2 = ciphertextAndKey.getKey()
            val c2 = ciphertextAndKey.getCiphertext()

            val seed = Seed.of(k1, k2!!)

            // add the contact deviceUid if not already there
            try {
                protocolManagerSession.identityDelegate!!.addDeviceForOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    null,
                    null,
                    null,
                    null,
                    true
                )

                // trigger an owned device discovery
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
            } catch (_: Exception) {
                Logger.w("Exception when adding an owned device")
            }

            // if there is already a channel, we have a problem! Abort the protocol and restart from scratch
            if (protocolManagerSession.channelDelegate!!.checkIfObliviousChannelExists(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    ownedIdentity
                )
            ) {
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialMessage(
                    coreProtocolMessage,
                    startState.remoteDeviceUid
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return CancelledState()
            }

            // create the channel
            protocolManagerSession.channelDelegate.createObliviousChannel(
                protocolManagerSession.session,
                ownedIdentity,
                startState.remoteDeviceUid,
                ownedIdentity,
                seed,
                0
            )

            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createAsymmetricChannelInfo(
                    ownedIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(startState.remoteDeviceUid)
                )
            )
            val messageToSend: ChannelMessageToSend? =
                ChannelCreationWithOwnedDeviceProtocol.K2Message(coreProtocolMessage, c2!!)
                    .generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return WaitForFirstAckState(startState.remoteDeviceUid)
        }
    }


    class RecoverK2CreateChannelAndSendAckStep(
        internal val startState: WaitingForK2State,
        internal val receivedMessage: K2Message,
        protocol: ChannelCreationWithOwnedDeviceProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val publicKeyEncryption = Suite.getPublicKeyEncryption(startState.ephemeralPrivateKey)!!
            val k2 =
                publicKeyEncryption.kemDecrypt(startState.ephemeralPrivateKey, receivedMessage.c2)
            if (k2 == null) {
                Logger.e("Could not recover k2.")
                return CancelledState()
            }

            // Add the otherDeviceUid to the contactIdentity if needed --> we no longer trigger a device discovery
            try {
                protocolManagerSession.identityDelegate!!.addDeviceForOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    null,
                    null,
                    null,
                    null,
                    true
                )

                // trigger an owned device discovery
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
            } catch (_: Exception) {
                Logger.w("Exception when adding an owned device")
            }

            // if there is already a channel, we have a problem! Abort the protocol and restart from scratch
            if (protocolManagerSession.channelDelegate!!.checkIfObliviousChannelExists(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    ownedIdentity
                )
            ) {
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.CHANNEL_CREATION_WITH_OWNED_DEVICE_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialMessage(
                    coreProtocolMessage,
                    startState.remoteDeviceUid
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return CancelledState()
            }


            val seed = Seed.of(startState.k1!!, k2)
            protocolManagerSession.channelDelegate.createObliviousChannel(
                protocolManagerSession.session,
                ownedIdentity,
                startState.remoteDeviceUid,
                ownedIdentity,
                seed,
                0
            )

            var serializedDetailsWithVersionAndPhoto = ""
            try {
                val ownedDetailsWithVersionAndPhoto =
                    protocolManagerSession.identityDelegate!!.getOwnedIdentityPublishedAndLatestDetails(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!![0]
                serializedDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                    .writeValueAsString(ownedDetailsWithVersionAndPhoto)
            } catch (e: Exception) {
                Logger.x(e)
            }

            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    ownedIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(startState.remoteDeviceUid),
                    false
                )
            )
            val messageToSend: ChannelMessageToSend? = FirstAckMessage(
                coreProtocolMessage,
                serializedDetailsWithVersionAndPhoto
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return WaitForSecondAckState(startState.remoteDeviceUid)
        }
    }


    class ConfirmChannelAndSendAckStep(
        internal val startState: WaitForFirstAckState,
        internal val receivedMessage: FirstAckMessage,
        protocol: ChannelCreationWithOwnedDeviceProtocol
    ) : ProtocolStep(
        ReceptionChannelInfo.createObliviousChannelInfo(
            startState.remoteDeviceUid, protocol.ownedIdentity!!
        ), receivedMessage, protocol
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // update the publishedContactDetails with what we just received
                try {
                    val ownDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                        .readValue<JsonIdentityDetailsWithVersionAndPhoto?>(
                            receivedMessage.remoteSerializedIdentityWithVersionAndPhoto,
                            JsonIdentityDetailsWithVersionAndPhoto::class.java
                        )
                    if (ownDetailsWithVersionAndPhoto != null) {
                        val photoDownloadNeeded =
                            protocolManagerSession.identityDelegate!!.setOwnedIdentityDetailsFromOtherDevice(
                                protocolManagerSession.session,
                                ownedIdentity,
                                ownDetailsWithVersionAndPhoto
                            )

                        if (photoDownloadNeeded) {
                            // we need to download a photo
                            val coreProtocolMessage = CoreProtocolMessage(
                                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                                ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,
                                UID(prng)
                            )
                            val messageToSend: ChannelMessageToSend? =
                                DownloadIdentityPhotoChildProtocol.InitialMessage(
                                    coreProtocolMessage,
                                    ownedIdentity,
                                    receivedMessage.remoteSerializedIdentityWithVersionAndPhoto
                                ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            run {
                // We received a message on the obliviousChannel, so we can confirm it
                protocolManagerSession.channelDelegate!!.confirmObliviousChannel(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    ownedIdentity
                )
            }

            run {
                // send this device capabilities to other device
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialSingleOwnedDeviceMessage(
                    coreProtocolMessage,
                    startState.remoteDeviceUid,
                    false
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // Delete the ChannelCreationProtocolInstance
                try {
                    val channelCreationProtocolInstance: ChannelCreationProtocolInstance? =
                        ChannelCreationProtocolInstance.get(
                            protocolManagerSession,
                            startState.remoteDeviceUid,
                            ownedIdentity,
                            ownedIdentity
                        )
                    channelCreationProtocolInstance?.delete()
                } catch (_: Exception) {
                    Logger.w("Exception when deleting a ChannelCreationProtocolInstance")
                }
            }

            run {
                // send Ack message to Bob
                var serializedDetailsWithVersionAndPhoto = ""
                try {
                    val ownedDetailsWithVersionAndPhoto =
                        protocolManagerSession.identityDelegate!!.getOwnedIdentityPublishedAndLatestDetails(
                            protocolManagerSession.session,
                            ownedIdentity
                        )!![0]
                    serializedDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                        .writeValueAsString(ownedDetailsWithVersionAndPhoto)
                } catch (e: Exception) {
                    Logger.x(e)
                }

                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createObliviousChannelInfo(
                        ownedIdentity,
                        ownedIdentity,
                        arrayOf<UID?>(startState.remoteDeviceUid),
                        true
                    )
                )
                val messageToSend: ChannelMessageToSend? = SecondAckMessage(
                    coreProtocolMessage,
                    serializedDetailsWithVersionAndPhoto
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            //            {
//                // initiate a device synchronization protocol
//                UID currentDeviceUid = protocolManagerSession!!.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(protocolManagerSession!!.session, getOwnedIdentity());
//                CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(getOwnedIdentity()),
//                        ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
//                        SynchronizationProtocol.computeOngoingProtocolInstanceUid(getOwnedIdentity(), currentDeviceUid, startState.remoteDeviceUid),
//                        false);
//                ChannelMessageToSend message = new SynchronizationProtocol.InitiateSyncMessage(coreProtocolMessage, startState.remoteDeviceUid).generateChannelProtocolMessageToSend();
//                protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, getPrng());
//            }
            return ChannelConfirmedState()
        }
    }

    class ConfirmChannelStep(
        internal val startState: WaitForSecondAckState,
        internal val receivedMessage: SecondAckMessage,
        protocol: ChannelCreationWithOwnedDeviceProtocol
    ) : ProtocolStep(
        ReceptionChannelInfo.createObliviousChannelInfo(
            startState.remoteDeviceUid, protocol.ownedIdentity!!
        ), receivedMessage, protocol
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            // update the publishedContactDetails with what we just received
            run {
                // update the publishedContactDetails with what we just received
                try {
                    val ownDetailsWithVersionAndPhoto = protocol.jsonObjectMapper
                        .readValue<JsonIdentityDetailsWithVersionAndPhoto?>(
                            receivedMessage.remoteSerializedIdentityWithVersionAndPhoto,
                            JsonIdentityDetailsWithVersionAndPhoto::class.java
                        )
                    if (ownDetailsWithVersionAndPhoto != null) {
                        val photoDownloadNeeded =
                            protocolManagerSession.identityDelegate!!.setOwnedIdentityDetailsFromOtherDevice(
                                protocolManagerSession.session,
                                ownedIdentity,
                                ownDetailsWithVersionAndPhoto
                            )

                        if (photoDownloadNeeded) {
                            // we need to download a photo
                            val coreProtocolMessage = CoreProtocolMessage(
                                SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                                ConcreteProtocol.DOWNLOAD_IDENTITY_PHOTO_CHILD_PROTOCOL_ID,
                                UID(prng)
                            )
                            val messageToSend: ChannelMessageToSend? =
                                DownloadIdentityPhotoChildProtocol.InitialMessage(
                                    coreProtocolMessage,
                                    ownedIdentity,
                                    receivedMessage.remoteSerializedIdentityWithVersionAndPhoto
                                ).generateChannelProtocolMessageToSend()
                            protocolManagerSession.channelDelegate!!.post(
                                protocolManagerSession.session,
                                messageToSend,
                                prng
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            run {
                // we can confirm the obliviousChannel
                protocolManagerSession.channelDelegate!!.confirmObliviousChannel(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.remoteDeviceUid,
                    ownedIdentity
                )
            }

            run {
                // send this device capabilities to other device
                val childProtocolInstanceUid = UID(prng)
                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.DEVICE_CAPABILITIES_DISCOVERY_PROTOCOL_ID,
                    childProtocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = InitialSingleOwnedDeviceMessage(
                    coreProtocolMessage,
                    startState.remoteDeviceUid,
                    false
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            // Delete the ChannelCreationProtocolInstance
            try {
                val channelCreationProtocolInstance: ChannelCreationProtocolInstance? =
                    ChannelCreationProtocolInstance.get(
                        protocolManagerSession,
                        startState.remoteDeviceUid,
                        ownedIdentity,
                        ownedIdentity
                    )
                channelCreationProtocolInstance?.delete()
            } catch (_: Exception) {
                Logger.w("Exception when deleting a ChannelCreationProtocolInstance")
            }

            //            {
//                // initiate a device synchronization protocol
//                UID currentDeviceUid = protocolManagerSession!!.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(protocolManagerSession!!.session, getOwnedIdentity());
//                CoreProtocolMessage coreProtocolMessage = new CoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(getOwnedIdentity()),
//                        ConcreteProtocol.SYNCHRONIZATION_PROTOCOL_ID,
//                        SynchronizationProtocol.computeOngoingProtocolInstanceUid(getOwnedIdentity(), currentDeviceUid, startState.remoteDeviceUid),
//                        false);
//                ChannelMessageToSend message = new SynchronizationProtocol.InitiateSyncMessage(coreProtocolMessage, startState.remoteDeviceUid).generateChannelProtocolMessageToSend();
//                protocolManagerSession!!.channelDelegate!!.post(protocolManagerSession!!.session, message, getPrng());
//            }
            return ChannelConfirmedState()
        }
    } //endregion

    companion object {
        //region States
        const val CANCELLED_STATE_ID: Int = 1
        const val PING_SENT_STATE_ID: Int = 2
        const val WAITING_FOR_K1_STATE_ID: Int = 3
        const val WAITING_FOR_K2_STATE_ID: Int = 4
        const val WAIT_FOR_FIRST_ACK_STATE_ID: Int = 5
        const val WAIT_FOR_SECOND_ACK_STATE_ID: Int = 7
        const val CHANNEL_CONFIRMED_STATE_ID: Int = 8

        //endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val PING_MESSAGE_ID: Int = 1
        const val ALICE_IDENTITY_AND_EPHEMERAL_KEY_MESSAGE_ID: Int = 2
        const val BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID: Int = 3
        const val K2_MESSAGE_ID: Int = 4
        const val FIRST_ACK_MESSAGE_ID: Int = 5
        const val SECOND_ACK_MESSAGE_ID: Int = 6
    }
}
