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
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep

class FullRatchetProtocol(
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
    override val protocolId: Int = ConcreteProtocol.FULL_RATCHET_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(FULL_RATCHET_DONE_STATE_ID, CANCELLED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            ALICE_WAITING_FOR_K1_STATE_ID -> return AliceWaitingForK1State::class.java
            BOB_WAITING_FOR_K2_STATE_ID -> return BobWaitingForK2State::class.java
            ALICE_WAITING_FOR_ACK_STATE_ID -> return AliceWaitingForAckState::class.java
            FULL_RATCHET_DONE_STATE_ID -> return FullRatchetDoneState::class.java
            CANCELLED_STATE_ID -> return CancelledState::class.java
            else -> return null
        }
    }

    class AliceWaitingForK1State : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactDeviceUid: UID
        internal val ephemeralPrivateKey: EncryptionPrivateKey?
        internal val restartCounter: Long

        constructor(encodedState: Encoded) : super(ALICE_WAITING_FOR_K1_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactDeviceUid = list[1].decodeUid()
            this.ephemeralPrivateKey = list[2].decodePrivateKey() as EncryptionPrivateKey?
            this.restartCounter = list[3].decodeLong()
        }

        internal constructor(
            contactIdentity: Identity,
            contactDeviceUid: UID,
            ephemeralPrivateKey: EncryptionPrivateKey?,
            restartCounter: Long
        ) : super(
            ALICE_WAITING_FOR_K1_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactDeviceUid = contactDeviceUid
            this.ephemeralPrivateKey = ephemeralPrivateKey
            this.restartCounter = restartCounter
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactDeviceUid),
                    Encoded.of(ephemeralPrivateKey!!),
                    Encoded.of(restartCounter),
                )
            )
        }
    }


    class BobWaitingForK2State : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactDeviceUid: UID
        internal val ephemeralPrivateKey: EncryptionPrivateKey?
        internal val k1: AuthEncKey?
        internal val restartCounter: Long

        constructor(encodedState: Encoded) : super(BOB_WAITING_FOR_K2_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactDeviceUid = list[1].decodeUid()
            this.ephemeralPrivateKey = list[2].decodePrivateKey() as EncryptionPrivateKey?
            this.k1 = list[3].decodeSymmetricKey() as AuthEncKey?
            this.restartCounter = list[4].decodeLong()
        }

        internal constructor(
            contactIdentity: Identity,
            contactDeviceUid: UID,
            ephemeralPrivateKey: EncryptionPrivateKey?,
            k1: AuthEncKey?,
            restartCounter: Long
        ) : super(
            BOB_WAITING_FOR_K2_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactDeviceUid = contactDeviceUid
            this.ephemeralPrivateKey = ephemeralPrivateKey
            this.k1 = k1
            this.restartCounter = restartCounter
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactDeviceUid),
                    Encoded.of(ephemeralPrivateKey!!),
                    Encoded.of(k1!!),
                    Encoded.of(restartCounter),
                )
            )
        }
    }


    class AliceWaitingForAckState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactDeviceUid: UID
        internal val seed: Seed
        internal val restartCounter: Long

        constructor(encodedState: Encoded) : super(ALICE_WAITING_FOR_ACK_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactDeviceUid = list[1].decodeUid()
            this.seed = list[2].decodeSeed()
            this.restartCounter = list[3].decodeLong()
        }

        internal constructor(
            contactIdentity: Identity,
            contactDeviceUid: UID,
            seed: Seed,
            restartCounter: Long
        ) : super(
            ALICE_WAITING_FOR_ACK_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactDeviceUid = contactDeviceUid
            this.seed = seed
            this.restartCounter = restartCounter
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactDeviceUid),
                    Encoded.of(seed),
                    Encoded.of(restartCounter),
                )
            )
        }
    }

    class FullRatchetDoneState : ConcreteProtocolState {
        constructor(encodedState: Encoded) : super(FULL_RATCHET_DONE_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(FULL_RATCHET_DONE_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }

    class CancelledState : ConcreteProtocolState {
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


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            ALICE_EPHEMERAL_KEY_MESSAGE_ID -> return AliceEphemeralKeyMessage::class.java
            BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID -> return BobEphemeralKeyAndK1Message::class.java
            ALICE_K2_MESSAGE_ID -> return AliceK2Message::class.java
            BOB_ACK_MESSAGE_ID -> return BobAckMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactDeviceUid: UID

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactDeviceUid: UID
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactDeviceUid = contactDeviceUid
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactDeviceUid = receivedMessage.inputs[1].decodeUid()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactDeviceUid),
            )
            }
    }

    class AliceEphemeralKeyMessage : ConcreteProtocolMessage {
        internal val contactEphemeralPublicKey: EncryptionPublicKey?
        internal val restartCounter: Long

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactEphemeralPublicKey: EncryptionPublicKey?,
            restartCounter: Long
        ) : super(coreProtocolMessage!!) {
            this.contactEphemeralPublicKey = contactEphemeralPublicKey
            this.restartCounter = restartCounter
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactEphemeralPublicKey =
                receivedMessage.inputs[0].decodePublicKey() as EncryptionPublicKey?
            this.restartCounter = receivedMessage.inputs[1].decodeLong()
        }

        override val protocolMessageId: Int = ALICE_EPHEMERAL_KEY_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactEphemeralPublicKey!!),
                Encoded.of(restartCounter),
            )
            }
    }

    class BobEphemeralKeyAndK1Message : ConcreteProtocolMessage {
        internal val contactEphemeralPublicKey: EncryptionPublicKey?
        internal val c1: EncryptedBytes
        internal val restartCounter: Long

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactEphemeralPublicKey: EncryptionPublicKey?,
            c1: EncryptedBytes,
            restartCounter: Long
        ) : super(coreProtocolMessage!!) {
            this.contactEphemeralPublicKey = contactEphemeralPublicKey
            this.c1 = c1
            this.restartCounter = restartCounter
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.contactEphemeralPublicKey =
                receivedMessage.inputs[0].decodePublicKey() as EncryptionPublicKey?
            this.c1 = receivedMessage.inputs[1].decodeEncryptedData()
            this.restartCounter = receivedMessage.inputs[2].decodeLong()
        }

        override val protocolMessageId: Int = BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactEphemeralPublicKey!!),
                Encoded.of(c1),
                Encoded.of(restartCounter),
            )
            }
    }

    class AliceK2Message : ConcreteProtocolMessage {
        internal val c2: EncryptedBytes
        internal val restartCounter: Long

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            c2: EncryptedBytes,
            restartCounter: Long
        ) : super(coreProtocolMessage!!) {
            this.c2 = c2
            this.restartCounter = restartCounter
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.c2 = receivedMessage.inputs[0].decodeEncryptedData()
            this.restartCounter = receivedMessage.inputs[1].decodeLong()
        }

        override val protocolMessageId: Int = ALICE_K2_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(c2),
                Encoded.of(restartCounter),
            )
            }
    }

    class BobAckMessage : ConcreteProtocolMessage {
        internal val restartCounter: Long

        constructor(coreProtocolMessage: CoreProtocolMessage?, restartCounter: Long) : super(
            coreProtocolMessage!!
        ) {
            this.restartCounter = restartCounter
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.restartCounter = receivedMessage.inputs[0].decodeLong()
        }

        override val protocolMessageId: Int = BOB_ACK_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(restartCounter),
            )
            }
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                AliceSendEphemeralKeyStep::class.java,
                BobSendEphemeralKeyAndK1Step::class.java
            )

            ALICE_WAITING_FOR_K1_STATE_ID -> return arrayOf<Class<*>>(
                AliceRecoverK1AndSendK2Step::class.java,
                AliceResendEphemeralKeyStep::class.java
            )

            BOB_WAITING_FOR_K2_STATE_ID -> return arrayOf<Class<*>>(
                BobRecoverK2ToUpdateReceiveSeedAndSendAckStep::class.java,
                BobSendEphemeralKeyAndK1Step::class.java
            )

            ALICE_WAITING_FOR_ACK_STATE_ID -> return arrayOf<Class<*>>(
                AliceUpdateSendSeedStep::class.java,
                AliceResendEphemeralKeyStep::class.java
            )

            FULL_RATCHET_DONE_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class AliceSendEphemeralKeyStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: FullRatchetProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!
            val localPrng = prng

            // generate a random 5-byte nonce as the heavy weight bits of the restart counter
            //   --> this prevents reusing a message from an old run of the protocol in a newer run (this is required because the prtocolUid is deterministic)
            val bytes = localPrng.bytes(5)
            var restartCounter: Long = 0
            for (i in 0..4) {
                restartCounter = restartCounter shl 8
                restartCounter += (bytes[i].toInt() and 0xff).toLong()
            }
            restartCounter =
                restartCounter shl 23 // the MSb is 0, 40 bits of nonce, 23 bits for the actual restartCounter

            val keyPair = Suite.generateEncryptionKeyPair(
                ownedIdentity.encryptionPublicKey.algorithmImplementation,
                localPrng
            )
            if (keyPair == null) {
                throw Exception()
            }

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    receivedMessage.contactIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(receivedMessage.contactDeviceUid),
                    true
                ), protocolId, protocolInstanceUid, false
            )
            val messageToSend: ChannelMessageToSend? = AliceEphemeralKeyMessage(
                coreProtocolMessage,
                keyPair.getPublicKey() as EncryptionPublicKey,
                restartCounter
            ).generateChannelProtocolMessageToSend()
            try {
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: NoAcceptableChannelException) {
                // the oblivious channel no longer exists, no need for a full ratchet!
                return CancelledState()
            }

            return AliceWaitingForK1State(
                receivedMessage.contactIdentity,
                receivedMessage.contactDeviceUid,
                keyPair.getPrivateKey() as EncryptionPrivateKey,
                restartCounter
            )
        }
    }


    class AliceResendEphemeralKeyStep : ProtocolStep {
        internal val contactIdentity: Identity?
        internal val contactDeviceUid: UID?
        internal val previousRestartCounter: Long
        internal val receivedMessage: InitialMessage

        constructor(
            startState: AliceWaitingForK1State,
            receivedMessage: InitialMessage,
            protocol: FullRatchetProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.contactIdentity = startState.contactIdentity
            this.contactDeviceUid = startState.contactDeviceUid
            this.previousRestartCounter = startState.restartCounter
            this.receivedMessage = receivedMessage
        }

        constructor(
            startState: AliceWaitingForAckState,
            receivedMessage: InitialMessage,
            protocol: FullRatchetProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.contactIdentity = startState.contactIdentity
            this.contactDeviceUid = startState.contactDeviceUid
            this.previousRestartCounter = startState.restartCounter
            this.receivedMessage = receivedMessage
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!
            if (!receivedMessage.contactDeviceUid.equals(contactDeviceUid) ||
                !receivedMessage.contactIdentity.equals(contactIdentity)
            ) {
                throw Exception()
            }

            val restartCounter = previousRestartCounter + 1

            val keyPair = Suite.generateEncryptionKeyPair(
                ownedIdentity.encryptionPublicKey.algorithmImplementation,
                prng
            )
            if (keyPair == null) {
                throw Exception()
            }

            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    receivedMessage.contactIdentity,
                    ownedIdentity,
                    arrayOf<UID?>(receivedMessage.contactDeviceUid),
                    true
                ), protocolId, protocolInstanceUid, false
            )
            val messageToSend: ChannelMessageToSend? = AliceEphemeralKeyMessage(
                coreProtocolMessage,
                keyPair.getPublicKey() as EncryptionPublicKey,
                restartCounter
            ).generateChannelProtocolMessageToSend()

            try {
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: NoAcceptableChannelException) {
                // the oblivious channel no longer exists, no need for a full ratchet!
                return CancelledState()
            }

            return AliceWaitingForK1State(
                receivedMessage.contactIdentity,
                receivedMessage.contactDeviceUid,
                keyPair.getPrivateKey() as EncryptionPrivateKey,
                restartCounter
            )
        }
    }


    class BobSendEphemeralKeyAndK1Step : ProtocolStep {
        internal val previousState: BobWaitingForK2State?
        internal val receivedMessage: AliceEphemeralKeyMessage

        constructor(
            startState: InitialProtocolState?,
            receivedMessage: AliceEphemeralKeyMessage,
            protocol: FullRatchetProtocol?
        ) : super(
            createAnyObliviousChannelInfo(), receivedMessage, protocol!!
        ) {
            this.previousState = null
            this.receivedMessage = receivedMessage
        }

        constructor(
            startState: BobWaitingForK2State,
            receivedMessage: AliceEphemeralKeyMessage,
            protocol: FullRatchetProtocol?
        ) : super(
            ReceptionChannelInfo.createObliviousChannelInfo(startState.contactDeviceUid, startState.contactIdentity),
            receivedMessage,
            protocol!!
        ) {
            this.previousState = startState
            this.receivedMessage = receivedMessage
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (previousState != null) {
                if ((receivedMessage.restartCounter shr 23) == (previousState.restartCounter shr 23) // nonce part of the restart counter are the same
                    && (receivedMessage.restartCounter <= previousState.restartCounter)
                ) {     // counter is smaller --> this is an old message of the same run --> ignore it
                    return previousState
                }
            }

            val currentDeviceUid =
                protocolManagerSession.identityDelegate!!.getCurrentDeviceUidOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )

            if (!protocolInstanceUid!!.equals(
                    FullRatchetProtocol.computeProtocolUid(
                        receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!,
                        ownedIdentity,
                        receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()!!,
                        currentDeviceUid!!
                    )
                )
            ) {
                // the protocolInstanceUid does not match what it should be --> Abort !
                return CancelledState()
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
                Suite.getPublicKeyEncryption(receivedMessage.contactEphemeralPublicKey)!!
            val ciphertextAndKey =
                publicKeyEncryption.kemEncrypt(receivedMessage.contactEphemeralPublicKey, prng)!!
            val k1 = ciphertextAndKey.getKey()
            val c1 = ciphertextAndKey.getCiphertext()

            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity(),
                    ownedIdentity,
                    arrayOf(receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()),
                    true
                )
            )
            val messageToSend: ChannelMessageToSend? =
                FullRatchetProtocol.BobEphemeralKeyAndK1Message(
                    coreProtocolMessage,
                    keyPair.getPublicKey() as EncryptionPublicKey,
                    c1!!,
                    receivedMessage.restartCounter
                ).generateChannelProtocolMessageToSend()
            try {
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: NoAcceptableChannelException) {
                // the oblivious channel no longer exists, no need for a full ratchet!
                return CancelledState()
            }

            return BobWaitingForK2State(
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!,
                receivedMessage.receptionChannelInfo!!.getRemoteDeviceUid()!!,
                keyPair.getPrivateKey() as EncryptionPrivateKey,
                k1,
                receivedMessage.restartCounter
            )
        }
    }


    class AliceRecoverK1AndSendK2Step(
        internal val startState: AliceWaitingForK1State,
        internal val receivedMessage: BobEphemeralKeyAndK1Message,
        protocol: FullRatchetProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createObliviousChannelInfo(
            startState.contactDeviceUid, startState.contactIdentity
        ), receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // verify that the restartCounter matches or ignore the message
            if (receivedMessage.restartCounter != startState.restartCounter) {
                return startState
            }

            // recover k1
            var publicKeyEncryption = Suite.getPublicKeyEncryption(startState.ephemeralPrivateKey)!!
            val k1 =
                publicKeyEncryption.kemDecrypt(startState.ephemeralPrivateKey, receivedMessage.c1)
            if (k1 == null) {
                Logger.e("Could not recover k1.")
                return CancelledState()
            }

            // compute k2
            publicKeyEncryption =
                Suite.getPublicKeyEncryption(receivedMessage.contactEphemeralPublicKey)!!

            val ciphertextAndKey =
                publicKeyEncryption.kemEncrypt(receivedMessage.contactEphemeralPublicKey, prng)!!
            val k2 = ciphertextAndKey.getKey()
            val c2 = ciphertextAndKey.getCiphertext()

            val seed = Seed.of(k1, k2!!)


            val coreProtocolMessage = CoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    startState.contactIdentity,
                    ownedIdentity,
                    arrayOf(startState.contactDeviceUid),
                    true
                ), protocolId, protocolInstanceUid, false
            )
            val messageToSend: ChannelMessageToSend? = AliceK2Message(
                coreProtocolMessage,
                c2!!,
                startState.restartCounter
            ).generateChannelProtocolMessageToSend()
            try {
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            } catch (_: NoAcceptableChannelException) {
                // the oblivious channel no longer exists, no need for a full ratchet!
                return CancelledState()
            }

            return AliceWaitingForAckState(
                startState.contactIdentity,
                startState.contactDeviceUid,
                seed,
                startState.restartCounter
            )
        }
    }


    class BobRecoverK2ToUpdateReceiveSeedAndSendAckStep(
        internal val startState: BobWaitingForK2State,
        internal val receivedMessage: AliceK2Message,
        protocol: FullRatchetProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createObliviousChannelInfo(
            startState.contactDeviceUid, startState.contactIdentity
        ), receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // verify that the restartCounter matches or ignore the message
            if (receivedMessage.restartCounter != startState.restartCounter) {
                return startState
            }

            // recover k2
            val publicKeyEncryption = Suite.getPublicKeyEncryption(startState.ephemeralPrivateKey)!!
            val k2 =
                publicKeyEncryption.kemDecrypt(startState.ephemeralPrivateKey, receivedMessage.c2)
            if (k2 == null) {
                Logger.e("Could not recover k2.")
                return CancelledState()
            }

            val seed = Seed.of(startState.k1!!, k2)

            protocolManagerSession.channelDelegate!!.updateObliviousChannelReceiveSeed(
                protocolManagerSession.session,
                ownedIdentity,
                startState.contactDeviceUid,
                startState.contactIdentity,
                seed,
                0
            )

            val coreProtocolMessage = buildCoreProtocolMessage(
                SendChannelInfo.createObliviousChannelInfo(
                    startState.contactIdentity,
                    ownedIdentity,
                    arrayOf(startState.contactDeviceUid),
                    true
                )
            )
            val messageToSend: ChannelMessageToSend? = BobAckMessage(
                coreProtocolMessage,
                startState.restartCounter
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return FullRatchetDoneState()
        }
    }


    class AliceUpdateSendSeedStep(
        internal val startState: AliceWaitingForAckState,
        internal val receivedMessage: BobAckMessage,
        protocol: FullRatchetProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createObliviousChannelInfo(
            startState.contactDeviceUid, startState.contactIdentity
        ), receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // verify that the restartCounter matches or ignore the message
            if (receivedMessage.restartCounter != startState.restartCounter) {
                return startState
            }

            protocolManagerSession.channelDelegate!!.updateObliviousChannelSendSeed(
                protocolManagerSession.session,
                ownedIdentity,
                startState.contactDeviceUid,
                startState.contactIdentity,
                startState.seed,
                0
            )

            return FullRatchetDoneState()
        }
    } // endregion


    companion object {
        fun computeProtocolUid(
            aliceIdentity: Identity,
            bobIdentity: Identity,
            aliceDeviceUid: UID,
            bobDeviceUid: UID
        ): UID {
            val prngSeed = Seed(
                Seed(aliceIdentity.getBytes()),
                Seed(bobIdentity.getBytes()),
                Seed(aliceDeviceUid.bytes),
                Seed(bobDeviceUid.bytes)
            )
            val seededPRNG = Suite.getDefaultPRNG(0, prngSeed)
            return UID(seededPRNG)
        }

        // region States
        const val ALICE_WAITING_FOR_K1_STATE_ID: Int = 1
        const val BOB_WAITING_FOR_K2_STATE_ID: Int = 2
        const val ALICE_WAITING_FOR_ACK_STATE_ID: Int = 3
        const val FULL_RATCHET_DONE_STATE_ID: Int = 4
        const val CANCELLED_STATE_ID: Int = 5

        // if receiving an initial message while in waiting_for_k1 state, resend a new ephemeral key, increment the internal full ratchet counter
        // if receiving an ephemeral key while in waiting_for_k2 state, resend a new ephemeral key, use the new internal full ratchet counter
        // once you get the ack, you can change the send seed
        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val ALICE_EPHEMERAL_KEY_MESSAGE_ID: Int = 1
        const val BOB_EPHEMERAL_KEY_AND_K1_MESSAGE_ID: Int = 2
        const val ALICE_K2_MESSAGE_ID: Int = 3
        const val BOB_ACK_MESSAGE_ID: Int = 4
    }
}
