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
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAsymmetricBroadcastChannelInfo
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createDirectTrustOrigin
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.MutualScanSignatureReceived
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.ProtocolStep

class TrustEstablishmentWithMutualScanProtocol(
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
    override val protocolId: Int = ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_MUTUAL_SCAN_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINISHED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            WAITING_FOR_CONFIRMATION_STATE_ID -> return WaitingForConfirmationState::class.java
            FINISHED_STATE_ID -> return FinishedState::class.java
            else -> return null
        }
    }

    class WaitingForConfirmationState : ConcreteProtocolState {
        internal val bobIdentity: Identity

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_CONFIRMATION_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.bobIdentity = list[0].decodeIdentity()
        }

        constructor(bobIdentity: Identity) : super(WAITING_FOR_CONFIRMATION_STATE_ID) {
            this.bobIdentity = bobIdentity
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(bobIdentity),
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

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            ALICE_SENDS_SIGNATURE_TO_BOB_MESSAGE_ID -> return AliceSendsSignatureToBobMessage::class.java
            ALICE_PROPAGATES_QR_CODE_MESSAGE_ID -> return AlicePropagatesQrCodeMessage::class.java
            BOB_SENDS_CONFIRMATION_AND_DETAILS_TO_ALICE_MESSAGE_ID -> return BobSendsConfirmationAndDetailsToAliceMessage::class.java
            BOB_PROPAGATES_SIGNATURE_MESSAGE_ID -> return BobPropagatesSignatureMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val signature: ByteArray


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.signature = signature
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signature = receivedMessage.inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(signature),
            )
            }
    }


    class AliceSendsSignatureToBobMessage : ConcreteProtocolMessage {
        internal val aliceIdentity: Identity
        internal val signature: ByteArray
        internal val serializedAliceDetails: String
        internal val aliceDeviceUids: Array<UID?>


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            aliceIdentity: Identity,
            signature: ByteArray,
            serializedAliceDetails: String,
            aliceDeviceUids: Array<UID?>
        ) : super(coreProtocolMessage!!) {
            this.aliceIdentity = aliceIdentity
            this.signature = signature
            this.serializedAliceDetails = serializedAliceDetails
            this.aliceDeviceUids = aliceDeviceUids
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.aliceIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signature = receivedMessage.inputs[1].decodeBytes()
            this.serializedAliceDetails = receivedMessage.inputs[2].decodeString()
            this.aliceDeviceUids = receivedMessage.inputs[3].decodeUidArray()
        }

        override val protocolMessageId: Int = ALICE_SENDS_SIGNATURE_TO_BOB_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(aliceIdentity),
                Encoded.of(signature),
                Encoded.of(serializedAliceDetails),
                Encoded.of(aliceDeviceUids),
            )
            }
    }


    class AlicePropagatesQrCodeMessage : ConcreteProtocolMessage {
        internal val bobIdentity: Identity
        internal val signature: ByteArray


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            bobIdentity: Identity,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.bobIdentity = bobIdentity
            this.signature = signature
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.bobIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signature = receivedMessage.inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = ALICE_PROPAGATES_QR_CODE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(bobIdentity),
                Encoded.of(signature),
            )
            }
    }

    class BobSendsConfirmationAndDetailsToAliceMessage : ConcreteProtocolMessage {
        internal val serializedBobDetails: String
        internal val bobDeviceUids: Array<UID?>


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            serializedBobDetails: String,
            bobDeviceUids: Array<UID?>
        ) : super(coreProtocolMessage!!) {
            this.serializedBobDetails = serializedBobDetails
            this.bobDeviceUids = bobDeviceUids
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 2) {
                throw Exception()
            }
            this.serializedBobDetails = receivedMessage.inputs[0].decodeString()
            this.bobDeviceUids = receivedMessage.inputs[1].decodeUidArray()
        }

        override val protocolMessageId: Int = BOB_SENDS_CONFIRMATION_AND_DETAILS_TO_ALICE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(serializedBobDetails),
                Encoded.of(bobDeviceUids),
            )
            }
    }


    class BobPropagatesSignatureMessage : ConcreteProtocolMessage {
        internal val aliceIdentity: Identity
        internal val signature: ByteArray
        internal val serializedAliceDetails: String
        internal val aliceDeviceUids: Array<UID?>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            aliceIdentity: Identity,
            signature: ByteArray,
            serializedAliceDetails: String,
            aliceDeviceUids: Array<UID?>
        ) : super(coreProtocolMessage!!) {
            this.aliceIdentity = aliceIdentity
            this.signature = signature
            this.serializedAliceDetails = serializedAliceDetails
            this.aliceDeviceUids = aliceDeviceUids
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.aliceIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.signature = receivedMessage.inputs[1].decodeBytes()
            this.serializedAliceDetails = receivedMessage.inputs[2].decodeString()
            this.aliceDeviceUids = receivedMessage.inputs[3].decodeUidArray()
        }

        override val protocolMessageId: Int = BOB_PROPAGATES_SIGNATURE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(aliceIdentity),
                Encoded.of(signature),
                Encoded.of(serializedAliceDetails),
                Encoded.of(aliceDeviceUids),
            )
            }
    }

    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            INITIAL_MESSAGE_ID -> return arrayOf<Class<*>>(
                AliceSendStep::class.java,
                AliceHandlesPropagatedQRCodeStep::class.java,
                BobAddsContactAndConfirmsStep::class.java,
                BobHandlesPropagatedSignatureStep::class.java,
            )

            WAITING_FOR_CONFIRMATION_STATE_ID -> return arrayOf<Class<*>>(AliceAddsContactStep::class.java)
            FINISHED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class AliceSendStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: TrustEstablishmentWithMutualScanProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // verify the signature
                if (!Signature.verify(
                        Constants.SignatureContext.MUTUAL_SCAN,
                        arrayOf<Identity?>(ownedIdentity, receivedMessage.contactIdentity),
                        receivedMessage.contactIdentity,
                        receivedMessage.signature
                    )
                ) {
                    return FinishedState()
                }
            }

            run {
                // send message to Bob
                val deviceUids =
                    protocolManagerSession.identityDelegate!!.getDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                val serializedAliceDetails =
                    protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAsymmetricBroadcastChannelInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = AliceSendsSignatureToBobMessage(
                    coreProtocolMessage,
                    ownedIdentity,
                    receivedMessage.signature,
                    serializedAliceDetails!!,
                    deviceUids!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // send propagate messages
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
                        val messageToSend: ChannelMessageToSend? = AlicePropagatesQrCodeMessage(
                            coreProtocolMessage,
                            receivedMessage.contactIdentity,
                            receivedMessage.signature
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

            return WaitingForConfirmationState(receivedMessage.contactIdentity)
        }
    }


    class AliceHandlesPropagatedQRCodeStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: AlicePropagatesQrCodeMessage,
        protocol: TrustEstablishmentWithMutualScanProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            run {
                // verify the signature
                if (!Signature.verify(
                        Constants.SignatureContext.MUTUAL_SCAN,
                        arrayOf<Identity?>(ownedIdentity, receivedMessage.bobIdentity),
                        receivedMessage.bobIdentity,
                        receivedMessage.signature
                    )
                ) {
                    return FinishedState()
                }
            }

            return WaitingForConfirmationState(receivedMessage.bobIdentity)
        }
    }


    class BobAddsContactAndConfirmsStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: AliceSendsSignatureToBobMessage,
        protocol: TrustEstablishmentWithMutualScanProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // verify the signature
                if (!Signature.verify(
                        Constants.SignatureContext.MUTUAL_SCAN,
                        arrayOf<Identity?>(receivedMessage.aliceIdentity, ownedIdentity),
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    return FinishedState()
                }
            }

            run {
                // verify the signature is fresh
                if (MutualScanSignatureReceived.exists(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    Logger.e("Mutual scan signature reuse!")
                    return FinishedState()
                }
            }

            run {
                // store the signature
                if (MutualScanSignatureReceived.create(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    ) == null
                ) {
                    return FinishedState()
                }
            }

            run {
                // signature is valid and fresh --> create the contact (if it does not already exists)
                if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.aliceIdentity
                    )
                ) {
                    protocolManagerSession.identityDelegate.addContactIdentity(
                        protocolManagerSession.session,
                        receivedMessage.aliceIdentity,
                        receivedMessage.serializedAliceDetails,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                } else {
                    protocolManagerSession.identityDelegate.addTrustOriginToContact(
                        protocolManagerSession.session,
                        receivedMessage.aliceIdentity,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                }

                var triggerDeviceDiscovery = false
                for (contactDeviceUid in receivedMessage.aliceDeviceUids) {
                    triggerDeviceDiscovery =
                        triggerDeviceDiscovery or protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.aliceIdentity,
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
                    val messageToSend: ChannelMessageToSend? =
                        DeviceDiscoveryProtocol.InitialMessage(
                            coreProtocolMessage,
                            receivedMessage.aliceIdentity
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // notify Alice she was added and send her our details
                val deviceUids =
                    protocolManagerSession.identityDelegate!!.getDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                val serializedBobDetails =
                    protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        receivedMessage.aliceIdentity,
                        ownedIdentity,
                        receivedMessage.aliceDeviceUids
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    BobSendsConfirmationAndDetailsToAliceMessage(
                        coreProtocolMessage,
                        serializedBobDetails!!,
                        deviceUids!!
                    ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            run {
                // propagate the message to other devices
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
                        val messageToSend: ChannelMessageToSend? = BobPropagatesSignatureMessage(
                            coreProtocolMessage,
                            receivedMessage.aliceIdentity,
                            receivedMessage.signature,
                            receivedMessage.serializedAliceDetails,
                            receivedMessage.aliceDeviceUids
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
                // send a notification so the app can automatically open the contact discussion
                protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_OWNED_IDENTITY_KEY,
                        ownedIdentity
                    )
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_CONTACT_IDENTITY_KEY,
                        receivedMessage.aliceIdentity
                    )
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY,
                        receivedMessage.signature
                    )
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED,
                        userInfo
                    )
                })
            }

            return FinishedState()
        }
    }


    class BobHandlesPropagatedSignatureStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: BobPropagatesSignatureMessage,
        protocol: TrustEstablishmentWithMutualScanProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // verify the signature
                if (!Signature.verify(
                        Constants.SignatureContext.MUTUAL_SCAN,
                        arrayOf<Identity?>(receivedMessage.aliceIdentity, ownedIdentity),
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    return FinishedState()
                }
            }

            run {
                // verify the signature is fresh
                if (MutualScanSignatureReceived.exists(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    return FinishedState()
                }
            }

            run {
                // store the signature
                if (MutualScanSignatureReceived.create(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    ) == null
                ) {
                    return FinishedState()
                }
            }

            run {
                // signature is valid and fresh --> create the contact (if it does not already exists)
                if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.aliceIdentity
                    )
                ) {
                    protocolManagerSession.identityDelegate.addContactIdentity(
                        protocolManagerSession.session,
                        receivedMessage.aliceIdentity,
                        receivedMessage.serializedAliceDetails,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                } else {
                    protocolManagerSession.identityDelegate.addTrustOriginToContact(
                        protocolManagerSession.session,
                        receivedMessage.aliceIdentity,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                }

                var triggerDeviceDiscovery = false
                for (contactDeviceUid in receivedMessage.aliceDeviceUids) {
                    triggerDeviceDiscovery =
                        triggerDeviceDiscovery or protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.aliceIdentity,
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
                    val messageToSend: ChannelMessageToSend? =
                        DeviceDiscoveryProtocol.InitialMessage(
                            coreProtocolMessage,
                            receivedMessage.aliceIdentity
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // send a notification so the app can automatically open the contact discussion
                protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo[ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_OWNED_IDENTITY_KEY] = ownedIdentity
                    userInfo[ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_CONTACT_IDENTITY_KEY] = receivedMessage.aliceIdentity
                    userInfo[ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY] = receivedMessage.signature
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED,
                        userInfo
                    )
                })
            }
            return FinishedState()
        }
    }


    class AliceAddsContactStep(
        internal val startState: WaitingForConfirmationState,
        internal val receivedMessage: BobSendsConfirmationAndDetailsToAliceMessage,
        protocol: TrustEstablishmentWithMutualScanProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // Bob added Alice to his contacts --> time for Alice to do the same
                if (!protocolManagerSession.identityDelegate!!.isIdentityAContactOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.bobIdentity
                    )
                ) {
                    protocolManagerSession.identityDelegate.addContactIdentity(
                        protocolManagerSession.session,
                        startState.bobIdentity,
                        receivedMessage.serializedBobDetails,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                } else {
                    protocolManagerSession.identityDelegate.addTrustOriginToContact(
                        protocolManagerSession.session,
                        startState.bobIdentity,
                        ownedIdentity,
                        createDirectTrustOrigin(
                            System.currentTimeMillis()
                        ),
                        true
                    )
                }

                var triggerDeviceDiscovery = false
                for (contactDeviceUid in receivedMessage.bobDeviceUids) {
                    triggerDeviceDiscovery =
                        triggerDeviceDiscovery or protocolManagerSession.identityDelegate.addDeviceForContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            startState.bobIdentity,
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
                    val messageToSend: ChannelMessageToSend? =
                        DeviceDiscoveryProtocol.InitialMessage(
                            coreProtocolMessage,
                            startState.bobIdentity
                        ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // send a notification so the app can automatically open the contact discussion
                protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo[ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_OWNED_IDENTITY_KEY] = ownedIdentity
                    userInfo[ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_CONTACT_IDENTITY_KEY] = startState.bobIdentity
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED,
                        userInfo
                    )
                })
            }
            return FinishedState()
        }
    } // endregion

    companion object {
        // region States
        const val WAITING_FOR_CONFIRMATION_STATE_ID: Int = 1
        const val FINISHED_STATE_ID: Int = 2

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val ALICE_SENDS_SIGNATURE_TO_BOB_MESSAGE_ID: Int = 1
        const val ALICE_PROPAGATES_QR_CODE_MESSAGE_ID: Int = 2
        const val BOB_SENDS_CONFIRMATION_AND_DETAILS_TO_ALICE_MESSAGE_ID: Int = 3
        const val BOB_PROPAGATES_SIGNATURE_MESSAGE_ID: Int = 4
    }
}
