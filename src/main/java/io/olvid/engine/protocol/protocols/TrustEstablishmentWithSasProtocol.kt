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
import io.olvid.engine.crypto.SAS
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createAcceptInviteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createInviteAcceptedDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createInviteSentDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createSasConfirmedDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createSasExchangeDialog
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAsymmetricBroadcastChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createDirectTrustOrigin
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.databases.TrustEstablishmentCommitmentReceived
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.util.Arrays
import java.util.UUID


class TrustEstablishmentWithSasProtocol(
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
    override val protocolId: Int = ConcreteProtocol.TRUST_ESTABLISHMENT_WITH_SAS_PROTOCOL_ID


    override val finalStateIds: IntArray = intArrayOf(CANCELLED_STATE_ID, MUTUAL_TRUST_CONFIRMED_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            WAITING_FOR_SEED_STATE_ID -> return WaitingForSeedState::class.java
            WAITING_FOR_CONFIRMATION_STATE_ID -> return WaitingForConfirmationState::class.java
            CANCELLED_STATE_ID -> return CancelledState::class.java
            WAITING_FOR_DECOMMITMENT_STATE_ID -> return WaitingForDecommitmentState::class.java
            WAITING_FOR_USER_SAS_STATE_ID -> return WaitingForUserSasState::class.java
            CONTACT_IDENTITY_TRUSTED_LEGACY_STATE_ID -> return ContactIdentityTrustedLegacyState::class.java
            MUTUAL_TRUST_CONFIRMED_STATE_ID -> return MutualTrustConfirmedState::class.java
            CONTACT_SAS_CHECKED_STATE_ID -> return ContactSasCheckedState::class.java
            else -> return null
        }
    }

    class WaitingForSeedState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val decommitment: ByteArray
        internal val seedAliceForSas: Seed
        internal val dialogUuid: UUID?

        constructor(encodedState: Encoded) : super(WAITING_FOR_SEED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.decommitment = list[1].decodeBytes()
            this.seedAliceForSas = list[2].decodeSeed()
            this.dialogUuid = list[3].decodeUuid()
        }

        internal constructor(
            contactIdentity: Identity,
            decommitment: ByteArray,
            seedAliceForSas: Seed,
            dialogUuid: UUID?
        ) : super(
            WAITING_FOR_SEED_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.decommitment = decommitment
            this.seedAliceForSas = seedAliceForSas
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(decommitment),
                    Encoded.of(seedAliceForSas),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }


    class WaitingForConfirmationState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val commitment: ByteArray
        internal val dialogUuid: UUID?

        constructor(encodedState: Encoded) : super(WAITING_FOR_CONFIRMATION_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.contactDeviceUids = list[2].decodeUidArray()
            this.commitment = list[3].decodeBytes()
            this.dialogUuid = list[4].decodeUuid()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            commitment: ByteArray,
            dialogUuid: UUID?
        ) : super(
            WAITING_FOR_CONFIRMATION_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.commitment = commitment
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactDeviceUids!!),
                    Encoded.of(commitment),
                    Encoded.of(dialogUuid)
                )
            )
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

    class WaitingForDecommitmentState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val commitment: ByteArray
        internal val seedBobForSas: Seed
        internal val dialogUuid: UUID?

        constructor(encodedState: Encoded) : super(WAITING_FOR_DECOMMITMENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.contactDeviceUids = list[2].decodeUidArray()
            this.commitment = list[3].decodeBytes()
            this.seedBobForSas = list[4].decodeSeed()
            this.dialogUuid = list[5].decodeUuid()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            commitment: ByteArray,
            seedBobForSas: Seed,
            dialogUuid: UUID?
        ) : super(
            WAITING_FOR_DECOMMITMENT_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.commitment = commitment
            this.seedBobForSas = seedBobForSas
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactDeviceUids!!),
                    Encoded.of(commitment),
                    Encoded.of(seedBobForSas),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }

    class WaitingForUserSasState : ConcreteProtocolState {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val seedForSas: Seed
        internal val contactSeedForSas: Seed
        internal val dialogUuid: UUID?
        internal val isAlice: Boolean

        constructor(encodedState: Encoded) : super(WAITING_FOR_USER_SAS_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 7) {
                throw Exception()
            }
            this.contactIdentity = list[0].decodeIdentity()
            this.contactSerializedDetails = list[1].decodeString()
            this.contactDeviceUids = list[2].decodeUidArray()
            this.seedForSas = list[3].decodeSeed()
            this.contactSeedForSas = list[4].decodeSeed()
            this.dialogUuid = list[5].decodeUuid()
            this.isAlice = list[6].decodeBoolean()
        }

        internal constructor(
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            seedForSas: Seed,
            contactSeedForSas: Seed,
            dialogUuid: UUID?,
            isAlice: Boolean
        ) : super(
            WAITING_FOR_USER_SAS_STATE_ID
        ) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.seedForSas = seedForSas
            this.contactSeedForSas = contactSeedForSas
            this.dialogUuid = dialogUuid
            this.isAlice = isAlice
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactIdentity),
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactDeviceUids!!),
                    Encoded.of(seedForSas),
                    Encoded.of(contactSeedForSas),
                    Encoded.of(dialogUuid),
                    Encoded.of(isAlice)
                )
            )
        }
    }

    class ContactIdentityTrustedLegacyState : ConcreteProtocolState {
        internal val contactSerializedDetails: String
        internal val contactIdentity: Identity
        internal val dialogUuid: UUID?

        constructor(encodedState: Encoded) : super(CONTACT_IDENTITY_TRUSTED_LEGACY_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 3) {
                throw Exception()
            }
            this.contactSerializedDetails = list[0].decodeString()
            this.contactIdentity = list[1].decodeIdentity()
            this.dialogUuid = list[2].decodeUuid()
        }

        internal constructor(
            contactSerializedDetails: String,
            contactIdentity: Identity,
            dialogUuid: UUID?
        ) : super(
            CONTACT_IDENTITY_TRUSTED_LEGACY_STATE_ID
        ) {
            Logger.e("Error: ContactIdentityTrustedLegacyState called and is deprecated.")
            this.contactSerializedDetails = contactSerializedDetails
            this.contactIdentity = contactIdentity
            this.dialogUuid = dialogUuid
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactIdentity),
                    Encoded.of(dialogUuid),
                )
            )
        }
    }

    class MutualTrustConfirmedState : ConcreteProtocolState {
        constructor(encodedState: Encoded) : super(MUTUAL_TRUST_CONFIRMED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 0) {
                throw Exception()
            }
        }

        internal constructor() : super(MUTUAL_TRUST_CONFIRMED_STATE_ID)

        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    class ContactSasCheckedState : ConcreteProtocolState {
        internal val contactSerializedDetails: String
        internal val contactIdentity: Identity
        internal val dialogUuid: UUID?
        internal val contactDeviceUids: Array<UID?>?

        constructor(encodedState: Encoded) : super(CONTACT_SAS_CHECKED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.contactSerializedDetails = list[0].decodeString()
            this.contactIdentity = list[1].decodeIdentity()
            this.dialogUuid = list[2].decodeUuid()
            this.contactDeviceUids = list[3].decodeUidArray()
        }

        internal constructor(
            contactSerializedDetails: String,
            contactIdentity: Identity,
            dialogUuid: UUID?,
            contactDeviceUids: Array<UID?>
        ) : super(
            CONTACT_SAS_CHECKED_STATE_ID
        ) {
            this.contactSerializedDetails = contactSerializedDetails
            this.contactIdentity = contactIdentity
            this.dialogUuid = dialogUuid
            this.contactDeviceUids = contactDeviceUids
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(contactSerializedDetails),
                    Encoded.of(contactIdentity),
                    Encoded.of(dialogUuid),
                    Encoded.of(contactDeviceUids!!),
                )
            )
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIAL_MESSAGE_ID -> return InitialMessage::class.java
            SEND_COMMITMENT_MESSAGE_ID -> return SendCommitmentMessage::class.java
            PROPAGATE_INVITATION_TO_ALICE_DEVICES_MESSAGE_ID -> return PropagateInvitationToAliceDevicesMessage::class.java
            PROPAGATE_COMMITMENT_TO_BOB_DEVICES_MESSAGE_ID -> return PropagateCommitmentToBobDevicesMessage::class.java
            BOB_DIALOG_INVITATION_CONFIRMATION_MESSAGE_ID -> return BobDialogInvitationConfirmationMessage::class.java
            PROPAGATE_CONFIRMATION_TO_BOB_DEVICES_MESSAGE_ID -> return PropagateConfirmationToBobDevicesMessage::class.java
            SEND_BOB_SEED_MESSAGE_ID -> return SendBobSeedMessage::class.java
            SEND_DECOMMITMENT_MESSAGE_ID -> return SendDecommitmentMessage::class.java
            DIALOG_FOR_SAS_EXCHANGE_MESSAGE_ID -> return DialogForSasExchangeMessage::class.java
            PROPAGATE_ENTERED_SAS_TO_OTHER_DEVICES_MESSAGE_ID -> return PropagateEnteredSasToOtherDevicesMessage::class.java
            MUTUAL_TRUST_CONFIRMATION_MESSAGE_ID -> return MutualTrustConfirmationMessage::class.java
            else -> return null
        }
    }

    class InitialMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactDisplayName: String
        internal val ownSerializedDetails: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactDisplayName: String,
            ownSerializedDetails: String
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactDisplayName = contactDisplayName
            this.ownSerializedDetails = ownSerializedDetails
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactDisplayName = receivedMessage.inputs[1].decodeString()
            this.ownSerializedDetails = receivedMessage.inputs[2].decodeString()
        }

        override val protocolMessageId: Int = INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactDisplayName),
                Encoded.of(ownSerializedDetails)
            )
            }
    }

    class SendCommitmentMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val commitment: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            commitment: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.commitment = commitment
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactSerializedDetails = receivedMessage.inputs[1].decodeString()
            this.contactDeviceUids = receivedMessage.inputs[2].decodeUidArray()
            this.commitment = receivedMessage.inputs[3].decodeBytes()
        }

        override val protocolMessageId: Int = SEND_COMMITMENT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactSerializedDetails),
                Encoded.of(contactDeviceUids!!),
                Encoded.of(commitment),
            )
            }
    }

    class PropagateInvitationToAliceDevicesMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactDisplayName: String
        internal val decommitment: ByteArray
        internal val seedAliceForSas: Seed

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactDisplayName: String,
            decommitment: ByteArray,
            seedAliceForSas: Seed
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactDisplayName = contactDisplayName
            this.decommitment = decommitment
            this.seedAliceForSas = seedAliceForSas
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactDisplayName = receivedMessage.inputs[1].decodeString()
            this.decommitment = receivedMessage.inputs[2].decodeBytes()
            this.seedAliceForSas = receivedMessage.inputs[3].decodeSeed()
        }

        override val protocolMessageId: Int = PROPAGATE_INVITATION_TO_ALICE_DEVICES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactDisplayName),
                Encoded.of(decommitment),
                Encoded.of(seedAliceForSas),
            )
            }
    }


    class PropagateCommitmentToBobDevicesMessage : ConcreteProtocolMessage {
        internal val contactIdentity: Identity
        internal val contactSerializedDetails: String
        internal val contactDeviceUids: Array<UID?>?
        internal val commitment: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            contactIdentity: Identity,
            contactSerializedDetails: String,
            contactDeviceUids: Array<UID?>,
            commitment: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.contactIdentity = contactIdentity
            this.contactSerializedDetails = contactSerializedDetails
            this.contactDeviceUids = contactDeviceUids
            this.commitment = commitment
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 4) {
                throw Exception()
            }
            this.contactIdentity = receivedMessage.inputs[0].decodeIdentity()
            this.contactSerializedDetails = receivedMessage.inputs[1].decodeString()
            this.contactDeviceUids = receivedMessage.inputs[2].decodeUidArray()
            this.commitment = receivedMessage.inputs[3].decodeBytes()
        }

        override val protocolMessageId: Int = PROPAGATE_COMMITMENT_TO_BOB_DEVICES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactSerializedDetails),
                Encoded.of(contactDeviceUids!!),
                Encoded.of(commitment),
            )
            }
    }


    class BobDialogInvitationConfirmationMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean
        internal val dialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            invitationAccepted = false
            dialogUuid = null
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            invitationAccepted = receivedMessage.encodedResponse.decodeBoolean()
            dialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = BOB_DIALOG_INVITATION_CONFIRMATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class PropagateConfirmationToBobDevicesMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            invitationAccepted: Boolean
        ) : super(coreProtocolMessage!!) {
            this.invitationAccepted = invitationAccepted
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.invitationAccepted = receivedMessage.inputs[0].decodeBoolean()
        }

        override val protocolMessageId: Int = PROPAGATE_CONFIRMATION_TO_BOB_DEVICES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted),
            )
            }
    }


    class SendBobSeedMessage : ConcreteProtocolMessage {
        internal val seedBobForSas: Seed
        internal val contactDeviceUids: Array<UID?>?
        internal val contactSerializedDetails: String

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            seedBobForSas: Seed,
            contactDeviceUids: Array<UID?>,
            contactSerializedDetails: String
        ) : super(coreProtocolMessage!!) {
            this.seedBobForSas = seedBobForSas
            this.contactDeviceUids = contactDeviceUids
            this.contactSerializedDetails = contactSerializedDetails
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 3) {
                throw Exception()
            }
            this.seedBobForSas = receivedMessage.inputs[0].decodeSeed()
            this.contactDeviceUids = receivedMessage.inputs[1].decodeUidArray()
            this.contactSerializedDetails = receivedMessage.inputs[2].decodeString()
        }

        override val protocolMessageId: Int = SEND_BOB_SEED_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(seedBobForSas),
                Encoded.of(contactDeviceUids!!),
                Encoded.of(contactSerializedDetails),
            )
            }
    }


    class SendDecommitmentMessage : ConcreteProtocolMessage {
        internal val decommitment: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            decommitment: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.decommitment = decommitment
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            this.decommitment = receivedMessage.inputs[0].decodeBytes()
        }

        override val protocolMessageId: Int = SEND_DECOMMITMENT_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(decommitment),
            )
            }
    }


    class DialogForSasExchangeMessage : ConcreteProtocolMessage {
        internal val sasEnteredByUser: ByteArray? // Only set when the message is sent to this protocol, not when sending this message to the UI
        internal val userDialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            this.sasEnteredByUser = null
            this.userDialogUuid = null
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            sasEnteredByUser = receivedMessage.encodedResponse.decodeBytes()
            userDialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = DIALOG_FOR_SAS_EXCHANGE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class PropagateEnteredSasToOtherDevicesMessage : ConcreteProtocolMessage {
        internal val sasEnteredByUser: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            sasEnteredByUser: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.sasEnteredByUser = sasEnteredByUser
        }

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 1) {
                throw Exception()
            }
            sasEnteredByUser = receivedMessage.inputs[0].decodeBytes()
        }

        override val protocolMessageId: Int = PROPAGATE_ENTERED_SAS_TO_OTHER_DEVICES_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(sasEnteredByUser),
            )
            }
    }


    class MutualTrustConfirmationMessage : ConcreteProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = MUTUAL_TRUST_CONFIRMATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    // endregion
    // region Steps
    public override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                SendCommitmentStep::class.java,
                StoreDecommitmentStep::class.java,
                StoreAndPropagateCommitmentAndAskForConfirmationStep::class.java,
                StoreCommitmentAndAskForConfirmationStep::class.java,
            )

            WAITING_FOR_CONFIRMATION_STATE_ID -> return arrayOf<Class<*>>(
                SendSeedAndPropagateConfirmationStep::class.java,
                ReceivedConfirmationFromOtherDeviceStep::class.java,
            )

            WAITING_FOR_SEED_STATE_ID -> return arrayOf<Class<*>>(
                ShowSasDialogAndSendDecommitmentStep::class.java
            )

            WAITING_FOR_DECOMMITMENT_STATE_ID -> return arrayOf<Class<*>>(ShowSasDialogStep::class.java)
            WAITING_FOR_USER_SAS_STATE_ID -> return arrayOf<Class<*>>(
                CheckPropagatedSasStep::class.java,
                CheckSasStep::class.java,
            )

            CONTACT_IDENTITY_TRUSTED_LEGACY_STATE_ID -> return arrayOf<Class<*>>(
                NotifiedMutualTrustEstablishedLegacyStep::class.java
            )

            CONTACT_SAS_CHECKED_STATE_ID -> return arrayOf<Class<*>>(AddTrustStep::class.java)
            CANCELLED_STATE_ID, MUTUAL_TRUST_CONFIRMED_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }


    class SendCommitmentStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitialMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val ownedDeviceUids =
                protocolManagerSession.identityDelegate!!.getDeviceUidsOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            val dialogUuid = UUID.randomUUID()

            val seedAliceForSas = Seed(prng)
            val commitmentScheme = Suite.getDefaultCommitment(0)
            val commitmentOutput = commitmentScheme.commit(
                ownedIdentity.getBytes(),
                seedAliceForSas.bytes,
                prng
            )

            run {
                // Display invite sent dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createInviteSentDialog(
                            receivedMessage.contactDisplayName,
                            receivedMessage.contactIdentity
                        ),
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

            run {
                // Propagate invitation to other owned devices
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
                            PropagateInvitationToAliceDevicesMessage(
                                coreProtocolMessage,
                                receivedMessage.contactIdentity,
                                receivedMessage.contactDisplayName,
                                commitmentOutput.decommitment,
                                seedAliceForSas
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
                // Broadcast commitment to Bob
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAsymmetricBroadcastChannelInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity
                    )
                )
                val messageToSend: ChannelMessageToSend? = SendCommitmentMessage(
                    coreProtocolMessage,
                    ownedIdentity,
                    receivedMessage.ownSerializedDetails,
                    ownedDeviceUids!!,
                    commitmentOutput.commitment
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForSeedState(
                receivedMessage.contactIdentity,
                commitmentOutput.decommitment,
                seedAliceForSas,
                dialogUuid
            )
        }
    }


    class StoreDecommitmentStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateInvitationToAliceDevicesMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val dialogUuid = UUID.randomUUID()

            run {
                // Display invite sent dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createInviteSentDialog(
                            receivedMessage.contactDisplayName,
                            receivedMessage.contactIdentity
                        ),
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

            return WaitingForSeedState(
                receivedMessage.contactIdentity,
                receivedMessage.decommitment,
                receivedMessage.seedAliceForSas,
                dialogUuid
            )
        }
    }


    class StoreAndPropagateCommitmentAndAskForConfirmationStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: SendCommitmentMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (TrustEstablishmentCommitmentReceived.exists(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.commitment
                )
            ) {
                // we already received this commitment
                return CancelledState()
            } else {
                // store the commitment to prevent future replay
                TrustEstablishmentCommitmentReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.commitment
                )
            }

            val dialogUuid = UUID.randomUUID()

            run {
                // Display invite received dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createAcceptInviteDialog(
                            receivedMessage.contactSerializedDetails,
                            receivedMessage.contactIdentity,
                            receivedMessage.serverTimestamp
                        ),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    BobDialogInvitationConfirmationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // Propagate invitation to other owned devices
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
                            PropagateCommitmentToBobDevicesMessage(
                                coreProtocolMessage,
                                receivedMessage.contactIdentity,
                                receivedMessage.contactSerializedDetails,
                                receivedMessage.contactDeviceUids!!,
                                receivedMessage.commitment
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

            return WaitingForConfirmationState(
                receivedMessage.contactIdentity,
                receivedMessage.contactSerializedDetails,
                receivedMessage.contactDeviceUids!!,
                receivedMessage.commitment,
                dialogUuid
            )
        }
    }


    class StoreCommitmentAndAskForConfirmationStep(
        internal val startState: InitialProtocolState?,
        internal val receivedMessage: PropagateCommitmentToBobDevicesMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (TrustEstablishmentCommitmentReceived.exists(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.commitment
                )
            ) {
                // we already received this commitment
                return CancelledState()
            } else {
                // store the commitment to prevent future replay
                TrustEstablishmentCommitmentReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.commitment
                )
            }

            val dialogUuid = UUID.randomUUID()
            run {
                // Display invite received dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createAcceptInviteDialog(
                            receivedMessage.contactSerializedDetails,
                            receivedMessage.contactIdentity,
                            receivedMessage.serverTimestamp
                        ),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    BobDialogInvitationConfirmationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForConfirmationState(
                receivedMessage.contactIdentity,
                receivedMessage.contactSerializedDetails,
                receivedMessage.contactDeviceUids!!,
                receivedMessage.commitment,
                dialogUuid
            )
        }
    }


    class SendSeedAndPropagateConfirmationStep(
        internal val startState: WaitingForConfirmationState,
        internal val receivedMessage: BobDialogInvitationConfirmationMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (startState.dialogUuid != receivedMessage.dialogUuid) {
                Logger.e("ObvDialog uuid mismatch in BobDialogInvitationConfirmationMessage.")
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
                        val messageToSend: ChannelMessageToSend? =
                            PropagateConfirmationToBobDevicesMessage(
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

            // if invitation was rejected, Cancel
            if (!receivedMessage.invitationAccepted) {
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

                return CancelledState()
            }

            run {
                // Display invitation accepted dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createInviteAcceptedDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity
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

            val seedBobForSas =
                protocolManagerSession.identityDelegate!!.getDeterministicSeedForOwnedIdentity(
                    ownedIdentity,
                    startState.commitment,
                    IdentityDelegate.DeterministicSeedContext.COMPUTE_SAS
                )
            val ownedDeviceUids =
                protocolManagerSession.identityDelegate.getDeviceUidsOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            val ownSerializedDetails =
                protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            run {
                // send the seed to Alice
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        startState.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? = SendBobSeedMessage(
                    coreProtocolMessage,
                    seedBobForSas!!,
                    ownedDeviceUids!!,
                    ownSerializedDetails!!
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForDecommitmentState(
                startState.contactIdentity,
                startState.contactSerializedDetails,
                startState.contactDeviceUids!!,
                startState.commitment,
                seedBobForSas!!,
                startState.dialogUuid
            )
        }
    }

    class ReceivedConfirmationFromOtherDeviceStep(
        internal val startState: WaitingForConfirmationState,
        internal val receivedMessage: PropagateConfirmationToBobDevicesMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // if invitation was rejected, Cancel
            if (!receivedMessage.invitationAccepted) {
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

                return CancelledState()
            }

            run {
                // Display invitation accepted dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createInviteAcceptedDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity
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

            val seedBobForSas =
                protocolManagerSession.identityDelegate!!.getDeterministicSeedForOwnedIdentity(
                    ownedIdentity,
                    startState.commitment,
                    IdentityDelegate.DeterministicSeedContext.COMPUTE_SAS
                )

            return WaitingForDecommitmentState(
                startState.contactIdentity,
                startState.contactSerializedDetails,
                startState.contactDeviceUids!!,
                startState.commitment,
                seedBobForSas!!,
                startState.dialogUuid
            )
        }
    }


    class ShowSasDialogAndSendDecommitmentStep(
        internal val startState: WaitingForSeedState,
        internal val receivedMessage: SendBobSeedMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // send decommitment to Bob's devices
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        receivedMessage.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? = SendDecommitmentMessage(
                    coreProtocolMessage,
                    startState.decommitment
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            val fullSas = SAS.computeDouble(
                startState.seedAliceForSas,
                receivedMessage.seedBobForSas,
                startState.contactIdentity,
                Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
            )
            val sasToDisplay =
                Arrays.copyOfRange(fullSas, 0, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)

            run {
                // display sas exchange dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createSasExchangeDialog(
                            receivedMessage.contactSerializedDetails,
                            startState.contactIdentity,
                            sasToDisplay,
                            receivedMessage.serverTimestamp
                        ),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DialogForSasExchangeMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForUserSasState(
                startState.contactIdentity,
                receivedMessage.contactSerializedDetails,
                receivedMessage.contactDeviceUids!!,
                startState.seedAliceForSas,
                receivedMessage.seedBobForSas,
                startState.dialogUuid,
                true
            )
        }
    }


    class ShowSasDialogStep(
        internal val startState: WaitingForDecommitmentState,
        internal val receivedMessage: SendDecommitmentMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            val commitmentScheme = Suite.getDefaultCommitment(0)
            val opened = commitmentScheme.open(
                startState.contactIdentity.getBytes(),
                startState.commitment,
                receivedMessage.decommitment
            )
            if (opened == null) {
                Logger.e("Unable to open commitment.")
                return null
            }
            val contactSeedForSas = Seed(opened)
            val fullSas = SAS.computeDouble(
                contactSeedForSas,
                startState.seedBobForSas,
                ownedIdentity,
                Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
            )
            val sasToDisplay = Arrays.copyOfRange(
                fullSas,
                Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS,
                2 * Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
            )

            run {
                // display sas exchange dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createSasExchangeDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity,
                            sasToDisplay,
                            receivedMessage.serverTimestamp
                        ),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DialogForSasExchangeMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return WaitingForUserSasState(
                startState.contactIdentity,
                startState.contactSerializedDetails,
                startState.contactDeviceUids!!,
                startState.seedBobForSas,
                contactSeedForSas,
                startState.dialogUuid,
                false
            )
        }
    }


    class CheckSasStep(
        internal val startState: WaitingForUserSasState,
        internal val receivedMessage: DialogForSasExchangeMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (startState.dialogUuid != receivedMessage.userDialogUuid) {
                Logger.e("ObvDialog uuid mismatch in DialogForSasExchangeMessage.")
                return null
            }

            val sasToDisplay: ByteArray?
            val computedSas: ByteArray?

            if (startState.isAlice) {
                val fullSas = SAS.computeDouble(
                    startState.seedForSas,
                    startState.contactSeedForSas,
                    startState.contactIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                sasToDisplay =
                    Arrays.copyOfRange(fullSas, 0, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)
                computedSas = Arrays.copyOfRange(
                    fullSas,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS,
                    2 * Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
            } else {
                val fullSas = SAS.computeDouble(
                    startState.contactSeedForSas,
                    startState.seedForSas,
                    ownedIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                sasToDisplay = Arrays.copyOfRange(
                    fullSas,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS,
                    2 * Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                computedSas =
                    Arrays.copyOfRange(fullSas, 0, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)
            }

            if (!computedSas.contentEquals(receivedMessage.sasEnteredByUser)) {
                Logger.d("The SAS entered by the user does not match the computed SAS.")
                // re-display the sas exchange dialog and remain in the same state
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createSasExchangeDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity,
                            sasToDisplay,
                            System.currentTimeMillis()
                        ),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DialogForSasExchangeMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
                return startState
            }

            run {
                // propagate the entered sas to other owned devices
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
                            PropagateEnteredSasToOtherDevicesMessage(
                                coreProtocolMessage,
                                receivedMessage.sasEnteredByUser!!
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
                // display the sas confirmed dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createSasConfirmedDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity,
                            sasToDisplay,
                            receivedMessage.sasEnteredByUser
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
                // notify the other party's devices that they are now ready to be trusted.
                val coreProtocolMessage = buildCoreProtocolMessage(
                    SendChannelInfo.createAsymmetricChannelInfo(
                        startState.contactIdentity,
                        ownedIdentity,
                        startState.contactDeviceUids!!
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    MutualTrustConfirmationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return ContactSasCheckedState(
                startState.contactSerializedDetails,
                startState.contactIdentity,
                startState.dialogUuid,
                startState.contactDeviceUids!!
            )
        }
    }


    class CheckPropagatedSasStep(
        internal val startState: WaitingForUserSasState,
        internal val receivedMessage: PropagateEnteredSasToOtherDevicesMessage,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            val sasToDisplay: ByteArray?
            val computedSas: ByteArray?

            if (startState.isAlice) {
                val fullSas = SAS.computeDouble(
                    startState.seedForSas,
                    startState.contactSeedForSas,
                    startState.contactIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                sasToDisplay =
                    Arrays.copyOfRange(fullSas, 0, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)
                computedSas = Arrays.copyOfRange(
                    fullSas,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS,
                    2 * Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
            } else {
                val fullSas = SAS.computeDouble(
                    startState.contactSeedForSas,
                    startState.seedForSas,
                    ownedIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                sasToDisplay = Arrays.copyOfRange(
                    fullSas,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS,
                    2 * Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
                computedSas =
                    Arrays.copyOfRange(fullSas, 0, Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS)
            }

            if (!computedSas.contentEquals(receivedMessage.sasEnteredByUser)) {
                Logger.e("The propagated SAS does not match the computed SAS.")

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

                return CancelledState()
            }

            run {
                // display the sas confirmed dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createSasConfirmedDialog(
                            startState.contactSerializedDetails,
                            startState.contactIdentity,
                            sasToDisplay,
                            receivedMessage.sasEnteredByUser
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

            return ContactSasCheckedState(
                startState.contactSerializedDetails,
                startState.contactIdentity,
                startState.dialogUuid,
                startState.contactDeviceUids!!
            )
        }
    }


    class NotifiedMutualTrustEstablishedLegacyStep(
        internal val startState: ContactIdentityTrustedLegacyState,
        internal val receivedMessage: MutualTrustConfirmationMessage?,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
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

            return MutualTrustConfirmedState()
        }
    }


    class AddTrustStep(
        internal val startState: ContactSasCheckedState,
        @field:Suppress("unused") internal val receivedMessage: MutualTrustConfirmationMessage?,
        protocol: TrustEstablishmentWithSasProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createAsymmetricChannelInfo(),
        receivedMessage!!, protocol!!
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
                    createDirectTrustOrigin(
                        System.currentTimeMillis()
                    ),
                    true
                )
            } else {
                protocolManagerSession.identityDelegate.addTrustOriginToContact(
                    protocolManagerSession.session,
                    startState.contactIdentity,
                    ownedIdentity,
                    createDirectTrustOrigin(
                        System.currentTimeMillis()
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


            run {
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

            return MutualTrustConfirmedState()
        }
    } // endregion

    companion object {
        // region States
        // Alice's side
        const val WAITING_FOR_SEED_STATE_ID: Int = 1

        // Bob's side
        const val WAITING_FOR_CONFIRMATION_STATE_ID: Int = 2
        const val CANCELLED_STATE_ID: Int = 3
        const val WAITING_FOR_DECOMMITMENT_STATE_ID: Int = 4

        // Alice and Bob's side
        const val WAITING_FOR_USER_SAS_STATE_ID: Int = 5
        const val CONTACT_IDENTITY_TRUSTED_LEGACY_STATE_ID: Int = 6
        const val MUTUAL_TRUST_CONFIRMED_STATE_ID: Int = 7
        const val CONTACT_SAS_CHECKED_STATE_ID: Int = 8

        // endregion
        // region Messages
        const val INITIAL_MESSAGE_ID: Int = 0
        const val SEND_COMMITMENT_MESSAGE_ID: Int = 1
        const val PROPAGATE_INVITATION_TO_ALICE_DEVICES_MESSAGE_ID: Int = 2
        const val PROPAGATE_COMMITMENT_TO_BOB_DEVICES_MESSAGE_ID: Int = 4
        const val BOB_DIALOG_INVITATION_CONFIRMATION_MESSAGE_ID: Int = 5
        const val PROPAGATE_CONFIRMATION_TO_BOB_DEVICES_MESSAGE_ID: Int = 6
        const val SEND_BOB_SEED_MESSAGE_ID: Int = 8
        const val SEND_DECOMMITMENT_MESSAGE_ID: Int = 9
        const val DIALOG_FOR_SAS_EXCHANGE_MESSAGE_ID: Int = 10
        const val PROPAGATE_ENTERED_SAS_TO_OTHER_DEVICES_MESSAGE_ID: Int = 12
        const val MUTUAL_TRUST_CONFIRMATION_MESSAGE_ID: Int = 13
    }
}
