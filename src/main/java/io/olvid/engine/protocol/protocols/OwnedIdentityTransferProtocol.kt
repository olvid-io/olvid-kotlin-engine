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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.SAS
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.PrivateIdentity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createTransferDialog
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.TransferCloseQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferRelayQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferSourceQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferTargetQuery
import io.olvid.engine.datatypes.containers.ServerQuery.TransferWaitQuery
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvDeviceManagementRequest
import io.olvid.engine.engine.types.ObvTransferStep
import io.olvid.engine.engine.types.ObvTransferStep.OngoingProtocol
import io.olvid.engine.engine.types.ObvTransferStep.SourceDisplaySessionNumber
import io.olvid.engine.engine.types.ObvTransferStep.SourceSasInput
import io.olvid.engine.engine.types.ObvTransferStep.SourceSnapshotSent
import io.olvid.engine.engine.types.ObvTransferStep.SourceWaitForSessionNumberStep
import io.olvid.engine.engine.types.ObvTransferStep.TargetRequestsKeycloakAuthenticationProof
import io.olvid.engine.engine.types.ObvTransferStep.TargetSessionNumberInput
import io.olvid.engine.engine.types.ObvTransferStep.TargetShowSas
import io.olvid.engine.engine.types.ObvTransferStep.TargetSnapshotReceived
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback
import io.olvid.engine.engine.types.sync.ObvSyncSnapshot
import io.olvid.engine.identity.databases.sync.IdentityManagerSyncSnapshot
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSession
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocolState
import io.olvid.engine.protocol.protocol_engine.EmptyProtocolMessage
import io.olvid.engine.protocol.protocol_engine.InitialProtocolState
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolStep
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID

class OwnedIdentityTransferProtocol(
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
    override val protocolId: Int = ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID

    override val finalStateIds: IntArray = intArrayOf(FINAL_STATE_ID)

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            SOURCE_WAITING_FOR_SESSION_NUMBER_STATE_ID -> return SourceWaitingForSessionNumberState::class.java
            SOURCE_WAITING_FOR_TARGET_CONNECTION_STATE_ID -> return SourceWaitingForTargetConnectionState::class.java
            TARGET_WAITING_FOR_SESSION_NUMBER_STATE_ID -> return TargetWaitingForSessionNumberState::class.java
            TARGET_WAITING_FOR_TRANSFERRED_IDENTITY_STATE_ID -> return TargetWaitingForTransferredIdentityState::class.java
            SOURCE_WAITING_FOR_TARGET_SEED_STATE_ID -> return SourceWaitingForTargetSeedState::class.java
            TARGET_WAITING_FOR_DECOMMITMENT_STATE_ID -> return TargetWaitingForDecommitmentState::class.java
            SOURCE_WAITING_FOR_SAS_INPUT_STATE_ID -> return SourceWaitingForSasInputState::class.java
            TARGET_WAITING_FOR_SNAPSHOT_STATE_ID -> return TargetWaitingForSnapshotState::class.java
            SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID -> return SourceWaitForKeycloakAuthenticationProofState::class.java
            TARGET_WAITING_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID -> return TargetWaitingForKeycloakAuthenticationProofState::class.java
            FINAL_STATE_ID -> return FinalState::class.java
            else -> return null
        }
    }

    class SourceWaitingForSessionNumberState : ConcreteProtocolState {
        internal val dialogUuid: UUID?

        constructor(dialogUuid: UUID?) : super(SOURCE_WAITING_FOR_SESSION_NUMBER_STATE_ID) {
            this.dialogUuid = dialogUuid
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(SOURCE_WAITING_FOR_SESSION_NUMBER_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 1) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                )
            )
        }
    }


    class SourceWaitingForTargetConnectionState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val ownConnectionIdentifier: String
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            ownConnectionIdentifier: String,
            sessionNumber: Long
        ) : super(
            SOURCE_WAITING_FOR_TARGET_CONNECTION_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.ownConnectionIdentifier = ownConnectionIdentifier
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(SOURCE_WAITING_FOR_TARGET_CONNECTION_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 3) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.ownConnectionIdentifier = list[1].decodeString()
            this.sessionNumber = list[2].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(ownConnectionIdentifier),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }

    class TargetWaitingForSessionNumberState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val deviceName: String
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?

        constructor(
            dialogUuid: UUID?,
            deviceName: String,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?
        ) : super(
            TARGET_WAITING_FOR_SESSION_NUMBER_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.deviceName = deviceName
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(TARGET_WAITING_FOR_SESSION_NUMBER_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.deviceName = list[1].decodeString()
            this.serverAuthenticationPrivateKey =
                list[2].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[3].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[4].decodeSymmetricKey() as MACKey?
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(deviceName),
                    Encoded.of(serverAuthenticationPrivateKey!!),
                    Encoded.of(encryptionPrivateKey!!),
                    Encoded.of(macKey!!),
                )
            )
        }
    }


    class TargetWaitingForTransferredIdentityState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val deviceName: String
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            deviceName: String,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?,
            sessionNumber: Long
        ) : super(
            TARGET_WAITING_FOR_TRANSFERRED_IDENTITY_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.deviceName = deviceName
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(TARGET_WAITING_FOR_TRANSFERRED_IDENTITY_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.deviceName = list[1].decodeString()
            this.serverAuthenticationPrivateKey =
                list[2].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[3].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[4].decodeSymmetricKey() as MACKey?
            this.sessionNumber = list[5].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(deviceName),
                    Encoded.of(serverAuthenticationPrivateKey!!),
                    Encoded.of(encryptionPrivateKey!!),
                    Encoded.of(macKey!!),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }


    class SourceWaitingForTargetSeedState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val otherConnectionIdentifier: String
        internal val ephemeralIdentity: Identity
        internal val seedSourceForSas: Seed
        internal val decommitment: ByteArray
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            otherConnectionIdentifier: String,
            ephemeralIdentity: Identity,
            seedSourceForSas: Seed,
            decommitment: ByteArray,
            sessionNumber: Long
        ) : super(
            SOURCE_WAITING_FOR_TARGET_SEED_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.ephemeralIdentity = ephemeralIdentity
            this.seedSourceForSas = seedSourceForSas
            this.decommitment = decommitment
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(SOURCE_WAITING_FOR_TARGET_SEED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.otherConnectionIdentifier = list[1].decodeString()
            this.ephemeralIdentity = list[2].decodeIdentity()
            this.seedSourceForSas = list[3].decodeSeed()
            this.decommitment = list[4].decodeBytes()
            this.sessionNumber = list[5].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(otherConnectionIdentifier),
                    Encoded.of(ephemeralIdentity),
                    Encoded.of(seedSourceForSas),
                    Encoded.of(decommitment),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }


    class TargetWaitingForDecommitmentState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val deviceName: String
        internal val otherConnectionIdentifier: String
        internal val transferredIdentity: Identity
        internal val commitment: ByteArray
        internal val seedTargetForSas: Seed
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            deviceName: String,
            otherConnectionIdentifier: String,
            transferredIdentity: Identity,
            commitment: ByteArray,
            seedTargetForSas: Seed,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?,
            sessionNumber: Long
        ) : super(
            TARGET_WAITING_FOR_DECOMMITMENT_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.deviceName = deviceName
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.transferredIdentity = transferredIdentity
            this.commitment = commitment
            this.seedTargetForSas = seedTargetForSas
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(TARGET_WAITING_FOR_DECOMMITMENT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 10) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.deviceName = list[1].decodeString()
            this.otherConnectionIdentifier = list[2].decodeString()
            this.transferredIdentity = list[3].decodeIdentity()
            this.commitment = list[4].decodeBytes()
            this.seedTargetForSas = list[5].decodeSeed()
            this.serverAuthenticationPrivateKey =
                list[6].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[7].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[8].decodeSymmetricKey() as MACKey?
            this.sessionNumber = list[9].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(deviceName),
                    Encoded.of(otherConnectionIdentifier),
                    Encoded.of(transferredIdentity),
                    Encoded.of(commitment),
                    Encoded.of(seedTargetForSas),
                    Encoded.of(serverAuthenticationPrivateKey!!),
                    Encoded.of(encryptionPrivateKey!!),
                    Encoded.of(macKey!!),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }


    class SourceWaitingForSasInputState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val otherConnectionIdentifier: String
        internal val targetDeviceName: String
        internal val ephemeralIdentity: Identity
        internal val fullSas: String
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            otherConnectionIdentifier: String,
            targetDeviceName: String,
            ephemeralIdentity: Identity,
            fullSas: String,
            sessionNumber: Long
        ) : super(
            SOURCE_WAITING_FOR_SAS_INPUT_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.targetDeviceName = targetDeviceName
            this.ephemeralIdentity = ephemeralIdentity
            this.fullSas = fullSas
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(SOURCE_WAITING_FOR_SAS_INPUT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.otherConnectionIdentifier = list[1].decodeString()
            this.targetDeviceName = list[2].decodeString()
            this.ephemeralIdentity = list[3].decodeIdentity()
            this.fullSas = list[4].decodeString()
            this.sessionNumber = list[5].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(otherConnectionIdentifier),
                    Encoded.of(targetDeviceName),
                    Encoded.of(ephemeralIdentity),
                    Encoded.of(fullSas),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }

    class SourceWaitForKeycloakAuthenticationProofState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val otherConnectionIdentifier: String
        internal val ephemeralIdentity: Identity
        internal val fullSas: String
        internal val sessionNumber: Long
        internal val deviceUidToKeepActive: UID? // may be null

        constructor(
            dialogUuid: UUID?,
            otherConnectionIdentifier: String,
            ephemeralIdentity: Identity,
            fullSas: String,
            sessionNumber: Long,
            deviceUidToKeepActive: UID?
        ) : super(
            SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.ephemeralIdentity = ephemeralIdentity
            this.fullSas = fullSas
            this.sessionNumber = sessionNumber
            this.deviceUidToKeepActive = deviceUidToKeepActive
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(
            SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID
        ) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6 && list.size != 5) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.otherConnectionIdentifier = list[1].decodeString()
            this.ephemeralIdentity = list[2].decodeIdentity()
            this.fullSas = list[3].decodeString()
            this.sessionNumber = list[4].decodeLong()
            if (list.size == 6) {
                this.deviceUidToKeepActive = list[5].decodeUid()
            } else {
                this.deviceUidToKeepActive = null
            }
        }

        override fun encode(): Encoded {
            if (deviceUidToKeepActive != null) {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(dialogUuid),
                        Encoded.of(otherConnectionIdentifier),
                        Encoded.of(ephemeralIdentity),
                        Encoded.of(fullSas),
                        Encoded.of(sessionNumber),
                        Encoded.of(deviceUidToKeepActive),
                    )
                )
            } else {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(dialogUuid),
                        Encoded.of(otherConnectionIdentifier),
                        Encoded.of(ephemeralIdentity),
                        Encoded.of(fullSas),
                        Encoded.of(sessionNumber),
                    )
                )
            }
        }
    }

    class TargetWaitingForKeycloakAuthenticationProofState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val deviceName: String
        internal val otherConnectionIdentifier: String
        internal val transferredIdentity: Identity
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?
        internal val fullSas: String
        internal val sessionNumber: Long

        constructor(
            dialogUuid: UUID?,
            deviceName: String,
            otherConnectionIdentifier: String,
            transferredIdentity: Identity,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?,
            fullSas: String,
            sessionNumber: Long
        ) : super(
            TARGET_WAITING_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.deviceName = deviceName
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.transferredIdentity = transferredIdentity
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
            this.fullSas = fullSas
            this.sessionNumber = sessionNumber
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(
            TARGET_WAITING_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID
        ) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 9) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.deviceName = list[1].decodeString()
            this.otherConnectionIdentifier = list[2].decodeString()
            this.transferredIdentity = list[3].decodeIdentity()
            this.serverAuthenticationPrivateKey =
                list[4].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[5].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[6].decodeSymmetricKey() as MACKey?
            this.fullSas = list[7].decodeString()
            this.sessionNumber = list[8].decodeLong()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(dialogUuid),
                    Encoded.of(deviceName),
                    Encoded.of(otherConnectionIdentifier),
                    Encoded.of(transferredIdentity),
                    Encoded.of(serverAuthenticationPrivateKey!!),
                    Encoded.of(encryptionPrivateKey!!),
                    Encoded.of(macKey!!),
                    Encoded.of(fullSas),
                    Encoded.of(sessionNumber),
                )
            )
        }
    }


    class TargetWaitingForSnapshotState : ConcreteProtocolState {
        internal val dialogUuid: UUID?
        internal val deviceName: String
        internal val otherConnectionIdentifier: String
        internal val transferredIdentity: Identity
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?
        internal val fullSas: String
        internal val sessionNumber: Long
        internal val serializedKeycloakAuthState: String? // non-null only after getting an transfer proof from keycloak

        constructor(
            dialogUuid: UUID?,
            deviceName: String,
            otherConnectionIdentifier: String,
            transferredIdentity: Identity,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?,
            fullSas: String,
            sessionNumber: Long,
            serializedKeycloakAuthState: String?
        ) : super(
            TARGET_WAITING_FOR_SNAPSHOT_STATE_ID
        ) {
            this.dialogUuid = dialogUuid
            this.deviceName = deviceName
            this.otherConnectionIdentifier = otherConnectionIdentifier
            this.transferredIdentity = transferredIdentity
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
            this.fullSas = fullSas
            this.sessionNumber = sessionNumber
            this.serializedKeycloakAuthState = serializedKeycloakAuthState
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(TARGET_WAITING_FOR_SNAPSHOT_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 10 && list.size != 9) {
                throw Exception()
            }
            this.dialogUuid = list[0].decodeUuid()
            this.deviceName = list[1].decodeString()
            this.otherConnectionIdentifier = list[2].decodeString()
            this.transferredIdentity = list[3].decodeIdentity()
            this.serverAuthenticationPrivateKey =
                list[4].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[5].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[6].decodeSymmetricKey() as MACKey?
            this.fullSas = list[7].decodeString()
            this.sessionNumber = list[8].decodeLong()
            if (list.size == 10) {
                this.serializedKeycloakAuthState = list[9].decodeString()
            } else {
                this.serializedKeycloakAuthState = null
            }
        }

        override fun encode(): Encoded {
            if (serializedKeycloakAuthState == null) {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(dialogUuid),
                        Encoded.of(deviceName),
                        Encoded.of(otherConnectionIdentifier),
                        Encoded.of(transferredIdentity),
                        Encoded.of(serverAuthenticationPrivateKey!!),
                        Encoded.of(encryptionPrivateKey!!),
                        Encoded.of(macKey!!),
                        Encoded.of(fullSas),
                        Encoded.of(sessionNumber),
                    )
                )
            } else {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(dialogUuid),
                        Encoded.of(deviceName),
                        Encoded.of(otherConnectionIdentifier),
                        Encoded.of(transferredIdentity),
                        Encoded.of(serverAuthenticationPrivateKey!!),
                        Encoded.of(encryptionPrivateKey!!),
                        Encoded.of(macKey!!),
                        Encoded.of(fullSas),
                        Encoded.of(sessionNumber),
                        Encoded.of(serializedKeycloakAuthState),
                    )
                )
            }
        }
    }


    class FinalState : ConcreteProtocolState(FINAL_STATE_ID) {
        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            INITIATE_TRANSFER_ON_SOURCE_DEVICE_MESSAGE_ID -> return InitiateTransferOnSourceDeviceMessage::class.java
            INITIATE_TRANSFER_ON_TARGET_DEVICE_MESSAGE_ID -> return InitiateTransferOnTargetDeviceMessage::class.java
            SOURCE_GET_SESSION_NUMBER_MESSAGE_ID -> return SourceGetSessionNumberMessage::class.java
            ABORTABLE_ONE_WAY_DIALOG_MESSAGE_ID -> return AbortableOneWayDialogMessage::class.java
            SOURCE_WAIT_FOR_TARGET_CONNECTION_MESSAGE_ID -> return SourceWaitForTargetConnectionMessage::class.java
            TARGET_GET_SESSION_NUMBER_MESSAGE_ID -> return TargetGetSessionNumberMessage::class.java
            TARGET_SEND_EPHEMERAL_IDENTITY_MESSAGE_ID -> return TargetSendEphemeralIdentityMessage::class.java
            SOURCE_SEND_COMMITMENT_MESSAGE_ID -> return SourceSendCommitmentMessage::class.java
            TARGET_SEED_MESSAGE_ID -> return TargetSeedMessage::class.java
            SOURCE_SAS_INPUT_MESSAGE_ID -> return SourceSasInputMessage::class.java
            SOURCE_DECOMMITMENT_MESSAGE_ID -> return SourceDecommitmentMessage::class.java
            TARGET_WAIT_FOR_SNAPSHOT_MESSAGE_ID -> return TargetWaitForSnapshotMessage::class.java
            SOURCE_SNAPSHOT_MESSAGE_ID -> return SourceSnapshotMessage::class.java
            SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID -> return SourceWaitForKeycloakAuthenticationProofMessage::class.java
            TARGET_RETRIEVE_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID -> return TargetRetrieveKeycloakAuthenticationProofMessage::class.java
            else -> return null
        }
    }

    class InitiateTransferOnSourceDeviceMessage : ConcreteProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = INITIATE_TRANSFER_ON_SOURCE_DEVICE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class InitiateTransferOnTargetDeviceMessage : ConcreteProtocolMessage {
        internal val deviceName: String
        internal val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
        internal val encryptionPrivateKey: EncryptionPrivateKey?
        internal val macKey: MACKey?

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            deviceName: String,
            serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey?,
            encryptionPrivateKey: EncryptionPrivateKey?,
            macKey: MACKey?
        ) : super(coreProtocolMessage!!) {
            this.deviceName = deviceName
            this.serverAuthenticationPrivateKey = serverAuthenticationPrivateKey
            this.encryptionPrivateKey = encryptionPrivateKey
            this.macKey = macKey
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 4) {
                throw Exception()
            }
            this.deviceName = list[0].decodeString()
            this.serverAuthenticationPrivateKey =
                list[1].decodePrivateKey() as ServerAuthenticationPrivateKey?
            this.encryptionPrivateKey = list[2].decodePrivateKey() as EncryptionPrivateKey?
            this.macKey = list[3].decodeSymmetricKey() as MACKey?
        }


        override val protocolMessageId: Int = INITIATE_TRANSFER_ON_TARGET_DEVICE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(deviceName),
                Encoded.of(serverAuthenticationPrivateKey!!),
                Encoded.of(encryptionPrivateKey!!),
                Encoded.of(macKey!!),
            )
            }
    }


    class SourceGetSessionNumberMessage : EmptyProtocolMessage {
        internal val serializedJsonResponseSource: String?

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            serializedJsonResponseSource = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            serializedJsonResponseSource =
                if (receivedMessage.encodedResponse == null) null else receivedMessage.encodedResponse
                    .decodeString()
        }

        override val protocolMessageId: Int = SOURCE_GET_SESSION_NUMBER_MESSAGE_ID
    }

    abstract class WaitOrRelayMessage : EmptyProtocolMessage {
        @JvmField val serializedJsonResponse: String?

        protected constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            serializedJsonResponse = null
        }

        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            serializedJsonResponse =
                if (receivedMessage.encodedResponse == null) null else receivedMessage.encodedResponse
                    .decodeString()
        }
    }

    class AbortableOneWayDialogMessage : EmptyProtocolMessage {
        internal val dialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            dialogUuid = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            if (receivedMessage.encodedResponse != null) {
                throw Exception()
            }
            dialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = ABORTABLE_ONE_WAY_DIALOG_MESSAGE_ID
    }

    class SourceWaitForTargetConnectionMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = SOURCE_WAIT_FOR_TARGET_CONNECTION_MESSAGE_ID
    }


    class TargetGetSessionNumberMessage : EmptyProtocolMessage {
        internal val sessionNumber: Long?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            sessionNumber = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            sessionNumber =
                if (receivedMessage.encodedResponse == null) null else receivedMessage.encodedResponse
                    .decodeLong()
        }

        override val protocolMessageId: Int = TARGET_GET_SESSION_NUMBER_MESSAGE_ID
    }

    class TargetSendEphemeralIdentityMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = TARGET_SEND_EPHEMERAL_IDENTITY_MESSAGE_ID
    }

    class SourceSendCommitmentMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = SOURCE_SEND_COMMITMENT_MESSAGE_ID
    }

    class TargetSeedMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = TARGET_SEED_MESSAGE_ID
    }

    class SourceSasInputMessage : EmptyProtocolMessage {
        internal val sas: String?
        internal val deviceUidToKeepActive: UID?

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            this.sas = null
            this.deviceUidToKeepActive = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            if (receivedMessage.encodedResponse == null) {
                this.sas = null
                this.deviceUidToKeepActive = null
            } else {
                val list: Array<Encoded> = receivedMessage.encodedResponse.decodeList()
                if (list.size == 1) {
                    this.sas = list[0].decodeString()
                    this.deviceUidToKeepActive = null
                } else {
                    this.sas = list[0].decodeString()
                    this.deviceUidToKeepActive = list[1].decodeUid()
                }
            }
        }

        override val protocolMessageId: Int = SOURCE_SAS_INPUT_MESSAGE_ID
    }


    class SourceDecommitmentMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = SOURCE_DECOMMITMENT_MESSAGE_ID
    }

    class TargetWaitForSnapshotMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = TARGET_WAIT_FOR_SNAPSHOT_MESSAGE_ID
    }

    class SourceSnapshotMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = SOURCE_SNAPSHOT_MESSAGE_ID
    }

    class CloseWebSocketMessage(coreProtocolMessage: CoreProtocolMessage?) :
        EmptyProtocolMessage(coreProtocolMessage) {
        override val protocolMessageId: Int = -1
    }

    class SourceWaitForKeycloakAuthenticationProofMessage : WaitOrRelayMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID
    }

    class TargetRetrieveKeycloakAuthenticationProofMessage : EmptyProtocolMessage {
        internal val signature: String?
        internal val serializedKeycloakAuthState: String?

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage) {
            this.signature = null
            this.serializedKeycloakAuthState = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            if (receivedMessage.encodedResponse == null) {
                this.signature = null
                this.serializedKeycloakAuthState = null
            } else {
                val list: Array<Encoded> = receivedMessage.encodedResponse.decodeList()
                if (list.size == 2) {
                    this.signature = list[0].decodeString()
                    this.serializedKeycloakAuthState = list[1].decodeString()
                } else {
                    this.signature = null
                    this.serializedKeycloakAuthState = null
                }
            }
        }

        override val protocolMessageId: Int = TARGET_RETRIEVE_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                InitiateTransferOnSourceDeviceStep::class.java,
                InitiateTransferOnTargetDeviceStep::class.java
            )

            SOURCE_WAITING_FOR_SESSION_NUMBER_STATE_ID -> return arrayOf<Class<*>>(
                SourceDisplaysSessionNumberStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            SOURCE_WAITING_FOR_TARGET_CONNECTION_STATE_ID -> return arrayOf<Class<*>>(
                SourceSendsTransferredIdentityAndCommitmentStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            TARGET_WAITING_FOR_SESSION_NUMBER_STATE_ID -> return arrayOf<Class<*>>(
                TargetProcessesSessionNumberAndSendsEphemeralIdentityStep::class.java
            )

            TARGET_WAITING_FOR_TRANSFERRED_IDENTITY_STATE_ID -> return arrayOf<Class<*>>(
                TargetSendsSeedStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            SOURCE_WAITING_FOR_TARGET_SEED_STATE_ID -> return arrayOf<Class<*>>(
                SourceSendsDecommitmentAndShowsSasInputStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            TARGET_WAITING_FOR_DECOMMITMENT_STATE_ID -> return arrayOf<Class<*>>(
                TargetShowsSasStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            SOURCE_WAITING_FOR_SAS_INPUT_STATE_ID -> return arrayOf<Class<*>>(
                SourceCheckSasInputAndSendSnapshotStep::class.java
            )

            TARGET_WAITING_FOR_SNAPSHOT_STATE_ID -> return arrayOf<Class<*>>(
                TargetProcessesSnapshotStep::class.java,
                UserInitiatedAbortProtocolStep::class.java
            )

            SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID -> return arrayOf<Class<*>>(
                SourceCheckTransferProofAndSendSnapshotStep::class.java
            )

            TARGET_WAITING_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID -> return arrayOf<Class<*>>(
                TargetSendKeycloakAuthenticationProofStep::class.java
            )

            FINAL_STATE_ID -> return arrayOf<Class<*>>()
            else -> return arrayOf<Class<*>>()
        }
    }

    class InitiateTransferOnSourceDeviceStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        @field:Suppress(
            "unused"
        ) internal val receivedMessage: InitiateTransferOnSourceDeviceMessage?,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val dialogUuid = UUID.randomUUID()
            run {
                // display spinner dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(SourceWaitForSessionNumberStep()),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AbortableOneWayDialogMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // connect to the transfer server and get a session number
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferSourceQuery()
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceGetSessionNumberMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return SourceWaitingForSessionNumberState(dialogUuid)
        }
    }

    class SourceDisplaysSessionNumberStep @Suppress("unused") constructor(
        internal val startState: SourceWaitingForSessionNumberState,
        internal val receivedMessage: SourceGetSessionNumberMessage,
        protocol: OwnedIdentityTransferProtocol
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val dialogUuid = startState.dialogUuid

            // check if the server query failed
            if (receivedMessage.serializedJsonResponseSource == null) {
                return failProtocol(
                    this,
                    dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            val sessionNumber: Long?
            val ownConnectionIdentifier: String?

            try {
                val jsonResponseSource = jsonObjectMapper.readValue<JsonResponseSource>(
                    receivedMessage.serializedJsonResponseSource,
                    JsonResponseSource::class.java
                )
                sessionNumber = jsonResponseSource.sessionNumber
                ownConnectionIdentifier = jsonResponseSource.awsConnectionId
            } catch (_: Exception) {
                return failProtocol(
                    this,
                    dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                )
            }

            if (sessionNumber == null || ownConnectionIdentifier == null) {
                return failProtocol(
                    this,
                    dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            run {
                // display session number
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(SourceDisplaySessionNumber(sessionNumber)),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AbortableOneWayDialogMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // wait for the transfer server's target connection message
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferWaitQuery()
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceWaitForTargetConnectionMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return SourceWaitingForTargetConnectionState(
                dialogUuid,
                ownConnectionIdentifier,
                sessionNumber
            )
        }
    }


    class InitiateTransferOnTargetDeviceStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        @field:Suppress(
            "unused"
        ) internal val receivedMessage: InitiateTransferOnTargetDeviceMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val dialogUuid = UUID.randomUUID()
            run {
                // display session number input field
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(TargetSessionNumberInput()),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetGetSessionNumberMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return TargetWaitingForSessionNumberState(
                dialogUuid,
                receivedMessage.deviceName,
                receivedMessage.serverAuthenticationPrivateKey,
                receivedMessage.encryptionPrivateKey,
                receivedMessage.macKey
            )
        }
    }

    class TargetProcessesSessionNumberAndSendsEphemeralIdentityStep(
        internal val startState: TargetWaitingForSessionNumberState,
        internal val receivedMessage: TargetGetSessionNumberMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.sessionNumber == null) {
                return userInitiatedAbortProtocol(this, startState.dialogUuid)
            }

            run {
                // display spinner dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(OngoingProtocol()),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AbortableOneWayDialogMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // send the ephemeral owned identity to the source
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferTargetQuery(
                            receivedMessage.sessionNumber!!,
                            Encoded.of(ownedIdentity).bytes
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetSendEphemeralIdentityMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return TargetWaitingForTransferredIdentityState(
                startState.dialogUuid,
                startState.deviceName,
                startState.serverAuthenticationPrivateKey,
                startState.encryptionPrivateKey,
                startState.macKey,
                receivedMessage.sessionNumber
            )
        }
    }


    class SourceSendsTransferredIdentityAndCommitmentStep(
        internal val startState: SourceWaitingForTargetConnectionState,
        internal val receivedMessage: SourceWaitForTargetConnectionMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                SourceWaitForTargetConnectionMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            val jsonResponse: JsonResponse
            val ephemeralIdentity: Identity
            try {
                jsonResponse = jsonObjectMapper.readValue(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
                ephemeralIdentity = Encoded(jsonResponse.payload!!).decodeIdentity()
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceSendsTransferredIdentityAndCommitmentStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId == null) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceSendsTransferredIdentityAndCommitmentStep invalid response")
                return restartStep(protocolManagerSession)
            }


            val seedSourceForSas = Seed(prng)
            val commitmentScheme = Suite.getDefaultCommitment(0)
            val commitmentOutput = commitmentScheme.commit(
                ownedIdentity.getBytes(),
                seedSourceForSas.bytes,
                prng
            )

            // send our own connectionIdentifier, the identity to transfer and a commitment
            val cleartextPayload = Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(startState.ownConnectionIdentifier),
                    Encoded.of(ownedIdentity),
                    Encoded.of(commitmentOutput.commitment),
                )
            ).bytes

            val payload = Suite.getPublicKeyEncryption(ephemeralIdentity.encryptionPublicKey)!!
                .encrypt(ephemeralIdentity.encryptionPublicKey, cleartextPayload, prng)!!

            run {
                // send the encrypted payload
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(
                            jsonResponse.otherConnectionId!!,
                            payload.getBytes(),
                            false
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceSendCommitmentMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // display spinner dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(OngoingProtocol()),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AbortableOneWayDialogMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return SourceWaitingForTargetSeedState(
                startState.dialogUuid,
                jsonResponse.otherConnectionId!!,
                ephemeralIdentity,
                seedSourceForSas,
                commitmentOutput.decommitment,
                startState.sessionNumber
            )
        }
    }


    class TargetSendsSeedStep(
        internal val startState: TargetWaitingForTransferredIdentityState,
        internal val receivedMessage: TargetSendEphemeralIdentityMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                TargetSendEphemeralIdentityMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                // this happens if the session number was rejected by the server
                //  --> prompt for a new session number
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(TargetSessionNumberInput()),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetGetSessionNumberMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return TargetWaitingForSessionNumberState(
                    startState.dialogUuid,
                    startState.deviceName,
                    startState.serverAuthenticationPrivateKey,
                    startState.encryptionPrivateKey,
                    startState.macKey
                )
            }

            val jsonResponse: JsonResponse
            try {
                jsonResponse = jsonObjectMapper.readValue<JsonResponse>(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetSendsSeedStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId == null || jsonResponse.payload == null) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetSendsSeedStep invalid response")
                return restartStep(protocolManagerSession)
            }

            val otherConnectionIdentifier: String?
            val transferredIdentity: Identity?
            val commitment: ByteArray?
            try {
                // decrypt and parse relayed message
                val cleartextPayload = Suite.getPublicKeyEncryption(startState.encryptionPrivateKey)!!
                    .decrypt(
                        startState.encryptionPrivateKey,
                        EncryptedBytes(jsonResponse.payload!!)
                    )!!
                val list: Array<Encoded> = Encoded(cleartextPayload).decodeList()
                if (list.size != 3) {
                    throw DecodingException()
                }
                otherConnectionIdentifier = list[0].decodeString()
                transferredIdentity = list[1].decodeIdentity()
                commitment = list[2].decodeBytes()
            } catch (_: Exception) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetSendsSeedStep failed to decrypt and parse response")
                return restartStep(protocolManagerSession)
            }

            if (otherConnectionIdentifier != jsonResponse.otherConnectionId) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetSendsSeedStep connection identifier mismatch!")
                return restartStep(protocolManagerSession)
            }

            if (protocolManagerSession.identityDelegate!!.isOwnedIdentity(
                    protocolManagerSession.session,
                    transferredIdentity,
                    false
                )
            ) {
                Logger.w("OwnedIdentityTransferProtocol: transferred identity is already an owned identity!")
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_TRANSFERRED_IDENTITY_ALREADY_EXISTS
                )
            }

            // compute Target part of the SAS
            val privateIdentity = PrivateIdentity(
                ownedIdentity,
                startState.serverAuthenticationPrivateKey!!,
                startState.encryptionPrivateKey!!,
                startState.macKey!!
            )
            val seedTargetForSas = privateIdentity.getDeterministicSeedForOwnedIdentity(
                commitment,
                IdentityDelegate.DeterministicSeedContext.COMPUTE_TRANSFER_SAS
            )

            run {
                // send the seedTargetForSas to Source
                val dataToSend = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(startState.deviceName),
                        Encoded.of(seedTargetForSas),
                    )
                )
                val payload = Suite.getPublicKeyEncryption(transferredIdentity.encryptionPublicKey)!!
                    .encrypt(transferredIdentity.encryptionPublicKey, dataToSend.bytes, prng)!!
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(otherConnectionIdentifier, payload.getBytes(), false)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetSeedMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return TargetWaitingForDecommitmentState(
                startState.dialogUuid,
                startState.deviceName,
                otherConnectionIdentifier,
                transferredIdentity,
                commitment,
                seedTargetForSas,
                startState.serverAuthenticationPrivateKey,
                startState.encryptionPrivateKey,
                startState.macKey,
                startState.sessionNumber
            )
        }
    }


    class SourceSendsDecommitmentAndShowsSasInputStep(
        internal val startState: SourceWaitingForTargetSeedState,
        internal val receivedMessage: SourceSendCommitmentMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                SourceSendCommitmentMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            val jsonResponse: JsonResponse
            try {
                jsonResponse = jsonObjectMapper.readValue<JsonResponse>(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceSendsDecommitmentAndShowsSasInputStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId != startState.otherConnectionIdentifier || jsonResponse.payload == null) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceSendsDecommitmentAndShowsSasInputStep invalid response or connectionIdentifier mismatch")
                return restartStep(protocolManagerSession)
            }

            val seedTargetForSas: Seed?
            val targetDeviceName: String?
            try {
                // decrypt and parse relayed message
                val cleartextPayload = protocolManagerSession.encryptionForIdentityDelegate!!.decrypt(
                    protocolManagerSession.session,
                    EncryptedBytes(jsonResponse.payload!!),
                    ownedIdentity
                )

                val list: Array<Encoded> =
                    Encoded(cleartextPayload!!).decodeList() // if cleartextPayload is null, this will throw
                targetDeviceName = list[0].decodeString()
                seedTargetForSas = list[1].decodeSeed()
            } catch (_: Exception) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceSendsDecommitmentAndShowsSasInputStep failed to decrypt and parse response")
                return restartStep(protocolManagerSession)
            }

            run {
                // send the decommitment
                val payload =
                    Suite.getPublicKeyEncryption(startState.ephemeralIdentity.encryptionPublicKey)!!
                        .encrypt(
                            startState.ephemeralIdentity.encryptionPublicKey,
                            startState.decommitment,
                            prng
                        )!!
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(
                            startState.otherConnectionIdentifier,
                            payload.getBytes(),
                            true
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceDecommitmentMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }


            // compute the complete SAS
            val fullSas = String(
                SAS.computeDouble(
                    startState.seedSourceForSas,
                    seedTargetForSas,
                    startState.ephemeralIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )!!, StandardCharsets.UTF_8
            )
            run {
                // show a dialog for SAS input
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(SourceSasInput(fullSas, targetDeviceName)),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceSasInputMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return SourceWaitingForSasInputState(
                startState.dialogUuid,
                startState.otherConnectionIdentifier,
                targetDeviceName,
                startState.ephemeralIdentity,
                fullSas,
                startState.sessionNumber
            )
        }
    }


    class TargetShowsSasStep(
        internal val startState: TargetWaitingForDecommitmentState,
        internal val receivedMessage: TargetSeedMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                TargetSeedMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            val jsonResponse: JsonResponse
            try {
                jsonResponse = jsonObjectMapper.readValue<JsonResponse>(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetShowsSasStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId != startState.otherConnectionIdentifier || jsonResponse.payload == null) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetShowsSasStep invalid response or connectionIdentifier mismatch")
                return restartStep(protocolManagerSession)
            }

            val decommitment: ByteArray
            try {
                // decrypt and parse relayed message
                decommitment = Suite.getPublicKeyEncryption(startState.encryptionPrivateKey)!!
                    .decrypt(
                        startState.encryptionPrivateKey,
                        EncryptedBytes(jsonResponse.payload!!)
                    ) ?: throw Exception()
            } catch (_: Exception) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetShowsSasStep failed to decrypt and parse response")
                return restartStep(protocolManagerSession)
            }

            val fullSas: ByteArray?
            run {
                // open the commitment and compute the full SAS
                val commitmentScheme = Suite.getDefaultCommitment(0)
                val opened = commitmentScheme.open(
                    startState.transferredIdentity.getBytes(),
                    startState.commitment,
                    decommitment
                )
                if (opened == null) {
                    Logger.e("Unable to open commitment.")
                    return failProtocol(
                        this,
                        startState.dialogUuid,
                        ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                    )
                }
                val seedSourceForSas = Seed(opened)
                fullSas = SAS.computeDouble(
                    seedSourceForSas,
                    startState.seedTargetForSas,
                    ownedIdentity,
                    Constants.DEFAULT_NUMBER_OF_DIGITS_FOR_SAS
                )
            }

            run {
                // show the SAS dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(
                            TargetShowSas(
                                kotlin.text.String(
                                    fullSas!!,
                                    StandardCharsets.UTF_8
                                )
                            )
                        ),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    AbortableOneWayDialogMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // send a wait message to receive the snapshot
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferWaitQuery()
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetWaitForSnapshotMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return TargetWaitingForSnapshotState(
                startState.dialogUuid,
                startState.deviceName,
                startState.otherConnectionIdentifier,
                startState.transferredIdentity,
                startState.serverAuthenticationPrivateKey,
                startState.encryptionPrivateKey,
                startState.macKey,
                kotlin.text.String(fullSas!!, StandardCharsets.UTF_8),
                startState.sessionNumber,
                null
            )
        }
    }


    class SourceCheckSasInputAndSendSnapshotStep(
        internal val startState: SourceWaitingForSasInputState,
        internal val receivedMessage: SourceSasInputMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.sas == null) {
                return userInitiatedAbortProtocol(this, startState.dialogUuid)
            }

            if (receivedMessage.sas != startState.fullSas) {
                // wrong sas --> show the dialog for SAS input again
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(
                            SourceSasInput(
                                startState.fullSas,
                                startState.targetDeviceName
                            )
                        ),
                        startState.dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceSasInputMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return startState
            }

            // check if owned identity is keycloak managed and transfer restricted
            val keycloakState =
                protocolManagerSession.identityDelegate!!.getOwnedIdentityKeycloakState(
                    protocolManagerSession.session,
                    ownedIdentity
                )
            if (keycloakState != null && keycloakState.transferRestricted) {
                // sas is correct --> send keycloak parameters so the target device can authenticate and respond with a transferProof

                var oidc: OpenIdConnect? = null
                for (authType in keycloakState.supportedAuthenticationMethods) {
                    if (authType is OpenIdConnect) {
                        oidc = authType
                        
                    }
                }
                if (oidc == null) {
                    Logger.e("ID is bound to a Keycloak server that forces transferRestricted but does not support OpenId Connect authentification. This is not supported!!!")
                    return failProtocol(
                        this,
                        startState.dialogUuid,
                        ObvTransferStep.Fail.FAIL_REASON_TRANSFER_RESTRICTED_AND_NO_OIDC
                    )
                }

                val configuration = JsonKeycloakConfiguration()
                configuration.server = keycloakState.keycloakServer
                configuration.cid = oidc.clientId
                configuration.secret = oidc.clientSecret

                val dataToSend = jsonObjectMapper.writeValueAsBytes(configuration)
                val payload =
                    Suite.getPublicKeyEncryption(startState.ephemeralIdentity.encryptionPublicKey)!!
                        .encrypt(
                            startState.ephemeralIdentity.encryptionPublicKey,
                            dataToSend,
                            prng
                        )!!

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(
                            startState.otherConnectionIdentifier,
                            payload.getBytes(),
                            false
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceWaitForKeycloakAuthenticationProofMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return SourceWaitForKeycloakAuthenticationProofState(
                    startState.dialogUuid,
                    startState.otherConnectionIdentifier,
                    startState.ephemeralIdentity,
                    startState.fullSas,
                    startState.sessionNumber,
                    receivedMessage.deviceUidToKeepActive
                )
            } else {
                // sas is correct --> we can send a snapshot
                sendSnapshotAndCloseWebsocket(
                    protocolManagerSession,
                    protocolInstanceUid,
                    ownedIdentity,
                    receivedMessage.deviceUidToKeepActive,
                    startState.otherConnectionIdentifier,
                    startState.ephemeralIdentity,
                    startState.dialogUuid,
                    prng
                )

                return FinalState()
            }
        }
    }

    class SourceCheckTransferProofAndSendSnapshotStep(
        internal val startState: SourceWaitForKeycloakAuthenticationProofState,
        internal val receivedMessage: SourceWaitForKeycloakAuthenticationProofMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                SourceWaitForKeycloakAuthenticationProofMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }

            val jsonResponse: JsonResponse
            val signature: String?
            try {
                jsonResponse = jsonObjectMapper.readValue<JsonResponse>(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
                val cleartextPayload = protocolManagerSession.encryptionForIdentityDelegate!!.decrypt(
                    protocolManagerSession.session,
                    EncryptedBytes(jsonResponse.payload!!),
                    ownedIdentity
                )

                signature = kotlin.text.String(cleartextPayload!!, StandardCharsets.UTF_8)
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceCheckTransferProofAndSendSnapshotStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId != startState.otherConnectionIdentifier) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.SourceCheckTransferProofAndSendSnapshotStep invalid response")
                return restartStep(protocolManagerSession)
            }


            // validate the received signature
            try {
                val signedContent = protocolManagerSession.identityDelegate!!.verifyKeycloakSignature(
                    protocolManagerSession.session,
                    ownedIdentity,
                    signature
                )
                val transferProof = jsonObjectMapper.readValue<JsonTransferProof>(
                    signedContent,
                    JsonTransferProof::class.java
                )

                val keycloakUserId =
                    protocolManagerSession.identityDelegate.getOwnedIdentityKeycloakUserId(
                        protocolManagerSession.session,
                        ownedIdentity
                    )

                if ((transferProof.session_id != String.format(
                        Locale.ENGLISH,
                        "%08d",
                        startState.sessionNumber
                    )) || (transferProof.sas != startState.fullSas) || !transferProof.identity.contentEquals(
                        ownedIdentity.getBytes()
                    ) || (transferProof.keycloak_id != keycloakUserId)
                ) {
                    return failProtocol(
                        this,
                        startState.dialogUuid,
                        ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                    )
                }
            } catch (_: Exception) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                )
            }

            sendSnapshotAndCloseWebsocket(
                protocolManagerSession,
                protocolInstanceUid,
                ownedIdentity,
                startState.deviceUidToKeepActive,
                startState.otherConnectionIdentifier,
                startState.ephemeralIdentity,
                startState.dialogUuid,
                prng
            )

            return FinalState()
        }
    }


    class TargetProcessesSnapshotStep(
        internal val startState: TargetWaitingForSnapshotState,
        internal val receivedMessage: TargetWaitForSnapshotMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        private fun restartStep(protocolManagerSession: ProtocolManagerSession): ConcreteProtocolState {
            val coreProtocolMessage = buildCoreProtocolMessage(
                createServerQueryChannelInfo(
                    ownedIdentity,
                    TransferWaitQuery()
                )
            )
            val messageToSend: ChannelMessageToSend? =
                TargetWaitForSnapshotMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )
            return startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.serializedJsonResponse == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_NETWORK_ERROR
                )
            }


            val jsonResponse: JsonResponse
            try {
                jsonResponse = jsonObjectMapper.readValue<JsonResponse>(
                    receivedMessage.serializedJsonResponse,
                    JsonResponse::class.java
                )
            } catch (_: Exception) {
                // failed to parse the response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetProcessesSnapshotStep failed to parse response")
                return restartStep(protocolManagerSession)
            }

            if (jsonResponse.otherConnectionId != startState.otherConnectionIdentifier || jsonResponse.payload == null) {
                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetProcessesSnapshotStep invalid response or connectionIdentifier mismatch")
                return restartStep(protocolManagerSession)
            }

            val wrappedIdentityDelegate =
                protocolManagerSession.identityDelegate!!.getSyncDelegateWithinTransaction(
                    protocolManagerSession.session
                )

            var plaintext: ByteArray? = null
            val syncSnapshot: ObvSyncSnapshot?
            val deviceUidToKeepActive: UID?
            try {
                // decrypt
                plaintext = Suite.getPublicKeyEncryption(startState.encryptionPrivateKey)!!.decrypt(
                    startState.encryptionPrivateKey,
                    EncryptedBytes(jsonResponse.payload!!)
                )!!

                // parse relayed message
                val list: Array<Encoded> = Encoded(plaintext).decodeList()

                // make sure we can parse the snapshot, but don't do anything with it, the app will take care of this
                syncSnapshot = ObvSyncSnapshot.fromEncodedDictionary(
                    list[0].decodeDictionary(),
                    wrappedIdentityDelegate,
                    protocolManagerSession.appBackupAndSyncDelegate!!
                )
                if (syncSnapshot == null) {
                    return failProtocol(
                        this,
                        startState.dialogUuid,
                        ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                    )
                }

                if (list.size == 2) {
                    deviceUidToKeepActive = list[1].decodeUid()
                } else {
                    deviceUidToKeepActive = null
                }
            } catch (_: Exception) {
                // parsing failed, try to parse it as a keycloak configuration
                if (plaintext != null) {
                    try {
                        val jsonKeycloakConfiguration =
                            jsonObjectMapper.readValue<JsonKeycloakConfiguration?>(
                                plaintext,
                                JsonKeycloakConfiguration::class.java
                            )
                        if (jsonKeycloakConfiguration != null && jsonKeycloakConfiguration.server != null && jsonKeycloakConfiguration.cid != null) {
                            val jkcServer = jsonKeycloakConfiguration.server
                            val jkcCid = jsonKeycloakConfiguration.cid
                            // we have received a JsonKeycloakConfiguration that needs to be passed to the app to force authentication
                            run {
                                // send keycloak config to app
                                val coreProtocolMessage = buildCoreProtocolMessage(
                                    createUserInterfaceChannelInfo(
                                        ownedIdentity,
                                        createTransferDialog(
                                            TargetRequestsKeycloakAuthenticationProof(
                                                jkcServer!!,
                                                jkcCid!!,
                                                jsonKeycloakConfiguration.secret,
                                                startState.fullSas,
                                                startState.sessionNumber
                                            )
                                        ),
                                        startState.dialogUuid
                                    )
                                )
                                val messageToSend: ChannelMessageToSend? =
                                    TargetRetrieveKeycloakAuthenticationProofMessage(
                                        coreProtocolMessage
                                    ).generateChannelDialogMessageToSend()
                                protocolManagerSession.channelDelegate!!.post(
                                    protocolManagerSession.session,
                                    messageToSend,
                                    prng
                                )
                            }

                            return TargetWaitingForKeycloakAuthenticationProofState(
                                startState.dialogUuid,
                                startState.deviceName,
                                startState.otherConnectionIdentifier,
                                startState.transferredIdentity,
                                startState.serverAuthenticationPrivateKey,
                                startState.encryptionPrivateKey,
                                startState.macKey,
                                startState.fullSas,
                                startState.sessionNumber
                            )
                        }
                    } catch (_: Exception) {
                    }
                }


                // invalid response --> send a Wait message and return to start state
                Logger.w("OwnedIdentityTransferProtocol.TargetProcessesSnapshotStep failed to decrypt and parse response")
                return restartStep(protocolManagerSession)
            }

            /**///// */
            // create the list of callbacks and add the sessionCommitListener first, so the delegates get a
            // chance to perform an action before the engine restore notifications start being sent
            val commitCallbackList: MutableList<RestoreFinishedCallback> =
                ArrayList<RestoreFinishedCallback>()
            protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                for (callback in commitCallbackList) {
                    callback.onRestoreSuccess()
                }
            })

            try {
                // create the owned identity (and associated stuff) at engine level

                val node = syncSnapshot.getSnapshotNode(wrappedIdentityDelegate.tag!!)
                val obvOwnedIdentity: ObvIdentity?
                if (node is IdentityManagerSyncSnapshot) {
                    obvOwnedIdentity =
                        protocolManagerSession.identityDelegate.restoreTransferredOwnedIdentity(
                            protocolManagerSession.session,
                            startState.deviceName,
                            node
                        )
                    if (startState.serializedKeycloakAuthState != null) {
                        protocolManagerSession.identityDelegate.saveKeycloakAuthState(
                            protocolManagerSession.session,
                            obvOwnedIdentity.getIdentity(),
                            startState.serializedKeycloakAuthState
                        )
                    }
                } else {
                    throw Exception()
                }

                // give a chance for all delegates to create an owned identity based on what the engine just created
                val callbacksOwnedIdentity = syncSnapshot.restoreOwnedIdentity(
                    obvOwnedIdentity,
                    wrappedIdentityDelegate,
                    protocolManagerSession.appBackupAndSyncDelegate
                )
                if (callbacksOwnedIdentity.isNotEmpty()) {
                    commitCallbackList.addAll(callbacksOwnedIdentity)
                }


                run {
                    // actually restore the snapshot
                    val callbacks = syncSnapshot.restore(
                        wrappedIdentityDelegate,
                        protocolManagerSession.appBackupAndSyncDelegate
                    )
                    if (callbacks.isNotEmpty()) {
                        commitCallbackList.addAll(callbacks)
                    }
                }
            } catch (e: Exception) {
                // if an exception occurs, always call the failure of any already added callback
                for (callback in commitCallbackList) {
                    callback.onRestoreFailure()
                }
                throw e
            }



            if (deviceUidToKeepActive != null) {
                if (deviceRegisteredNotificationListenerNumber != null) {
                    // remove any left-over listener
                    protocolManagerSession.notificationListeningDelegate!!.removeListener(
                        DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED,
                        deviceRegisteredNotificationListenerNumber!!
                    )
                }
                // create the new listener
                deviceRegisteredNotificationListener =
                    NotificationListener { notificationName: String?, userInfo: Map<String, Any>? ->
                    try {
                        if (notificationName != DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED || userInfo == null) {
                            return@NotificationListener
                        }
                        val identity =
                            userInfo.get(DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED_OWNED_IDENTITY_KEY)
                        if (identity !is Identity || startState.transferredIdentity != identity) {
                            return@NotificationListener
                        }

                        // this is the right notification, unregister this listener
                        if (deviceRegisteredNotificationListenerNumber != null) {
                            protocolManagerSession.notificationListeningDelegate!!.removeListener(
                                DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED,
                                deviceRegisteredNotificationListenerNumber!!
                            )
                            deviceRegisteredNotificationListener = null
                            deviceRegisteredNotificationListenerNumber = null
                        }

                        // trigger the device keep active request
                        protocolManagerSession.protocolStarterDelegate!!.processDeviceManagementRequest(
                            startState.transferredIdentity,
                            ObvDeviceManagementRequest.createSetUnexpiringDeviceRequest(
                                deviceUidToKeepActive.bytes
                            )
                        )
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
                // register it
                deviceRegisteredNotificationListenerNumber =
                    protocolManagerSession.notificationListeningDelegate!!.addListener(
                        DownloadNotifications.NOTIFICATION_PUSH_NOTIFICATION_REGISTERED,
                        deviceRegisteredNotificationListener!!
                    )
            }



            try {
                // trigger a download of all user data (including other identities, but we do not really care...)
                protocolManagerSession.identityDelegate.downloadAllUserData(protocolManagerSession.session)
            } catch (_: Exception) {
            }



            run {
                // close the websocket
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferCloseQuery(false)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    CloseWebSocketMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // notify the app that the transfer is finished
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(TargetSnapshotReceived()),
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
                // at the very end, add a final session commit listener that will be called after all engine notifications are sent
                protocolManagerSession.session.addSessionCommitListener(SessionCommitListener {
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_SNAPSHOT_RESTORATION_FINISHED,
                        HashMap<String, Any>()
                    )
                })
            }

            return FinalState()
        }

        companion object {
            // used to keep a reference to the listener waiting for the new device to be registered on the server
            internal var deviceRegisteredNotificationListener: NotificationListener? = null
            internal var deviceRegisteredNotificationListenerNumber: Long? = null
        }
    }


    class TargetSendKeycloakAuthenticationProofStep(
        internal val startState: TargetWaitingForKeycloakAuthenticationProofState,
        internal val receivedMessage: TargetRetrieveKeycloakAuthenticationProofMessage,
        protocol: OwnedIdentityTransferProtocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (receivedMessage.signature == null) {
                return failProtocol(
                    this,
                    startState.dialogUuid,
                    ObvTransferStep.Fail.FAIL_REASON_INVALID_RESPONSE
                )
            }


            run {
                // send the signature to the source
                val payload =
                    Suite.getPublicKeyEncryption(startState.transferredIdentity.encryptionPublicKey)!!
                        .encrypt(
                            startState.transferredIdentity.encryptionPublicKey,
                            receivedMessage.signature!!.toByteArray(
                                StandardCharsets.UTF_8
                            ),
                            prng
                        )!!
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(
                            startState.otherConnectionIdentifier,
                            payload.getBytes(),
                            false
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    TargetWaitForSnapshotMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return TargetWaitingForSnapshotState(
                startState.dialogUuid,
                startState.deviceName,
                startState.otherConnectionIdentifier,
                startState.transferredIdentity,
                startState.serverAuthenticationPrivateKey,
                startState.encryptionPrivateKey,
                startState.macKey,
                startState.fullSas,
                startState.sessionNumber,
                receivedMessage.serializedKeycloakAuthState
            )
        }
    }


    class UserInitiatedAbortProtocolStep : ProtocolStep {
        internal val receivedMessage: AbortableOneWayDialogMessage

        @Suppress("unused")
        constructor(
            startState: SourceWaitingForSessionNumberState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: SourceWaitingForTargetConnectionState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: TargetWaitingForTransferredIdentityState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: SourceWaitingForTargetSeedState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: TargetWaitingForDecommitmentState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: TargetWaitingForSnapshotState?,
            receivedMessage: AbortableOneWayDialogMessage,
            protocol: OwnedIdentityTransferProtocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.receivedMessage = receivedMessage
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            return userInitiatedAbortProtocol(this, receivedMessage.dialogUuid)
        }
    }

    // endregion
    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonResponseSource {
        @JvmField var awsConnectionId: String? = null
        @JvmField var sessionNumber: Long? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonResponse {
        @JvmField var otherConnectionId: String? = null
        @JvmField var payload: ByteArray? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonKeycloakConfiguration {
        @JvmField var server: String? = null
        @JvmField var cid: String? = null
        @JvmField var secret: String? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class JsonTransferProof {
        @JvmField var session_id: String? = null
        @JvmField var sas: String? = null
        @JvmField var identity: ByteArray? = null
        @JvmField var keycloak_id: String? = null
    }

    companion object {
        // region States
        const val SOURCE_WAITING_FOR_SESSION_NUMBER_STATE_ID: Int = 1
        const val SOURCE_WAITING_FOR_TARGET_CONNECTION_STATE_ID: Int = 2
        const val TARGET_WAITING_FOR_SESSION_NUMBER_STATE_ID: Int = 3
        const val TARGET_WAITING_FOR_TRANSFERRED_IDENTITY_STATE_ID: Int = 4
        const val SOURCE_WAITING_FOR_TARGET_SEED_STATE_ID: Int = 5
        const val TARGET_WAITING_FOR_DECOMMITMENT_STATE_ID: Int = 6
        const val SOURCE_WAITING_FOR_SAS_INPUT_STATE_ID: Int = 7
        const val TARGET_WAITING_FOR_SNAPSHOT_STATE_ID: Int = 8
        const val SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID: Int = 9
        const val TARGET_WAITING_FOR_KEYCLOAK_AUTHENTICATION_PROOF_STATE_ID: Int = 10
        const val FINAL_STATE_ID: Int = 99

        // endregion
        // region Messages
        const val INITIATE_TRANSFER_ON_SOURCE_DEVICE_MESSAGE_ID: Int = 0
        const val INITIATE_TRANSFER_ON_TARGET_DEVICE_MESSAGE_ID: Int = 1
        const val SOURCE_GET_SESSION_NUMBER_MESSAGE_ID: Int = 2
        const val ABORTABLE_ONE_WAY_DIALOG_MESSAGE_ID: Int = 3
        const val SOURCE_WAIT_FOR_TARGET_CONNECTION_MESSAGE_ID: Int = 4
        const val TARGET_GET_SESSION_NUMBER_MESSAGE_ID: Int = 5
        const val TARGET_SEND_EPHEMERAL_IDENTITY_MESSAGE_ID: Int = 6
        const val SOURCE_SEND_COMMITMENT_MESSAGE_ID: Int = 7
        const val TARGET_SEED_MESSAGE_ID: Int = 8
        const val SOURCE_SAS_INPUT_MESSAGE_ID: Int = 9
        const val SOURCE_DECOMMITMENT_MESSAGE_ID: Int = 10
        const val TARGET_WAIT_FOR_SNAPSHOT_MESSAGE_ID: Int = 11
        const val SOURCE_SNAPSHOT_MESSAGE_ID: Int = 12
        const val SOURCE_WAIT_FOR_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID: Int = 13
        const val TARGET_RETRIEVE_KEYCLOAK_AUTHENTICATION_PROOF_MESSAGE_ID: Int = 14


        @Throws(Exception::class)
        private fun sendSnapshotAndCloseWebsocket(
            protocolManagerSession: ProtocolManagerSession,
            protocolInstanceUid: UID?,
            ownedIdentity: Identity?,
            deviceUidToKeepActive: UID?,
            otherConnectionIdentifier: String,
            ephemeralIdentity: Identity,
            dialogUuid: UUID?,
            prng: PRNGService?
        ) {
            run {
                val wrappedIdentityDelegate =
                    protocolManagerSession.identityDelegate!!.getSyncDelegateWithinTransaction(
                        protocolManagerSession.session
                    )
                val syncSnapshot = ObvSyncSnapshot.get(
                    ownedIdentity,
                    wrappedIdentityDelegate,
                    protocolManagerSession.appBackupAndSyncDelegate!!
                )
                val cleartext: ByteArray?
                if (deviceUidToKeepActive == null) {
                    cleartext = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(
                                syncSnapshot.toEncodedDictionary(
                                    wrappedIdentityDelegate,
                                    protocolManagerSession.appBackupAndSyncDelegate
                                )!!
                            ),
                        )
                    ).bytes
                } else {
                    cleartext = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(
                                syncSnapshot.toEncodedDictionary(
                                    wrappedIdentityDelegate,
                                    protocolManagerSession.appBackupAndSyncDelegate
                                )!!
                            ),
                            Encoded.of(deviceUidToKeepActive),
                        )
                    ).bytes
                }
                val payload = Suite.getPublicKeyEncryption(ephemeralIdentity.encryptionPublicKey)!!
                    .encrypt(ephemeralIdentity.encryptionPublicKey, cleartext, prng)!!
                val coreProtocolMessage = CoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferRelayQuery(otherConnectionIdentifier, payload.getBytes(), true)
                    ),
                    ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? =
                    SourceSnapshotMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // close the websocket
                val coreProtocolMessage = CoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        TransferCloseQuery(false)
                    ),
                    ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? =
                    CloseWebSocketMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            run {
                // notify the app to end
                val coreProtocolMessage = CoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createTransferDialog(SourceSnapshotSent()),
                        dialogUuid
                    ),
                    ConcreteProtocol.OWNED_IDENTITY_TRANSFER_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }
        }


        @Throws(Exception::class)
        private fun userInitiatedAbortProtocol(
            protocolStep: ProtocolStep,
            dialogUuid: UUID?
        ): ConcreteProtocolState {
            run {
                // remove any dialog
                val coreProtocolMessage = protocolStep.buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        protocolStep.ownedIdentity,
                        createDeleteDialog(),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolStep.protocolManagerSession!!.channelDelegate!!.post(
                    protocolStep.protocolManagerSession!!.session,
                    messageToSend,
                    protocolStep.prng
                )
            }

            run {
                // close the websocket connection
                val coreProtocolMessage = protocolStep.buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        protocolStep.ownedIdentity,
                        TransferCloseQuery(true)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    CloseWebSocketMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolStep.protocolManagerSession!!.channelDelegate!!.post(
                    protocolStep.protocolManagerSession!!.session,
                    messageToSend,
                    protocolStep.prng
                )
            }

            return FinalState()
        }

        @Throws(Exception::class)
        private fun failProtocol(
            protocolStep: ProtocolStep,
            dialogUuid: UUID?,
            failReason: Int
        ): ConcreteProtocolState {
            run {
                // display fail dialog
                val coreProtocolMessage = protocolStep.buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        protocolStep.ownedIdentity,
                        createTransferDialog(ObvTransferStep.Fail(failReason)),
                        dialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolStep.protocolManagerSession!!.channelDelegate!!.post(
                    protocolStep.protocolManagerSession!!.session,
                    messageToSend,
                    protocolStep.prng
                )
            }

            run {
                // close the websocket connection
                val coreProtocolMessage = protocolStep.buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        protocolStep.ownedIdentity,
                        TransferCloseQuery(true)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    CloseWebSocketMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolStep.protocolManagerSession!!.channelDelegate!!.post(
                    protocolStep.protocolManagerSession!!.session,
                    messageToSend,
                    protocolStep.prng
                )
            }

            return FinalState()
        }
    }
}
