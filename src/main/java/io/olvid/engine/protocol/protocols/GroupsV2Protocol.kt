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

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.KDF
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createGroupV2FrozenInvitationDialog
import io.olvid.engine.datatypes.containers.DialogType.Companion.createGroupV2InvitationDialog
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.AdministratorsChain
import io.olvid.engine.datatypes.containers.GroupV2.AdministratorsChain.Companion.startNewChain
import io.olvid.engine.datatypes.containers.GroupV2.BlobKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierVersionAndKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissionsAndDetails
import io.olvid.engine.datatypes.containers.GroupV2.InvitationCollectedData
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializeKnownPermissions
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.fromString
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.serializePermissions
import io.olvid.engine.datatypes.containers.GroupV2.ServerBlob
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.GroupV2.getSharedBlobSecretKey
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createAsymmetricBroadcastChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createObliviousChannelOrPreKeyInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createServerQueryChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery.CreateGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeleteGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.GetGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.LockGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutGroupLogQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
import io.olvid.engine.datatypes.containers.ServerQuery.UpdateGroupBlobQuery
import io.olvid.engine.datatypes.key.asymmetric.KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2PendingMember
import io.olvid.engine.identity.datatypes.KeycloakGroupBlob
import io.olvid.engine.protocol.databases.GroupV2PreShotVersionSeedReceived
import io.olvid.engine.protocol.databases.GroupV2SignatureReceived
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
import java.security.InvalidKeyException
import java.sql.SQLException
import java.util.Arrays
import java.util.UUID

class GroupsV2Protocol(
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
    override val protocolId: Int = ConcreteProtocol.GROUPS_V2_PROTOCOL_ID

    override fun getStateClass(stateId: Int): Class<*>? {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return InitialProtocolState::class.java
            UPLOADING_CREATED_GROUP_DATA_STATE_ID -> return UploadingCreatedGroupDataState::class.java
            DOWNLOADING_GROUP_BLOB_STATE_ID -> return DownloadingGroupBlobState::class.java
            I_NEED_MORE_SEEDS_STATE_ID -> return INeedMoreSeedsState::class.java
            INVITATION_RECEIVED_STATE_ID -> return InvitationReceivedState::class.java
            REJECTING_INVITATION_OR_LEAVING_GROUP_STATE_ID -> return RejectingInvitationOrLeavingGroupState::class.java
            WAITING_FOR_LOCK_STATE_ID -> return WaitingForLockState::class.java
            UPLOADING_UPDATED_GROUP_BLOB_STATE_ID -> return UploadingUpdatedGroupBlobState::class.java
            UPLOADING_UPDATED_GROUP_PHOTO_STATE_ID -> return UploadingUpdatedGroupPhotoState::class.java
            DISBANDING_GROUP_STATE_ID -> return DisbandingGroupState::class.java
            FINAL_STATE_ID -> return FinalState::class.java
            else -> return null
        }
    }

    override val finalStateIds: IntArray = intArrayOf(FINAL_STATE_ID)

    class UploadingCreatedGroupDataState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val waitingForBlobUpload: Boolean
        internal val waitingForPhotoUpload: Boolean

        constructor(
            groupIdentifier: GroupV2.Identifier,
            groupVersion: Int,
            waitingForBlobUpload: Boolean,
            waitingForPhotoUpload: Boolean
        ) : super(
            UPLOADING_CREATED_GROUP_DATA_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.waitingForBlobUpload = waitingForBlobUpload
            this.waitingForPhotoUpload = waitingForPhotoUpload
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(UPLOADING_CREATED_GROUP_DATA_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 4) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupVersion = list[1].decodeLong().toInt()
            this.waitingForBlobUpload = list[2].decodeBoolean()
            this.waitingForPhotoUpload = list[3].decodeBoolean()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(groupVersion.toLong()),
                    Encoded.of(waitingForBlobUpload),
                    Encoded.of(waitingForPhotoUpload),
                )
            )
        }
    }

    abstract class CollectingSeedsAbstractState : ConcreteProtocolState {
        @JvmField val groupIdentifier: GroupV2.Identifier
        @JvmField val dialogUuid: UUID?
        @JvmField val invitationCollectedData: InvitationCollectedData
        @JvmField val ownInvitationNoncesAcceptedOnOtherDevices: Array<ByteArray?>
        @JvmField val lastKnownOwnInvitationNonce: ByteArray?
        @JvmField val lastKnownOtherGroupMemberIdentities: Array<Identity>?

        protected constructor(
            stateId: Int,
            groupIdentifier: GroupV2.Identifier,
            dialogUuid: UUID?,
            invitationCollectedData: InvitationCollectedData,
            ownInvitationNoncesAcceptedOnOtherDevices: Array<ByteArray?>,
            lastKnownOwnInvitationNonce: ByteArray?,
            lastKnownOtherGroupMemberIdentities: Array<Identity>?
        ) : super(stateId) {
            this.groupIdentifier = groupIdentifier
            this.invitationCollectedData = invitationCollectedData
            this.dialogUuid = dialogUuid
            this.ownInvitationNoncesAcceptedOnOtherDevices =
                ownInvitationNoncesAcceptedOnOtherDevices
            this.lastKnownOwnInvitationNonce = lastKnownOwnInvitationNonce
            this.lastKnownOtherGroupMemberIdentities = lastKnownOtherGroupMemberIdentities
        }

        @Suppress("unused")
        constructor(stateId: Int, encodedState: Encoded) : super(stateId) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size < 3 || list.size > 6) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.dialogUuid = list[1].decodeUuid()
            this.invitationCollectedData = InvitationCollectedData.of(list[2])
            if ((list.size and 0x1) == 0) {
                val encodeds: Array<Encoded> = list[3].decodeList()
                this.ownInvitationNoncesAcceptedOnOtherDevices =
                    arrayOfNulls<ByteArray>(encodeds.size)
                for (i in encodeds.indices) {
                    this.ownInvitationNoncesAcceptedOnOtherDevices[i] = encodeds[i].decodeBytes()
                }
            } else {
                this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            }
            this.lastKnownOwnInvitationNonce =
                if (list.size >= 5) list[list.size - 2].decodeBytes() else null
            this.lastKnownOtherGroupMemberIdentities =
                if (list.size >= 5) list[list.size - 1].decodeIdentityArray() else null
        }

        override fun encode(): Encoded {
            val encodedNonces =
                arrayOfNulls<Encoded>(ownInvitationNoncesAcceptedOnOtherDevices.size)
            for (i in encodedNonces.indices) {
                encodedNonces[i] = Encoded.of(ownInvitationNoncesAcceptedOnOtherDevices[i]!!)
            }
            if (lastKnownOwnInvitationNonce == null || lastKnownOtherGroupMemberIdentities == null) {
                return Encoded.of(
                    arrayOf<Encoded>(
                        groupIdentifier.encode(),
                        Encoded.of(dialogUuid),
                        invitationCollectedData.encode(),
                        Encoded.of(encodedNonces.requireNoNulls()),
                    )
                )
            } else {
                return Encoded.of(
                    arrayOf<Encoded>(
                        groupIdentifier.encode(),
                        Encoded.of(dialogUuid),
                        invitationCollectedData.encode(),
                        Encoded.of(encodedNonces.requireNoNulls()),
                        Encoded.of(lastKnownOwnInvitationNonce),
                        Encoded.of(lastKnownOtherGroupMemberIdentities),
                    )
                )
            }
        }
    }

    class DownloadingGroupBlobState : CollectingSeedsAbstractState {
        internal val serverQueryNonce: ByteArray

        constructor(
            groupIdentifier: GroupV2.Identifier,
            dialogUuid: UUID?,
            invitationCollectedData: InvitationCollectedData,
            ownInvitationNoncesAcceptedOnOtherDevices: Array<ByteArray?>,
            lastKnownOwnInvitationNonce: ByteArray?,
            lastKnownOtherGroupMemberIdentities: Array<Identity>?,
            serverQueryNonce: ByteArray
        ) : super(
            DOWNLOADING_GROUP_BLOB_STATE_ID,
            groupIdentifier,
            dialogUuid,
            invitationCollectedData,
            ownInvitationNoncesAcceptedOnOtherDevices,
            lastKnownOwnInvitationNonce,
            lastKnownOtherGroupMemberIdentities
        ) {
            this.serverQueryNonce = serverQueryNonce
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(
            DOWNLOADING_GROUP_BLOB_STATE_ID,
            encodedState.decodeList()[0]
        ) {
            serverQueryNonce = encodedState.decodeList()[1].decodeBytes()
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    super.encode(),
                    Encoded.of(serverQueryNonce),
                )
            )
        }
    }

    class INeedMoreSeedsState : CollectingSeedsAbstractState {
        constructor(
            groupIdentifier: GroupV2.Identifier,
            dialogUuid: UUID?,
            invitationCollectedData: InvitationCollectedData,
            ownInvitationNoncesAcceptedOnOtherDevices: Array<ByteArray?>,
            lastKnownOwnInvitationNonce: ByteArray?,
            lastKnownOtherGroupMemberIdentities: Array<Identity>?
        ) : super(
            I_NEED_MORE_SEEDS_STATE_ID,
            groupIdentifier,
            dialogUuid,
            invitationCollectedData,
            ownInvitationNoncesAcceptedOnOtherDevices,
            lastKnownOwnInvitationNonce,
            lastKnownOtherGroupMemberIdentities
        )

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(I_NEED_MORE_SEEDS_STATE_ID, encodedState)
    }

    class InvitationReceivedState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val dialogUuid: UUID?
        internal val inviterIdentity: Identity
        internal val serverBlob: ServerBlob
        internal val blobKeys: BlobKeys
        internal val groupUpdateTimestamp: Long?


        constructor(
            groupIdentifier: GroupV2.Identifier,
            dialogUuid: UUID?,
            inviterIdentity: Identity,
            serverBlob: ServerBlob,
            blobKeys: BlobKeys,
            groupUpdateTimestamp: Long?
        ) : super(
            INVITATION_RECEIVED_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.dialogUuid = dialogUuid
            this.inviterIdentity = inviterIdentity
            this.serverBlob = serverBlob
            this.blobKeys = blobKeys
            this.groupUpdateTimestamp = groupUpdateTimestamp
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(INVITATION_RECEIVED_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 5 && list.size != 6) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.dialogUuid = list[1].decodeUuid()
            this.inviterIdentity = list[2].decodeIdentity()
            this.serverBlob = ServerBlob.of(list[3])
            this.blobKeys = BlobKeys.of(list[4])
            if (list.size == 6) { // this also ensures backward compatibility with old encoded states
                this.groupUpdateTimestamp = list[5].decodeLong()
            } else {
                this.groupUpdateTimestamp = null
            }
        }

        override fun encode(): Encoded {
            if (groupUpdateTimestamp == null) {
                return Encoded.of(
                    arrayOf<Encoded>(
                        groupIdentifier.encode(),
                        Encoded.of(dialogUuid),
                        Encoded.of(inviterIdentity),
                        serverBlob.encode(),
                        blobKeys.encode(),
                    )
                )
            } else {
                return Encoded.of(
                    arrayOf<Encoded>(
                        groupIdentifier.encode(),
                        Encoded.of(dialogUuid),
                        Encoded.of(inviterIdentity),
                        serverBlob.encode(),
                        blobKeys.encode(),
                        Encoded.of(groupUpdateTimestamp),
                    )
                )
            }
        }
    }

    class RejectingInvitationOrLeavingGroupState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupMembersToNotify: MutableList<Identity>

        constructor(
            groupIdentifier: GroupV2.Identifier,
            groupMembersToNotify: MutableList<Identity>
        ) : super(
            REJECTING_INVITATION_OR_LEAVING_GROUP_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.groupMembersToNotify = groupMembersToNotify
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(REJECTING_INVITATION_OR_LEAVING_GROUP_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupMembersToNotify = Arrays.asList(*list[1].decodeIdentityArray())
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(groupMembersToNotify.toTypedArray()),
                )
            )
        }
    }


    class WaitingForLockState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val changeSet: ObvGroupV2ChangeSet
        internal val lockNonce: ByteArray
        internal val failedUploadCounter: Long
        internal val preShotVersionSeed: Seed? // a null preShotVersionSeed is encoded as an empty byte array

        constructor(
            groupIdentifier: GroupV2.Identifier,
            changeSet: ObvGroupV2ChangeSet,
            lockNonce: ByteArray,
            failedUploadCounter: Long,
            preShotVersionSeed: Seed?
        ) : super(
            WAITING_FOR_LOCK_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.changeSet = changeSet
            this.lockNonce = lockNonce
            this.failedUploadCounter = failedUploadCounter
            this.preShotVersionSeed = preShotVersionSeed
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(WAITING_FOR_LOCK_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            // size == 4 is for legacy states, before the introduction of preShotVersionSeed
            if (list.size != 4 && list.size != 5) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.changeSet = ObvGroupV2ChangeSet.of(list[1])
            this.lockNonce = list[2].decodeBytes()
            this.failedUploadCounter = list[3].decodeLong()
            this.preShotVersionSeed = if (list.size == 5) {
                try {
                    list[4].decodeSeed()
                } catch (_: IllegalArgumentException) {
                    null
                }
            } else {
                null
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    changeSet.encode(),
                    Encoded.of(lockNonce),
                    Encoded.of(failedUploadCounter),
                    if (preShotVersionSeed == null) Encoded.of(ByteArray(0)) else Encoded.of(preShotVersionSeed),
                )
            )
        }
    }

    class UploadingUpdatedGroupBlobState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val changeSet: ObvGroupV2ChangeSet
        internal val updatedBlob: ServerBlob
        internal val updatedBlobKeys: BlobKeys
        internal val membersToKick: HashMap<Identity?, ByteArray?>
        internal val absolutePhotoUrlToUpload: String?
        internal val failedUploadCounter: Long
        internal val preShotVersionSeed: Seed? // a null preShotVersionSeed is encoded as an empty byte array

        constructor(
            groupIdentifier: GroupV2.Identifier,
            changeSet: ObvGroupV2ChangeSet,
            updatedBlob: ServerBlob,
            updatedBlobKeys: BlobKeys,
            membersToKick: HashMap<Identity?, ByteArray?>,
            absolutePhotoUrlToUpload: String?,
            failedUploadCounter: Long,
            preShotVersionSeed: Seed?
        ) : super(
            UPLOADING_UPDATED_GROUP_BLOB_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.changeSet = changeSet
            this.updatedBlob = updatedBlob
            this.updatedBlobKeys = updatedBlobKeys
            this.membersToKick = membersToKick
            this.absolutePhotoUrlToUpload = absolutePhotoUrlToUpload
            this.failedUploadCounter = failedUploadCounter
            this.preShotVersionSeed = preShotVersionSeed
        }


        @Suppress("unused")
        constructor(encodedState: Encoded) : super(UPLOADING_UPDATED_GROUP_BLOB_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            // size == 7 is for legacy states, before the introduction of preShotVersionSeed
            if (list.size != 7 && list.size != 8) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.changeSet = ObvGroupV2ChangeSet.of(list[1])
            this.updatedBlob = ServerBlob.of(list[2])
            this.updatedBlobKeys = BlobKeys.of(list[3])
            this.membersToKick = Companion.decodeMembersToKick(list[4])
            val decoded = list[5].decodeString()
            this.absolutePhotoUrlToUpload = if (decoded.isEmpty()) null else decoded
            this.failedUploadCounter = list[6].decodeLong()
            this.preShotVersionSeed = if (list.size == 8) {
                try {
                    list[7].decodeSeed()
                } catch (_: IllegalArgumentException) {
                    null
                }
            } else {
                null
            }
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    changeSet.encode(),
                    updatedBlob.encode(),
                    updatedBlobKeys.encode(),
                    encodeMembersToKick(membersToKick),
                    Encoded.of(if (absolutePhotoUrlToUpload == null) "" else absolutePhotoUrlToUpload),
                    Encoded.of(failedUploadCounter),
                    if (preShotVersionSeed == null) Encoded.of(ByteArray(0)) else Encoded.of(preShotVersionSeed),
                )
            )
        }
    }

    class UploadingUpdatedGroupPhotoState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val changeSet: ObvGroupV2ChangeSet
        internal val updatedBlob: ServerBlob
        internal val updatedBlobKeys: BlobKeys
        internal val membersToKick: HashMap<Identity?, ByteArray?>
        internal val absolutePhotoUrlToUpload: String?

        constructor(
            groupIdentifier: GroupV2.Identifier,
            changeSet: ObvGroupV2ChangeSet,
            updatedBlob: ServerBlob,
            updatedBlobKeys: BlobKeys,
            membersToKick: HashMap<Identity?, ByteArray?>,
            absolutePhotoUrlToUpload: String?
        ) : super(
            UPLOADING_UPDATED_GROUP_PHOTO_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.changeSet = changeSet
            this.updatedBlob = updatedBlob
            this.updatedBlobKeys = updatedBlobKeys
            this.membersToKick = membersToKick
            this.absolutePhotoUrlToUpload = absolutePhotoUrlToUpload
        }


        @Suppress("unused")
        constructor(encodedState: Encoded) : super(UPLOADING_UPDATED_GROUP_PHOTO_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 6) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.changeSet = ObvGroupV2ChangeSet.of(list[1])
            this.updatedBlob = ServerBlob.of(list[2])
            this.updatedBlobKeys = BlobKeys.of(list[3])
            this.membersToKick = Companion.decodeMembersToKick(list[4])
            val decoded = list[5].decodeString()
            this.absolutePhotoUrlToUpload = if (decoded.isEmpty()) null else decoded
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    changeSet.encode(),
                    updatedBlob.encode(),
                    updatedBlobKeys.encode(),
                    encodeMembersToKick(membersToKick),
                    Encoded.of(if (absolutePhotoUrlToUpload == null) "" else absolutePhotoUrlToUpload),
                )
            )
        }
    }

    class DisbandingGroupState : ConcreteProtocolState {
        internal val groupIdentifier: GroupV2.Identifier
        internal val blobKeys: BlobKeys

        constructor(groupIdentifier: GroupV2.Identifier, blobKeys: BlobKeys) : super(
            DISBANDING_GROUP_STATE_ID
        ) {
            this.groupIdentifier = groupIdentifier
            this.blobKeys = blobKeys
        }

        @Suppress("unused")
        constructor(encodedState: Encoded) : super(DISBANDING_GROUP_STATE_ID) {
            val list: Array<Encoded> = encodedState.decodeList()
            if (list.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.blobKeys = BlobKeys.of(list[1])
        }

        override fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    blobKeys.encode(),
                )
            )
        }
    }


    class FinalState : ConcreteProtocolState(FINAL_STATE_ID) {
        override fun encode(): Encoded {
            return Encoded.of(arrayOf<Encoded>())
        }
    }


    init {
        eraseReceivedMessagesAfterReachingAFinalState = false
    }

    override fun getMessageClass(protocolMessageId: Int): Class<*>? {
        when (protocolMessageId) {
            GROUP_CREATION_INITIAL_MESSAGE_ID -> return GroupCreationInitialMessage::class.java
            UPLOAD_GROUP_PHOTO_MESSAGE_ID -> return UploadGroupPhotoMessage::class.java
            UPLOAD_GROUP_BLOB_MESSAGE_ID -> return UploadGroupBlobMessage::class.java
            FINALIZE_GROUP_CREATION_MESSAGE_ID -> return FinalizeGroupCreationMessage::class.java
            INVITATION_OR_MEMBERS_UPDATE_MESSAGE_ID -> return InvitationOrMembersUpdateMessage::class.java
            INVITATION_OR_MEMBERS_UPDATE_BROADCAST_MESSAGE_ID -> return InvitationOrMembersUpdateBroadcastMessage::class.java
            INVITATION_OR_MEMBERS_UPDATE_PROPAGATED_MESSAGE_ID -> return InvitationOrMembersUpdatePropagatedMessage::class.java
            DOWNLOAD_GROUP_BLOB_MESSAGE_ID -> return DownloadGroupBlobMessage::class.java
            FINALIZE_GROUP_UPDATE_MESSAGE_ID -> return FinalizeGroupUpdateMessage::class.java
            DELETE_GROUP_BLOB_FROM_SERVER_MESSAGE_ID -> return DeleteGroupBlobFromServerMessage::class.java
            DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID -> return DialogAcceptGroupInvitationMessage::class.java
            PING_MESSAGE_ID -> return PingMessage::class.java
            PROPAGATED_PING_MESSAGE_ID -> return PropagatedPingMessage::class.java
            KICK_MESSAGE_ID -> return KickMessage::class.java
            PROPAGATE_INVITATION_DIALOG_RESPONSE_MESSAGE_ID -> return PropagateInvitationDialogResponseMessage::class.java
            PUT_GROUP_LOG_ON_SERVER_MESSAGE_ID -> return PutGroupLogOnServerMessage::class.java
            INVITATION_REJECTED_BROADCAST_MESSAGE_ID -> return InvitationRejectedBroadcastMessage::class.java
            PROPAGATE_INVITATION_REJECTED_MESSAGE_ID -> return PropagateInvitationRejectedMessage::class.java
            GROUP_UPDATE_INITIAL_MESSAGE_ID -> return GroupUpdateInitialMessage::class.java
            REQUEST_LOCK_MESSAGE_ID -> return RequestLockMessage::class.java
            GROUP_LEAVE_INITIAL_MESSAGE_ID -> return GroupLeaveInitialMessage::class.java
            PROPAGATED_GROUP_LEAVE_MESSAGE_ID -> return PropagatedGroupLeaveMessage::class.java
            GROUP_DISBAND_INITIAL_MESSAGE_ID -> return GroupDisbandInitialMessage::class.java
            PROPAGATED_GROUP_DISBAND_MESSAGE_ID -> return PropagatedGroupDisbandMessage::class.java
            PROPAGATED_KICK_MESSAGE_ID -> return PropagatedKickMessage::class.java
            GROUP_RE_DOWNLOAD_INITIAL_MESSAGE_ID -> return GroupReDownloadInitialMessage::class.java
            INITIATE_BATCH_KEYS_RESEND_MESSAGE_ID -> return InitiateBatchKeysResendMessage::class.java
            BLOB_KEYS_BATCH_AFTER_CHANNEL_CREATION_MESSAGE_ID -> return BlobKeysBatchAfterChannelCreationMessage::class.java
            BLOB_KEYS_AFTER_CHANNEL_CREATION_MESSAGE_ID -> return BlobKeysAfterChannelCreationMessage::class.java
            CREATE_OR_UPDATE_KEYCLOAK_GROUP_MESSAGE_ID -> return CreateOrUpdateKeycloakGroupMessage::class.java
            INITIATE_TARGETED_PING_MESSAGE_ID -> return InitiateTargetedPingMessage::class.java
            PRE_SHOT_VERSION_SEED_MESSAGE_ID -> return PreShotVersionSeedMessage::class.java
            AUTO_ACCEPT_INVITATION_MESSAGE -> return AutoAcceptInvitationMessage::class.java
            else -> return null
        }
    }


    class GroupCreationInitialMessage : ConcreteProtocolMessage {
        internal val ownPermissions: HashSet<GroupV2.Permission>
        internal val otherGroupMembers: HashSet<IdentityAndPermissions> // does not include the group creator identity
        internal val serializedGroupDetails: String // serialized JsonGroupDetails
        internal val absolutePhotoUrl: String?
        internal val serializedGroupType: String? // serialized JsonGroupType, may be NULL


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            ownPermissions: HashSet<GroupV2.Permission>,
            otherGroupMembers: HashSet<IdentityAndPermissions>,
            serializedGroupDetails: String,
            absolutePhotoUrl: String?,
            serializedGroupType: String?
        ) : super(coreProtocolMessage!!) {
            this.ownPermissions = ownPermissions
            this.otherGroupMembers = otherGroupMembers
            this.serializedGroupDetails = serializedGroupDetails
            this.absolutePhotoUrl = absolutePhotoUrl
            this.serializedGroupType = serializedGroupType
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size == 5) {
                this.ownPermissions = deserializeKnownPermissions(inputs[0].decodeBytes())
                this.otherGroupMembers = HashSet<IdentityAndPermissions>()
                for (encodedGroupMember in inputs[1].decodeList()) {
                    this.otherGroupMembers.add(IdentityAndPermissions.of(encodedGroupMember))
                }
                this.serializedGroupDetails = inputs[2].decodeString()
                val url = inputs[3].decodeString()
                if (url.isEmpty()) {
                    this.absolutePhotoUrl = null
                } else {
                    this.absolutePhotoUrl = url
                }
                this.serializedGroupType = inputs[4].decodeString()
            } else if (inputs.size == 4) { // null serializedGroupType
                this.ownPermissions = deserializeKnownPermissions(inputs[0].decodeBytes())
                this.otherGroupMembers = HashSet<IdentityAndPermissions>()
                for (encodedGroupMember in inputs[1].decodeList()) {
                    this.otherGroupMembers.add(IdentityAndPermissions.of(encodedGroupMember))
                }
                this.serializedGroupDetails = inputs[2].decodeString()
                val url = inputs[3].decodeString()
                if (url.isEmpty()) {
                    this.absolutePhotoUrl = null
                } else {
                    this.absolutePhotoUrl = url
                }
                this.serializedGroupType = null
            } else {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = GROUP_CREATION_INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodedGroupMembers: MutableList<Encoded> = ArrayList<Encoded>()
            for (groupMember in otherGroupMembers) {
                encodedGroupMembers.add(groupMember.encode())
            }
            if (serializedGroupType == null) {
                return arrayOf<Encoded>(
                    Encoded.of(serializePermissions(ownPermissions)!!),
                    Encoded.of(encodedGroupMembers.toTypedArray<Encoded>()),
                    Encoded.of(serializedGroupDetails),
                    Encoded.of(if (absolutePhotoUrl == null) "" else absolutePhotoUrl),
                )
            } else {
                return arrayOf<Encoded>(
                    Encoded.of(serializePermissions(ownPermissions)!!),
                    Encoded.of(encodedGroupMembers.toTypedArray<Encoded>()),
                    Encoded.of(serializedGroupDetails),
                    Encoded.of(if (absolutePhotoUrl == null) "" else absolutePhotoUrl),
                    Encoded.of(serializedGroupType),
                )
            }
            }
    }

    class UploadGroupPhotoMessage : ConcreteProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse != null) { // the response should always be null for putUserData
                throw Exception()
            }
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = UPLOAD_GROUP_PHOTO_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class UploadGroupBlobMessage : ConcreteProtocolMessage {
        internal val uploadResult: Int // 0 success, 1 retry-able fail, 2 definitive fail

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            this.uploadResult = 2
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) { // the response should never be null for putGroupBlob
                throw Exception()
            }
            this.uploadResult = receivedMessage.encodedResponse.decodeLong().toInt()
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = UPLOAD_GROUP_BLOB_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }


    class FinalizeGroupCreationMessage : EmptyProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = FINALIZE_GROUP_CREATION_MESSAGE_ID
    }

    class InvitationOrMembersUpdateMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val blobKeys: BlobKeys
        internal val notifiedDeviceUids: Array<UID?>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            groupVersion: Int,
            blobKeys: BlobKeys,
            notifiedDeviceUids: Array<UID?>
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.blobKeys = blobKeys
            this.notifiedDeviceUids = notifiedDeviceUids
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 4) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupVersion = list[1].decodeLong().toInt()
            this.blobKeys = BlobKeys.of(list[2])
            this.notifiedDeviceUids = list[3].decodeUidArray()
        }


        override val protocolMessageId: Int = INVITATION_OR_MEMBERS_UPDATE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(groupVersion.toLong()),
                blobKeys.encode(),
                Encoded.of(notifiedDeviceUids),
            )
            }
    }

    class InvitationOrMembersUpdateBroadcastMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val blobKeys: BlobKeys

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            groupVersion: Int,
            blobKeys: BlobKeys
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.blobKeys = blobKeys
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 3) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupVersion = list[1].decodeLong().toInt()
            this.blobKeys = BlobKeys.of(list[2])
        }

        override val protocolMessageId: Int = INVITATION_OR_MEMBERS_UPDATE_BROADCAST_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(groupVersion.toLong()),
                blobKeys.encode(),
            )
            }
    }

    class InvitationOrMembersUpdatePropagatedMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val blobKeys: BlobKeys
        internal val inviterIdentity: Identity? // may be null

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            groupVersion: Int,
            blobKeys: BlobKeys,
            inviterIdentity: Identity?
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.blobKeys = blobKeys
            this.inviterIdentity = inviterIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 4 && list.size != 3) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupVersion = list[1].decodeLong().toInt()
            this.blobKeys = BlobKeys.of(list[2])
            if (list.size == 3) {
                this.inviterIdentity = null
            } else {
                this.inviterIdentity = list[3].decodeIdentity()
            }
        }

        override val protocolMessageId: Int = INVITATION_OR_MEMBERS_UPDATE_PROPAGATED_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            if (inviterIdentity == null) {
                return arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(groupVersion.toLong()),
                    blobKeys.encode(),
                )
            } else {
                return arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(groupVersion.toLong()),
                    blobKeys.encode(),
                    Encoded.of(inviterIdentity),
                )
            }
            }
    }

    open class DownloadGroupBlobMessage : ConcreteProtocolMessage {
        @JvmField val encryptedServerBlob: EncryptedBytes?
        @JvmField val logEntries: MutableList<ByteArray?>?
        @JvmField val groupAdminPublicKey: ServerAuthenticationPublicKey?
        @JvmField val serverQueryNonce: ByteArray?
        @JvmField val groupUpdateTimestamp: Long?
        @JvmField val deletedFromServer: Boolean

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            this.encryptedServerBlob = null
            this.logEntries = null
            this.groupAdminPublicKey = null
            this.serverQueryNonce = null
            this.groupUpdateTimestamp = null
            this.deletedFromServer = false
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) { // a null response means the query has expired --> the protocol can be aborted
                this.encryptedServerBlob = null
                this.logEntries = null
                this.groupAdminPublicKey = null
                this.serverQueryNonce = null
                this.groupUpdateTimestamp = null
                this.deletedFromServer = false
            } else {
                val list: Array<Encoded> = receivedMessage.encodedResponse.decodeList()
                if (list.size == 1 && list[0].decodeBoolean()) { // this response means the group was deleted from the server --> the protocol can be aborted and the group deleted
                    this.encryptedServerBlob = null
                    this.logEntries = null
                    this.groupAdminPublicKey = null
                    this.serverQueryNonce = null
                    this.groupUpdateTimestamp = null
                    this.deletedFromServer = true
                } else {
                    this.encryptedServerBlob = list[0].decodeEncryptedData()
                    this.logEntries = ArrayList<ByteArray?>()
                    for (encodedLogEntry in list[1].decodeList()) {
                        this.logEntries.add(encodedLogEntry.decodeBytes())
                    }
                    this.groupAdminPublicKey =
                        list[2].decodePublicKey() as ServerAuthenticationPublicKey?
                    this.serverQueryNonce = list[3].decodeBytes()
                    if (list.size == 5) { // backward compatibility with old received messages
                        val timestamp = list[4].decodeLong()
                        this.groupUpdateTimestamp = if (timestamp == 0L) null else timestamp
                    } else {
                        this.groupUpdateTimestamp = null
                    }
                    this.deletedFromServer = false
                }
            }
            if (receivedMessage.inputs.size != 0) {
                throw Exception()
            }
        }

        override val protocolMessageId: Int = DOWNLOAD_GROUP_BLOB_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    class FinalizeGroupUpdateMessage : EmptyProtocolMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = FINALIZE_GROUP_UPDATE_MESSAGE_ID
    }

    class DeleteGroupBlobFromServerMessage : EmptyProtocolMessage {
        internal val success: Boolean

        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            success = false
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage) {
            if (receivedMessage.encodedResponse == null) {
                success = false
            } else {
                success = receivedMessage.encodedResponse.decodeBoolean()
            }
        }

        override val protocolMessageId: Int = DELETE_GROUP_BLOB_FROM_SERVER_MESSAGE_ID
    }

    class DialogAcceptGroupInvitationMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean
        internal val dialogUuid: UUID?

        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!) {
            invitationAccepted = false
            dialogUuid = null
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            if (receivedMessage.encodedResponse == null) {
                throw Exception()
            }
            invitationAccepted = receivedMessage.encodedResponse.decodeBoolean()
            dialogUuid = receivedMessage.userDialogUuid
        }

        override val protocolMessageId: Int = DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() = arrayOf<Encoded>()
    }

    open class PingMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupMemberInvitationNonce: ByteArray
        internal val signature: ByteArray
        internal val isResponse: Boolean

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            groupMemberInvitationNonce: ByteArray,
            signature: ByteArray,
            isResponse: Boolean
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.groupMemberInvitationNonce = groupMemberInvitationNonce
            this.signature = signature
            this.isResponse = isResponse
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 4) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.groupMemberInvitationNonce = list[1].decodeBytes()
            this.signature = list[2].decodeBytes()
            this.isResponse = list[3].decodeBoolean()
        }

        override val protocolMessageId: Int = PING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(groupMemberInvitationNonce),
                Encoded.of(signature),
                Encoded.of(isResponse),
            )
            }
    }

    class PropagatedPingMessage : PingMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            groupMemberInvitationNonce: ByteArray,
            signature: ByteArray,
            isResponse: Boolean
        ) : super(
            coreProtocolMessage,
            groupIdentifier,
            groupMemberInvitationNonce,
            signature,
            isResponse
        )

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATED_PING_MESSAGE_ID
    }

    open class KickMessage : ConcreteProtocolMessage {
        @JvmField val groupIdentifier: GroupV2.Identifier
        @JvmField val encryptedAdministratorsChain: EncryptedBytes
        @JvmField val signature: ByteArray

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            encryptedAdministratorsChain: EncryptedBytes,
            signature: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.encryptedAdministratorsChain = encryptedAdministratorsChain
            this.signature = signature
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 3) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.encryptedAdministratorsChain = list[1].decodeEncryptedData()
            this.signature = list[2].decodeBytes()
        }

        override val protocolMessageId: Int = KICK_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(encryptedAdministratorsChain),
                Encoded.of(signature),
            )
            }
    }

    class PropagatedKickMessage : KickMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            encryptedAdministratorsChain: EncryptedBytes,
            signature: ByteArray
        ) : super(coreProtocolMessage, groupIdentifier, encryptedAdministratorsChain, signature)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATED_KICK_MESSAGE_ID
    }


    class PropagateInvitationDialogResponseMessage : ConcreteProtocolMessage {
        internal val invitationAccepted: Boolean
        internal val ownGroupInvitationNonce: ByteArray

        internal constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            invitationAccepted: Boolean,
            ownGroupInvitationNonce: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.invitationAccepted = invitationAccepted
            this.ownGroupInvitationNonce = ownGroupInvitationNonce
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 2) {
                throw Exception()
            }
            this.invitationAccepted = list[0].decodeBoolean()
            this.ownGroupInvitationNonce = list[1].decodeBytes()
        }

        override val protocolMessageId: Int = PROPAGATE_INVITATION_DIALOG_RESPONSE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(invitationAccepted),
                Encoded.of(ownGroupInvitationNonce),
            )
            }
    }

    class PutGroupLogOnServerMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = PUT_GROUP_LOG_ON_SERVER_MESSAGE_ID
    }


    open class InvitationRejectedBroadcastMessage : ConcreteProtocolMessage {
        @JvmField val groupIdentifier: GroupV2.Identifier

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 1) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
        }

        override val protocolMessageId: Int = INVITATION_REJECTED_BROADCAST_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
            )
            }
    }


    class PropagateInvitationRejectedMessage : InvitationRejectedBroadcastMessage {
        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage, groupIdentifier)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = PROPAGATE_INVITATION_REJECTED_MESSAGE_ID
    }


    class GroupUpdateInitialMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val changeSet: ObvGroupV2ChangeSet


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            changeSet: ObvGroupV2ChangeSet
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.changeSet = changeSet
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
            this.changeSet = ObvGroupV2ChangeSet.of(inputs[1])
        }

        override val protocolMessageId: Int = GROUP_UPDATE_INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                changeSet.encode(),
            )
            }
    }

    class RequestLockMessage : DownloadGroupBlobMessage {
        internal constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage) : super(receivedMessage)

        override val protocolMessageId: Int = REQUEST_LOCK_MESSAGE_ID
    }

    class GroupLeaveInitialMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 1) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
        }

        override val protocolMessageId: Int = GROUP_LEAVE_INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
            )
            }
    }

    class PropagatedGroupLeaveMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val ownInvitationNonce: ByteArray


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            ownInvitationNonce: ByteArray
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.ownInvitationNonce = ownInvitationNonce
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
            this.ownInvitationNonce = inputs[1].decodeBytes()
        }

        override val protocolMessageId: Int = PROPAGATED_GROUP_LEAVE_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(ownInvitationNonce),
            )
            }
    }


    class GroupDisbandInitialMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier


        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 1) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
        }

        override val protocolMessageId: Int = GROUP_DISBAND_INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
            )
            }
    }

    class PropagatedGroupDisbandMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 1) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
        }

        override val protocolMessageId: Int = PROPAGATED_GROUP_DISBAND_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
            )
            }
    }

    class GroupReDownloadInitialMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
        }


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 1) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(inputs[0])
        }

        override val protocolMessageId: Int = GROUP_RE_DOWNLOAD_INITIAL_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
            )
            }
    }


    class InitiateBatchKeysResendMessage : ConcreteProtocolMessage {
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


        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 2) {
                throw Exception()
            }
            this.contactIdentity = inputs[0].decodeIdentity()
            this.contactDeviceUid = inputs[1].decodeUid()
        }

        override val protocolMessageId: Int = INITIATE_BATCH_KEYS_RESEND_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(contactIdentity),
                Encoded.of(contactDeviceUid),
            )
            }
    }


    class BlobKeysBatchAfterChannelCreationMessage : ConcreteProtocolMessage {
        internal val groupInfos: Array<IdentifierVersionAndKeys>

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInfos: Array<IdentifierVersionAndKeys>
        ) : super(coreProtocolMessage!!) {
            this.groupInfos = groupInfos
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val inputs = receivedMessage.inputs
            if (inputs.size != 1) {
                throw Exception()
            }
            val encodeds: Array<Encoded> = inputs[0].decodeList()
            @Suppress("UNCHECKED_CAST")
            this.groupInfos = arrayOfNulls<IdentifierVersionAndKeys>(encodeds.size) as Array<IdentifierVersionAndKeys>
            for (i in encodeds.indices) {
                this.groupInfos[i] = IdentifierVersionAndKeys(encodeds[i])
            }
        }

        override val protocolMessageId: Int = BLOB_KEYS_BATCH_AFTER_CHANNEL_CREATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val encodeds = arrayOfNulls<Encoded>(groupInfos.size)
            for (i in groupInfos.indices) {
                encodeds[i] = groupInfos[i].encode()
            }
            return arrayOf<Encoded>(
                Encoded.of(encodeds.requireNoNulls()),
            )
            }
    }

    class BlobKeysAfterChannelCreationMessage : ConcreteProtocolMessage {
        internal val groupInviter: Identity
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val blobKeys: BlobKeys

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupInviter: Identity,
            groupIdentifier: GroupV2.Identifier,
            groupVersion: Int,
            blobKeys: BlobKeys
        ) : super(coreProtocolMessage!!) {
            this.groupInviter = groupInviter
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.blobKeys = blobKeys
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 4) {
                throw Exception()
            }
            this.groupInviter = list[0].decodeIdentity()
            this.groupIdentifier = GroupV2.Identifier.of(list[1])
            this.groupVersion = list[2].decodeLong().toInt()
            this.blobKeys = BlobKeys.of(list[3])
        }

        override val protocolMessageId: Int = BLOB_KEYS_AFTER_CHANNEL_CREATION_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                Encoded.of(groupInviter),
                groupIdentifier.encode(),
                Encoded.of(groupVersion.toLong()),
                blobKeys.encode(),
            )
            }
    }

    class CreateOrUpdateKeycloakGroupMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val serializedKeycloakGroupBlob: String

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            serializedKeycloakGroupBlob: String
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.serializedKeycloakGroupBlob = serializedKeycloakGroupBlob
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.serializedKeycloakGroupBlob = list[1].decodeString()
        }

        override val protocolMessageId: Int = CREATE_OR_UPDATE_KEYCLOAK_GROUP_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
            val jsonObjectMapper = ObjectMapper()
            jsonObjectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL)
            return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(serializedKeycloakGroupBlob),
            )
            }
    }

    class InitiateTargetedPingMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val pendingMemberIdentity: Identity

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            pendingMemberIdentity: Identity
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.pendingMemberIdentity = pendingMemberIdentity
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.pendingMemberIdentity = list[1].decodeIdentity()
        }

        override val protocolMessageId: Int = INITIATE_TARGETED_PING_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                groupIdentifier.encode(),
                Encoded.of(pendingMemberIdentity),
            )
            }
    }

    class PreShotVersionSeedMessage : ConcreteProtocolMessage {
        internal val groupIdentifier: GroupV2.Identifier
        internal val versionSeed: Seed

        constructor(
            coreProtocolMessage: CoreProtocolMessage?,
            groupIdentifier: GroupV2.Identifier,
            versionSeed: Seed
        ) : super(coreProtocolMessage!!) {
            this.groupIdentifier = groupIdentifier
            this.versionSeed = versionSeed
        }

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(CoreProtocolMessage(receivedMessage!!)) {
            val list = receivedMessage.inputs
            if (list.size != 2) {
                throw Exception()
            }
            this.groupIdentifier = GroupV2.Identifier.of(list[0])
            this.versionSeed = list[1].decodeSeed()
        }

        override val protocolMessageId: Int = PRE_SHOT_VERSION_SEED_MESSAGE_ID

        override val inputs: Array<Encoded>
            get() {
                return arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(versionSeed),
                )
            }
    }

    class AutoAcceptInvitationMessage : EmptyProtocolMessage {
        constructor(coreProtocolMessage: CoreProtocolMessage?) : super(coreProtocolMessage!!)

        @Suppress("unused")
        constructor(receivedMessage: ReceivedMessage?) : super(receivedMessage)

        override val protocolMessageId: Int = AUTO_ACCEPT_INVITATION_MESSAGE
    }


    // endregion
    // region Steps
    override fun getPossibleStepClasses(stateId: Int): Array<Class<*>> {
        when (stateId) {
            ConcreteProtocol.INITIAL_STATE_ID -> return arrayOf<Class<*>>(
                InitiateGroupCreationStep::class.java,
                ProcessInvitationOrMembersUpdateStep::class.java,
                DoNothingAfterServerQueryStep::class.java,
                ProcessPingStep::class.java,
                InitiateBlobReDownloadStep::class.java,
                InitiateGroupUpdateStep::class.java,
                GetKickedStep::class.java,
                LeaveGroupStep::class.java,
                DisbandGroupStep::class.java,
                PrepareBatchKeysMessageStep::class.java,
                ProcessBatchKeysMessageStep::class.java,
                ProcessCreateOrUpdateKeycloakGroupMessage::class.java,
                SendKeycloakGroupTargetedPingStep::class.java,
                ProcessReceivedPreShotVersionSeedStep::class.java
            )

            UPLOADING_CREATED_GROUP_DATA_STATE_ID -> return arrayOf<Class<*>>(
                CheckIfGroupCreationCanBeFinalizedStep::class.java,
                FinalizeGroupCreationStep::class.java
            )

            DOWNLOADING_GROUP_BLOB_STATE_ID -> return arrayOf<Class<*>>(
                ProcessDownloadedGroupDataStep::class.java,
                ProcessInvitationDialogResponseStep::class.java,
                LeaveGroupStep::class.java,
                GetKickedStep::class.java,
                DisbandGroupStep::class.java,
                ProcessReceivedPreShotVersionSeedStep::class.java
            )

            I_NEED_MORE_SEEDS_STATE_ID -> return arrayOf<Class<*>>(
                ProcessInvitationOrMembersUpdateStep::class.java,
                ProcessInvitationDialogResponseStep::class.java,
                LeaveGroupStep::class.java,
                GetKickedStep::class.java,
                DisbandGroupStep::class.java,
                InitiateBlobReDownloadStep::class.java
            )

            INVITATION_RECEIVED_STATE_ID -> return arrayOf<Class<*>>(
                ProcessInvitationOrMembersUpdateStep::class.java,
                ProcessInvitationDialogResponseStep::class.java,
                InitiateBlobReDownloadStep::class.java,
                GetKickedStep::class.java,
                DisbandGroupStep::class.java,
                ProcessReceivedPreShotVersionSeedStep::class.java
            )

            REJECTING_INVITATION_OR_LEAVING_GROUP_STATE_ID -> return arrayOf<Class<*>>(
                NotifyMembersOfRejectionOrGroupLeftStep::class.java
            )

            WAITING_FOR_LOCK_STATE_ID -> return arrayOf<Class<*>>(
                PrepareBlobForGroupUpdateStep::class.java,
                GetKickedStep::class.java,
                LeaveGroupStep::class.java,
                DisbandGroupStep::class.java,
                ProcessReceivedPreShotVersionSeedStep::class.java
            )

            UPLOADING_UPDATED_GROUP_BLOB_STATE_ID -> return arrayOf<Class<*>>(
                ProcessGroupUpdateBlobUploadResponseStep::class.java,
                DisbandGroupStep::class.java
            )

            UPLOADING_UPDATED_GROUP_PHOTO_STATE_ID -> return arrayOf<Class<*>>(
                ProcessGroupUpdatePhotoUploadResponseStep::class.java,
                FinalizeGroupUpdateStep::class.java,
                DisbandGroupStep::class.java
            )

            DISBANDING_GROUP_STATE_ID -> return arrayOf<Class<*>>(FinalizeGroupDisbandStep::class.java)
            else -> return arrayOf<Class<*>>()
        }
    }

    class InitiateGroupCreationStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: GroupCreationInitialMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            // no need to check that group members are indeed contacts, this will be checked in createNewGroupV2
            val chain: AdministratorsChain?
            run {
                val otherAdmins: MutableList<Identity?> = ArrayList<Identity?>()
                for (groupMember in receivedMessage.otherGroupMembers) {
                    if (groupMember.isAdmin) {
                        otherAdmins.add(groupMember.identity)
                    }
                }

                // compute the first blockchain block
                chain = startNewChain(
                    protocolManagerSession.session,
                    protocolManagerSession.identityDelegate!!,
                    ownedIdentity,
                    otherAdmins.toTypedArray<Identity?>(),
                    prng
                )
            }

            val verifiedAdministratorsChain = chain!!.encode().bytes
            val groupIdentifier = GroupV2.Identifier(
                chain.groupUid,
                ownedIdentity.server,
                GroupV2.Identifier.CATEGORY_SERVER
            )
            val serverPhotoInfo =
                if (receivedMessage.absolutePhotoUrl == null) null else ServerPhotoInfo(
                    ownedIdentity,
                    UID(prng),
                    Suite.getDefaultAuthEnc(0).generateKey(prng)!!
                )
            val blobMainSeed = Seed(prng)
            val blobVersionSeed = Seed(prng)
            val groupAdminServerAuthenticationKeyPair =
                Suite.generateServerAuthenticationKeyPair(null, prng)
            val ownGroupInvitationNonce =
                prng.bytes(Constants.GROUP_V2_INVITATION_NONCE_LENGTH)
            run {
                // create the group in database
                val otherGroupMembers = HashSet<IdentityAndPermissionsAndDetails?>()
                for (identityAndPermissions in receivedMessage.otherGroupMembers) {
                    val permissionStrings: MutableList<String> = ArrayList<String>()
                    for (permission in identityAndPermissions.permissions) {
                        permissionStrings.add(permission.string)
                    }
                    val serializedContactDetails =
                        protocolManagerSession.identityDelegate!!.getSerializedPublishedDetailsOfContactIdentity(
                            protocolManagerSession.session,
                            ownedIdentity,
                            identityAndPermissions.identity
                        )
                    otherGroupMembers.add(
                        IdentityAndPermissionsAndDetails(
                            identityAndPermissions.identity,
                            permissionStrings,
                            serializedContactDetails!!,
                            prng.bytes(Constants.GROUP_V2_INVITATION_NONCE_LENGTH)
                        )
                    )
                }

                val ownPermissionStrings: MutableList<String?> = ArrayList<String?>()
                for (permission in receivedMessage.ownPermissions) {
                    ownPermissionStrings.add(permission.string)
                }

                // this create a frozen group, so no need to freeze in this step
                protocolManagerSession.identityDelegate!!.createNewGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier,
                    receivedMessage.serializedGroupDetails,
                    receivedMessage.absolutePhotoUrl,
                    serverPhotoInfo,
                    verifiedAdministratorsChain,
                    BlobKeys(
                        blobMainSeed,
                        blobVersionSeed,
                        groupAdminServerAuthenticationKeyPair!!.getPrivateKey() as ServerAuthenticationPrivateKey
                    ),
                    ownGroupInvitationNonce,
                    ownPermissionStrings,
                    otherGroupMembers,
                    receivedMessage.serializedGroupType
                )
            }

            val serverBlob = protocolManagerSession.identityDelegate!!.getGroupV2ServerBlob(
                protocolManagerSession.session,
                ownedIdentity,
                groupIdentifier
            )

            if (serverBlob == null) {
                throw Exception("Failed to retrieve serverBlob from a just created group")
            }

            val encryptedBlob: EncryptedBytes
            run {
                // compute the encoded, signed, padded, and encrypted blob from the ServerBlob we have
                val encodedServerBlob = serverBlob.encode()
                val signature = protocolManagerSession.identityDelegate.signBlock(
                    protocolManagerSession.session,
                    Constants.SignatureContext.GROUP_BLOB,
                    encodedServerBlob.bytes,
                    ownedIdentity,
                    prng
                )

                val encodedSignedBlob = Encoded.of(
                    arrayOf<Encoded>(
                        encodedServerBlob,
                        Encoded.of(ownedIdentity),
                        Encoded.of(signature!!),
                    )
                )

                val unpaddedLength = encodedSignedBlob.bytes.size
                val paddedLength =
                    (1 + ((unpaddedLength - 1) shr 12)) shl 12 // we pad to the smallest multiple of 4096 larger than the actual length

                val paddedBlobPlaintext = ByteArray(paddedLength)
                System.arraycopy(encodedSignedBlob.bytes, 0, paddedBlobPlaintext, 0, unpaddedLength)
                val blobEncryptionKey = getSharedBlobSecretKey(blobMainSeed, blobVersionSeed)
                encryptedBlob = Suite.getAuthEnc(blobEncryptionKey)!!
                    .encrypt(blobEncryptionKey, paddedBlobPlaintext, prng)
            }


            if (serverBlob.serverPhotoInfo != null) {
                // upload the group photo if needed

                val photoUrl = protocolManagerSession.identityDelegate.getGroupV2PhotoUrl(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )

                if (photoUrl != null) {
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            PutUserDataQuery(
                                ownedIdentity,
                                serverBlob.serverPhotoInfo.serverPhotoLabel,
                                photoUrl,
                                serverBlob.serverPhotoInfo.serverPhotoKey
                            )
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        GroupsV2Protocol.UploadGroupPhotoMessage(coreProtocolMessage)
                            .generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }


            run {
                // upload the encrypted blob
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        CreateGroupBlobQuery(
                            groupIdentifier,
                            Encoded.of(groupAdminServerAuthenticationKeyPair!!.getPublicKey()),
                            encryptedBlob
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    UploadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return UploadingCreatedGroupDataState(
                groupIdentifier,
                serverBlob.version,
                true,
                serverBlob.serverPhotoInfo != null
            )
        }
    }


    class CheckIfGroupCreationCanBeFinalizedStep : ProtocolStep {
        private enum class UploadType {
            BLOB,
            PHOTO,
        }

        internal val startState: UploadingCreatedGroupDataState
        private val uploadType: UploadType
        internal val uploadResult: Int

        @Suppress("unused")
        constructor(
            startState: UploadingCreatedGroupDataState,
            receivedMessage: UploadGroupPhotoMessage?,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.uploadType = UploadType.PHOTO
            this.uploadResult = 0
        }

        @Suppress("unused")
        constructor(
            startState: UploadingCreatedGroupDataState,
            receivedMessage: UploadGroupBlobMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.uploadType = UploadType.BLOB
            this.uploadResult = receivedMessage.uploadResult
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            val groupIdentifier = startState.groupIdentifier
            var waitingForBlobUpload = startState.waitingForBlobUpload
            var waitingForPhotoUpload = startState.waitingForPhotoUpload

            when (uploadType) {
                UploadType.BLOB -> {
                    if (uploadResult == 0) {
                        waitingForBlobUpload = false
                    } else {
                        // we were not able to upload the blob to the server --> delete the group
                        protocolManagerSession.identityDelegate!!.deleteGroupV2(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupIdentifier,
                            null
                        )
                        return FinalState()
                    }
                }

                UploadType.PHOTO -> waitingForPhotoUpload = false
            }

            if (!waitingForBlobUpload && !waitingForPhotoUpload) {
                // if there is nothing left to upload, post a message to initiate the finalization of the group creation
                val coreProtocolMessage =
                    buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                val messageToSend: ChannelMessageToSend? =
                    FinalizeGroupCreationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return UploadingCreatedGroupDataState(
                groupIdentifier,
                startState.groupVersion,
                waitingForBlobUpload,
                waitingForPhotoUpload
            )
        }
    }


    class FinalizeGroupCreationStep(
        internal val startState: UploadingCreatedGroupDataState, @field:Suppress(
            "unused"
        ) internal val receivedMessage: FinalizeGroupCreationMessage?, protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            run {
                // for each group member send
                //  - the main seed
                //  - the version seed
                //  - for admins the groupAdmin private key
                // send the message through oblivious channel
                val blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
                val groupMembersAndPermissions =
                    protocolManagerSession.identityDelegate.getGroupV2OtherMembersAndPermissions(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.groupIdentifier
                    )
                if ((blobKeys == null) || (blobKeys.groupAdminServerAuthenticationPrivateKey == null) || (groupMembersAndPermissions == null)) {
                    // we are unable to retrieve basic group information --> delete the group we created before inviting anyone
                    protocolManagerSession.identityDelegate.deleteGroupV2(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.groupIdentifier,
                        null
                    )
                    return FinalState()
                }

                val invitationProtocolInstanceUid =
                    startState.groupIdentifier.computeProtocolInstanceUid()

                // here we loop on OTHER group members, not ourself
                for (groupMembersAndPermission in groupMembersAndPermissions) {
                    val contactDeviceUidsWithChannel =
                        protocolManagerSession.channelDelegate!!.getConfirmedObliviousChannelOrPreKeyDeviceUids(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupMembersAndPermission!!.identity
                        )
                    if (contactDeviceUidsWithChannel.size > 0) {
                        val keysToSend = BlobKeys(
                            blobKeys.blobMainSeed,
                            blobKeys.blobVersionSeed,
                            if (groupMembersAndPermission.isAdmin) blobKeys.groupAdminServerAuthenticationPrivateKey else null
                        )

                        val coreProtocolMessage = CoreProtocolMessage(
                            createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                groupMembersAndPermission.identity,
                                ownedIdentity
                            ),
                            protocolId,
                            invitationProtocolInstanceUid
                        )
                        val messageToSend: ChannelMessageToSend? = InvitationOrMembersUpdateMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier,
                            startState.groupVersion,
                            keysToSend,
                            contactDeviceUidsWithChannel
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } else {
                        // we have a problem, we invited a member with whom we do not have a channel...
                        // rollback everything and delete the group
                        protocolManagerSession.session.rollback()
                        protocolManagerSession.session.startTransaction()
                        protocolManagerSession.identityDelegate.deleteGroupV2(
                            protocolManagerSession.session,
                            ownedIdentity,
                            startState.groupIdentifier,
                            null
                        )

                        // delete the group from the server
                        val signature = Signature.sign(
                            Constants.SignatureContext.GROUP_DELETE_ON_SERVER,
                            blobKeys.groupAdminServerAuthenticationPrivateKey.signaturePrivateKey,
                            prng
                        )
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createServerQueryChannelInfo(
                                ownedIdentity,
                                DeleteGroupBlobQuery(startState.groupIdentifier, signature!!)
                            )
                        )
                        val messageToSend: ChannelMessageToSend? =
                            DeleteGroupBlobFromServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                        protocolManagerSession.channelDelegate.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )

                        return FinalState()
                    }
                }

                // also notify other owned devices
                val allOwnedDeviceUids =
                    protocolManagerSession.identityDelegate.getDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )
                if (allOwnedDeviceUids!!.size > 1) {
                    try {
                        val keysToSend = BlobKeys(
                            blobKeys.blobMainSeed,
                            blobKeys.blobVersionSeed,
                            blobKeys.groupAdminServerAuthenticationPrivateKey
                        )

                        val coreProtocolMessage = CoreProtocolMessage(
                            createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                ownedIdentity,
                                ownedIdentity
                            ),
                            protocolId,
                            invitationProtocolInstanceUid
                        )
                        // we send the full set of owned devices, not only "other" own device uid, so that receiving devices know if all devices were notified
                        val messageToSend: ChannelMessageToSend? = InvitationOrMembersUpdateMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier,
                            startState.groupVersion,
                            keysToSend,
                            allOwnedDeviceUids
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
                // also unfreeze the group
                protocolManagerSession.identityDelegate!!.unfreezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
            }


            return FinalState()
        }
    }


    class ProcessInvitationOrMembersUpdateStep : ProtocolStep {
        internal val obliviousChannelContactIdentity: Identity?
        internal val startState: ConcreteProtocolState?
        internal val invitationCollectedData: InvitationCollectedData
        internal val dialogUuid: UUID?
        internal val ownInvitationNoncesAcceptedOnOtherDevices: Array<ByteArray?>
        internal val lastKnownOwnInvitationNonce: ByteArray?
        internal val lastKnownOtherGroupMemberIdentities: Array<Identity>?

        // elements from the received message
        internal val groupIdentifier: GroupV2.Identifier
        internal val groupVersion: Int
        internal val blobKeys: BlobKeys
        internal val notifiedDeviceUids: Array<UID?>
        internal val propagateIfNeeded: Boolean


        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InvitationOrMembersUpdateMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity =
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
            this.startState = null
            this.invitationCollectedData = InvitationCollectedData()
            this.dialogUuid = UUID.randomUUID()
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = null
            this.lastKnownOtherGroupMemberIdentities = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = receivedMessage.notifiedDeviceUids
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InvitationOrMembersUpdateBroadcastMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = null
            this.startState = null
            this.invitationCollectedData = InvitationCollectedData()
            this.dialogUuid = UUID.randomUUID()
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = null
            this.lastKnownOtherGroupMemberIdentities = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            // never consider a mainSeed received through an asymmetric channel, IT'S A TRAP!
            this.blobKeys = BlobKeys(
                null,
                receivedMessage.blobKeys.blobVersionSeed,
                receivedMessage.blobKeys.groupAdminServerAuthenticationPrivateKey
            )
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InvitationOrMembersUpdatePropagatedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.inviterIdentity
            this.startState = null
            this.invitationCollectedData = InvitationCollectedData()
            this.dialogUuid = UUID.randomUUID()
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = null
            this.lastKnownOtherGroupMemberIdentities = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: BlobKeysAfterChannelCreationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.groupInviter
            this.startState = null
            this.invitationCollectedData = InvitationCollectedData()
            this.dialogUuid = UUID.randomUUID()
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = null
            this.lastKnownOtherGroupMemberIdentities = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }


        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: InvitationOrMembersUpdateMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity =
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
            this.startState = startState
            this.invitationCollectedData = startState.invitationCollectedData
            this.dialogUuid = startState.dialogUuid
            this.ownInvitationNoncesAcceptedOnOtherDevices =
                startState.ownInvitationNoncesAcceptedOnOtherDevices
            this.lastKnownOwnInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.lastKnownOtherGroupMemberIdentities =
                startState.lastKnownOtherGroupMemberIdentities
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = receivedMessage.notifiedDeviceUids
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: InvitationOrMembersUpdateBroadcastMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = null
            this.startState = startState
            this.invitationCollectedData = startState.invitationCollectedData
            this.dialogUuid = startState.dialogUuid
            this.ownInvitationNoncesAcceptedOnOtherDevices =
                startState.ownInvitationNoncesAcceptedOnOtherDevices
            this.lastKnownOwnInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.lastKnownOtherGroupMemberIdentities =
                startState.lastKnownOtherGroupMemberIdentities
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            // never consider a mainSeed received through an asymmetric channel, IT'S A TRAP!
            this.blobKeys = BlobKeys(
                null,
                receivedMessage.blobKeys.blobVersionSeed,
                receivedMessage.blobKeys.groupAdminServerAuthenticationPrivateKey
            )
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: InvitationOrMembersUpdatePropagatedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.inviterIdentity
            this.startState = startState
            this.invitationCollectedData = startState.invitationCollectedData
            this.dialogUuid = startState.dialogUuid
            this.ownInvitationNoncesAcceptedOnOtherDevices =
                startState.ownInvitationNoncesAcceptedOnOtherDevices
            this.lastKnownOwnInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.lastKnownOtherGroupMemberIdentities =
                startState.lastKnownOtherGroupMemberIdentities
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: BlobKeysAfterChannelCreationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.groupInviter
            this.startState = startState
            this.invitationCollectedData = startState.invitationCollectedData
            this.dialogUuid = startState.dialogUuid
            this.ownInvitationNoncesAcceptedOnOtherDevices =
                startState.ownInvitationNoncesAcceptedOnOtherDevices
            this.lastKnownOwnInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.lastKnownOtherGroupMemberIdentities =
                startState.lastKnownOtherGroupMemberIdentities
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }


        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: InvitationOrMembersUpdateMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity =
                receivedMessage.receptionChannelInfo!!.getRemoteIdentity()
            this.startState = startState

            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )

            this.dialogUuid = startState.dialogUuid
            var nonce: ByteArray? = null
            val identities: MutableList<Identity?> = ArrayList<Identity?>()
            for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                    nonce = identityAndPermissionsAndDetails.groupInvitationNonce
                    continue
                }
                identities.add(identityAndPermissionsAndDetails.identity)
            }
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = nonce
            @Suppress("UNCHECKED_CAST")
            this.lastKnownOtherGroupMemberIdentities = identities.toTypedArray<Identity?>() as Array<Identity>
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = receivedMessage.notifiedDeviceUids
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: InvitationOrMembersUpdateBroadcastMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = null
            this.startState = startState

            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )

            this.dialogUuid = startState.dialogUuid
            var nonce: ByteArray? = null
            val identities: MutableList<Identity?> = ArrayList<Identity?>()
            for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                    nonce = identityAndPermissionsAndDetails.groupInvitationNonce
                    continue
                }
                identities.add(identityAndPermissionsAndDetails.identity)
            }
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = nonce
            @Suppress("UNCHECKED_CAST")
            this.lastKnownOtherGroupMemberIdentities = identities.toTypedArray<Identity?>() as Array<Identity>
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            // never consider a mainSeed received through an asymmetric channel, IT'S A TRAP!
            this.blobKeys = BlobKeys(
                null,
                receivedMessage.blobKeys.blobVersionSeed,
                receivedMessage.blobKeys.groupAdminServerAuthenticationPrivateKey
            )
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: InvitationOrMembersUpdatePropagatedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.inviterIdentity
            this.startState = startState

            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )

            this.dialogUuid = startState.dialogUuid
            var nonce: ByteArray? = null
            val identities: MutableList<Identity?> = ArrayList<Identity?>()
            for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                    nonce = identityAndPermissionsAndDetails.groupInvitationNonce
                    continue
                }
                identities.add(identityAndPermissionsAndDetails.identity)
            }
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = nonce
            @Suppress("UNCHECKED_CAST")
            this.lastKnownOtherGroupMemberIdentities = identities.toTypedArray<Identity?>() as Array<Identity>
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: BlobKeysAfterChannelCreationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.obliviousChannelContactIdentity = receivedMessage.groupInviter
            this.startState = startState

            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )

            this.dialogUuid = startState.dialogUuid
            var nonce: ByteArray? = null
            val identities: MutableList<Identity?> = ArrayList<Identity?>()
            for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                    nonce = identityAndPermissionsAndDetails.groupInvitationNonce
                    continue
                }
                identities.add(identityAndPermissionsAndDetails.identity)
            }
            this.ownInvitationNoncesAcceptedOnOtherDevices = arrayOfNulls<ByteArray>(0)
            this.lastKnownOwnInvitationNonce = nonce
            @Suppress("UNCHECKED_CAST")
            this.lastKnownOtherGroupMemberIdentities = identities.toTypedArray<Identity?>() as Array<Identity>
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.groupVersion = receivedMessage.groupVersion
            this.blobKeys = receivedMessage.blobKeys
            this.notifiedDeviceUids = arrayOfNulls<UID>(0)
            this.propagateIfNeeded = false
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // first check that the protocolInstanceUid matches the groupIdentifier
                if (!protocolInstanceUid!!.equals(groupIdentifier.computeProtocolInstanceUid())) {
                    if (startState != null) {
                        return startState
                    } else {
                        return FinalState()
                    }
                }
            }

            run {
                // if the sender could not send the message to all devices, propagate it to other owned devices, if any
                // only propagate if the message was received from a contact, not another owned device
                if (propagateIfNeeded && (obliviousChannelContactIdentity == null || obliviousChannelContactIdentity != ownedIdentity)) {
                    val otherOwnedDeviceUids =
                        protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                            protocolManagerSession.session,
                            ownedIdentity
                        )

                    val notNotifiedUids = HashSet<UID?>(Arrays.asList<UID?>(*otherOwnedDeviceUids!!))
                    for (deviceUid in notifiedDeviceUids) {
                        notNotifiedUids.remove(deviceUid)
                    }

                    if (!notNotifiedUids.isEmpty()) {
                        try {
                            val coreProtocolMessage = buildCoreProtocolMessage(
                                createObliviousChannelOrPreKeyInfo(
                                    ownedIdentity,
                                    ownedIdentity,
                                    notNotifiedUids.toTypedArray<UID?>(),
                                    true
                                )
                            )
                            val messageToSend: ChannelMessageToSend? =
                                InvitationOrMembersUpdatePropagatedMessage(
                                    coreProtocolMessage,
                                    groupIdentifier,
                                    groupVersion,
                                    blobKeys,
                                    obliviousChannelContactIdentity
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
            }

            run {
                if (startState is InvitationReceivedState) {
                    // if still in InvitationReceivedState, check the version and trigger a re-download if necessary
                    if (startState.serverBlob.version > groupVersion
                        || (startState.serverBlob.version == groupVersion && obliviousChannelContactIdentity != ownedIdentity)
                    ) {
                        return startState
                    }


                    // freeze the invitation while we update the blob
                    val groupV2PendingMembers = HashSet<ObvGroupV2PendingMember>()
                    var ownPermissions = HashSet<GroupV2.Permission>()
                    for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                        if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                            @Suppress("UNCHECKED_CAST")
                            ownPermissions =
                                GroupV2.Permission.fromStrings(identityAndPermissionsAndDetails.permissionStrings as MutableCollection<String?>)
                            continue
                        }
                        groupV2PendingMembers.add(
                            ObvGroupV2PendingMember(
                                identityAndPermissionsAndDetails.identity.getBytes(),
                                @Suppress("UNCHECKED_CAST")
                                GroupV2.Permission.fromStrings(identityAndPermissionsAndDetails.permissionStrings as MutableCollection<String?>),
                                identityAndPermissionsAndDetails.serializedIdentityDetails
                            )
                        )
                    }

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity, createGroupV2FrozenInvitationDialog(
                                startState.inviterIdentity, ObvGroupV2(
                                    ownedIdentity.getBytes(),
                                    startState.groupIdentifier,
                                    ownPermissions,
                                    null,
                                    groupV2PendingMembers,
                                    startState.serverBlob.serializedGroupDetails,
                                    null, null, null, 0
                                )
                            ), startState.dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogAcceptGroupInvitationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            // check if we already joined this group
            val dbGroupVersion = protocolManagerSession.identityDelegate!!.getGroupV2Version(
                protocolManagerSession.session,
                ownedIdentity,
                groupIdentifier
            )
            if (dbGroupVersion != null) {
                // if we joined this group and the obliviousChannelContactIdentity is still a pending member, there is a problem! We send him a ping
                if (dbGroupVersion <= groupVersion && obliviousChannelContactIdentity != null && protocolManagerSession.identityDelegate.isIdentityAPendingGroupV2Member(
                        protocolManagerSession.session,
                        ownedIdentity,
                        groupIdentifier,
                        obliviousChannelContactIdentity
                    )
                ) {
                    val ownGroupInvitationNonce =
                        protocolManagerSession.identityDelegate.getGroupV2OwnGroupInvitationNonce(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupIdentifier
                        )
                    if (ownGroupInvitationNonce != null) {
                        val pingSignature =
                            protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                protocolManagerSession.session,
                                Constants.SignatureContext.GROUP_JOIN_NONCE,
                                groupIdentifier,
                                ownGroupInvitationNonce,
                                obliviousChannelContactIdentity,
                                ownedIdentity,
                                prng
                            )

                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAsymmetricBroadcastChannelInfo(
                                obliviousChannelContactIdentity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                            coreProtocolMessage,
                            groupIdentifier,
                            ownGroupInvitationNonce,
                            pingSignature!!,
                            false
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }


                if (dbGroupVersion >= groupVersion) {
                    // we already have a more recent version of this group, ignore the message
                    if (startState != null) {
                        return startState
                    } else {
                        return FinalState()
                    }
                }
            }

            /**//////////// */
            // see what was already collected, and augment it with what we received/what we have in db
            if (dbGroupVersion != null) {
                // if we already joined the group, retrieve blobKeys from db
                val blobKeys = protocolManagerSession.identityDelegate.getGroupV2BlobKeys(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
                // add the mainSeed as a "ownedIdentity" candidate...
                invitationCollectedData.addBlobKeysCandidates(ownedIdentity, blobKeys!!)

                // freeze the group
                protocolManagerSession.identityDelegate.freezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
            }

            invitationCollectedData.addBlobKeysCandidates(obliviousChannelContactIdentity, blobKeys)

            val serverQueryNonce = prng.bytes(16)
            run {
                // run the server query to download the server blob
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        GetGroupBlobQuery(groupIdentifier, serverQueryNonce)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DownloadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return DownloadingGroupBlobState(
                groupIdentifier,
                dialogUuid,
                invitationCollectedData,
                ownInvitationNoncesAcceptedOnOtherDevices,
                lastKnownOwnInvitationNonce,
                lastKnownOtherGroupMemberIdentities,
                serverQueryNonce
            )
        }
    }

    class ProcessDownloadedGroupDataStep @Suppress("unused") constructor(
        internal val startState: DownloadingGroupBlobState,
        internal val receivedMessage: DownloadGroupBlobMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            run {
                if (receivedMessage.serverQueryNonce != null && !receivedMessage.serverQueryNonce.contentEquals(
                        startState.serverQueryNonce
                    )
                ) {
                    // this serverQuery response was for another request, ignore it!
                    return startState
                }
            }

            run {
                if (receivedMessage.encryptedServerBlob == null || receivedMessage.logEntries == null || receivedMessage.groupAdminPublicKey == null) {
                    // the server does not have a group with that identifier, there is nothing we can do --> abort the protocol
                    if (receivedMessage.deletedFromServer) {
                        // blob was deleted from server --> delete the group locally too
                        protocolManagerSession.identityDelegate!!.deleteGroupV2(
                            protocolManagerSession.session,
                            ownedIdentity,
                            startState.groupIdentifier,
                            null
                        )
                        GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                            protocolManagerSession,
                            ownedIdentity,
                            startState.groupIdentifier
                        )
                    }

                    // remove the dialog if any
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

                    // unfreeze the group anyway as we will be in FinalState
                    protocolManagerSession.identityDelegate!!.unfreezeGroupV2(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.groupIdentifier
                    )

                    return FinalState()
                }
            }


            run {
                // try to decrypt the downloaded blob
                for (inviterIdentityAndBlobMainSeedCandidate in startState.invitationCollectedData.inviterIdentityAndBlobMainSeedCandidates.entries) {

                    // Add the received pre-shot version seeds to the candidates we already collected
                    // we use a LinkedHashSet so that collected seeds are tried first, before the pre-shot seeds
                    val allVersionSeeds: MutableSet<Seed> =
                        LinkedHashSet(startState.invitationCollectedData.blobVersionSeedCandidates)
                    for (groupV2PreShotVersionSeedReceived in GroupV2PreShotVersionSeedReceived.getAllForGroupIdentifier(
                            protocolManagerSession,
                            ownedIdentity,
                            startState.groupIdentifier
                        )) {
                        allVersionSeeds.add(groupV2PreShotVersionSeedReceived.versionSeed)
                    }

                    for (blobVersionSeed in allVersionSeeds) {
                        val authEncKey = GroupV2.getSharedBlobSecretKey(
                            inviterIdentityAndBlobMainSeedCandidate.value!!,
                            blobVersionSeed
                        )
                        try {
                            val paddedBlobPlaintext = Suite.getAuthEnc(authEncKey)!!
                                .decrypt(authEncKey, receivedMessage.encryptedServerBlob)!!
                            val encodeds: Array<Encoded> =
                                Encoded(paddedBlobPlaintext).decodeListWithPadding()

                            val serverBlob = ServerBlob.of(encodeds[0])
                            val signerIdentity = encodeds[1].decodeIdentity()
                            val signature = encodeds[2].decodeBytes()

                            // check the administrators chain
                            try {
                                serverBlob.administratorsChain.withCheckedIntegrity(
                                    serverBlob.administratorsChain.groupUid,
                                    signerIdentity,
                                    protocolManagerSession.identityDelegate!!.getGroupV2AdministratorsChain(
                                        protocolManagerSession.session,
                                        ownedIdentity,
                                        startState.groupIdentifier
                                    )
                                )
                            } catch (_: Exception) {
                                Logger.w("Downloaded a group blob with invalid administratorsChain")
                                throw DecodingException()
                            }


                            // check the signature
                            if (!Signature.verify(
                                    Constants.SignatureContext.GROUP_BLOB,
                                    encodeds[0].bytes,
                                    signerIdentity,
                                    signature
                                )
                            ) {
                                Logger.w("Downloaded a group blob with invalid signature")
                                throw DecodingException()
                            }

                            // check that admins match the administratorsChain
                            run {
                                val blobAdmins = HashSet<Identity?>()
                                for (member in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                                    if (member.permissionStrings.contains(GroupV2.Permission.GROUP_ADMIN.string)) {
                                        blobAdmins.add(member.identity)
                                    }
                                }
                                val chainAdmins = serverBlob.administratorsChain.adminIdentities
                                if (blobAdmins != chainAdmins) {
                                    Logger.w("Downloaded a group blob with non-matching admins in AdministratorsChain")
                                    throw DecodingException()
                                }
                            }

                            /**////// */
                            // if we reach this point, we have the right seeds and a valid decrypted blob
                            /**//////////// */
                            // process the received log to remove people who left the group (including myself sometimes...)
                            val leavers = serverBlob.consolidateWithLogEntries(
                                startState.groupIdentifier,
                                receivedMessage.logEntries!!
                            )

                            // check whether I am indeed part of the group
                            var ownIdentityAndPermissions: IdentityAndPermissionsAndDetails? = null
                            var admin = false
                            for (identityAndPermissionsAndDetails in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                                if (ownedIdentity.equals(identityAndPermissionsAndDetails.identity)) {
                                    ownIdentityAndPermissions = identityAndPermissionsAndDetails
                                    // check if I am admin
                                    for (permissionString in identityAndPermissionsAndDetails.permissionStrings) {
                                        if (fromString(permissionString) == GroupV2.Permission.GROUP_ADMIN) {
                                            admin = true
                                            
                                        }
                                    }
                                    
                                }
                            }

                            if (ownIdentityAndPermissions == null) {
                                Logger.w("Downloaded a group blob for a group I am not part of")
                                throw DecodingException()
                            }

                            var groupAdminServerAuthenticationPrivateKey: ServerAuthenticationPrivateKey? =
                                null
                            // I am admin, check that I indeed have the groupAdminServerAuthenticationPrivateKey
                            if (admin) {
                                for (serverAuthenticationPrivateKey in startState.invitationCollectedData.groupAdminServerAuthenticationPrivateKeyCandidates) {
                                    if (KeyPair.areKeysMatching(
                                            receivedMessage.groupAdminPublicKey!!,
                                            serverAuthenticationPrivateKey
                                        )
                                    ) {
                                        groupAdminServerAuthenticationPrivateKey =
                                            serverAuthenticationPrivateKey
                                        
                                    }
                                }

                                if (groupAdminServerAuthenticationPrivateKey == null) {
                                    Logger.d("We were able to decrypt a blob, we are admin, but we do not yet have the groupAdminServerAuthenticationPrivateKey")
                                    throw DecryptionException()
                                }
                            }


                            /**//////////// */
                            // from here we have everything:
                            //  - the blob
                            //  - the inviter
                            //  - the keys
                            //  - the leaverIdentities
                            val blobKeys = BlobKeys(
                                inviterIdentityAndBlobMainSeedCandidate.value,
                                blobVersionSeed,
                                groupAdminServerAuthenticationPrivateKey
                            )

                            if (protocolManagerSession.identityDelegate.getGroupV2Version(
                                    protocolManagerSession.session,
                                    ownedIdentity,
                                    startState.groupIdentifier
                                ) != null
                            ) {
                                // update the group from what we downloaded, and retrieve the list of new members to "ping"
                                val newGroupMembers =
                                    protocolManagerSession.identityDelegate.updateGroupV2WithNewBlob(
                                        protocolManagerSession.session,
                                        ownedIdentity,
                                        startState.groupIdentifier,
                                        serverBlob,
                                        blobKeys,
                                        false,
                                        signerIdentity,
                                        leavers,
                                        receivedMessage.groupUpdateTimestamp
                                    )

                                if (newGroupMembers == null) {
                                    // We were not able to update the group, return null to retry...
                                    return null
                                }

                                // if the update was initiated by another of our own devices, auto-trust the details
                                if (signerIdentity == ownedIdentity) {
                                    protocolManagerSession.identityDelegate.trustGroupV2PublishedDetails(
                                        protocolManagerSession.session,
                                        ownedIdentity,
                                        startState.groupIdentifier
                                    )
                                }

                                protocolManagerSession.identityDelegate.unfreezeGroupV2(
                                    protocolManagerSession.session,
                                    ownedIdentity,
                                    startState.groupIdentifier
                                )

                                // check if a photo download is needed
                                if (serverBlob.serverPhotoInfo != null && protocolManagerSession.identityDelegate.getGroupV2PhotoUrl(
                                        protocolManagerSession.session,
                                        ownedIdentity,
                                        startState.groupIdentifier
                                    ) == null
                                ) {
                                    val coreProtocolMessage = CoreProtocolMessage(
                                        SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                                        ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
                                        UID(prng)
                                    )
                                    val messageToSend: ChannelMessageToSend? =
                                        DownloadGroupV2PhotoProtocol.InitialMessage(
                                            coreProtocolMessage,
                                            startState.groupIdentifier,
                                            serverBlob.serverPhotoInfo
                                        ).generateChannelProtocolMessageToSend()
                                    protocolManagerSession.channelDelegate!!.post(
                                        protocolManagerSession.session,
                                        messageToSend,
                                        prng
                                    )
                                }

                                if (!newGroupMembers.isEmpty()) {
                                    // send a ping to all new members to notify them you indeed joined the group
                                    for (groupMemberIdentity in newGroupMembers) {
                                        val pingSignature =
                                            protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                                protocolManagerSession.session,
                                                Constants.SignatureContext.GROUP_JOIN_NONCE,
                                                startState.groupIdentifier,
                                                ownIdentityAndPermissions.groupInvitationNonce,
                                                groupMemberIdentity,
                                                ownedIdentity,
                                                prng
                                            )

                                        val coreProtocolMessage = buildCoreProtocolMessage(
                                            createAsymmetricBroadcastChannelInfo(
                                                groupMemberIdentity,
                                                ownedIdentity
                                            )
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            GroupsV2Protocol.PingMessage(
                                                coreProtocolMessage,
                                                startState.groupIdentifier,
                                                ownIdentityAndPermissions.groupInvitationNonce,
                                                pingSignature!!,
                                                false
                                            ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }
                                }

                                return FinalState()
                            } else if (startState.invitationCollectedData.inviterIdentityAndBlobMainSeedCandidates.containsKey(
                                    ownedIdentity
                                )
                            ) {
                                // If owned identity is part of the inviterIdentityAndBlobMainSeedCandidates, this means the group was:
                                // - either created by me on another device
                                // - either created by someone else, but I joined it on another device
                                // In both case the group can be safely created and joined

                                // create the group in DB (we use the createJoinedGroupV2 method which is better suited here, even if another of my devices created the group)

                                val success =
                                    protocolManagerSession.identityDelegate.createJoinedGroupV2(
                                        protocolManagerSession.session,
                                        ownedIdentity,
                                        startState.groupIdentifier,
                                        blobKeys,
                                        serverBlob,
                                        true,
                                        null,
                                        receivedMessage.groupUpdateTimestamp
                                    )

                                // if success == false, this is not a retry-able failure, so we do nothing
                                if (success) {
                                    run {
                                        // remove the dialog if there is one
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


                                    // getGroupV2PhotoUrl will always return null here, but we check anyways
                                    if (serverBlob.serverPhotoInfo != null && protocolManagerSession.identityDelegate.getGroupV2PhotoUrl(
                                            protocolManagerSession.session,
                                            ownedIdentity,
                                            startState.groupIdentifier
                                        ) == null
                                    ) {
                                        val coreProtocolMessage = CoreProtocolMessage(
                                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                                            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
                                            UID(prng)
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            DownloadGroupV2PhotoProtocol.InitialMessage(
                                                coreProtocolMessage,
                                                startState.groupIdentifier,
                                                serverBlob.serverPhotoInfo
                                            ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }

                                    // send a ping to all members to notify them you indeed joined the group
                                    for (groupMember in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                                        if (groupMember.identity.equals(ownedIdentity)) {
                                            continue
                                        }

                                        val pingSignature =
                                            protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                                protocolManagerSession.session,
                                                Constants.SignatureContext.GROUP_JOIN_NONCE,
                                                startState.groupIdentifier,
                                                ownIdentityAndPermissions.groupInvitationNonce,
                                                groupMember.identity,
                                                ownedIdentity,
                                                prng
                                            )

                                        val coreProtocolMessage = buildCoreProtocolMessage(
                                            createAsymmetricBroadcastChannelInfo(
                                                groupMember.identity,
                                                ownedIdentity
                                            )
                                        )
                                        val messageToSend: ChannelMessageToSend? =
                                            GroupsV2Protocol.PingMessage(
                                                coreProtocolMessage,
                                                startState.groupIdentifier,
                                                ownIdentityAndPermissions.groupInvitationNonce,
                                                pingSignature!!,
                                                false
                                            ).generateChannelProtocolMessageToSend()
                                        protocolManagerSession.channelDelegate!!.post(
                                            protocolManagerSession.session,
                                            messageToSend,
                                            prng
                                        )
                                    }
                                }

                                return FinalState()
                            } else {
                                // check if we already received an "accept" from another owned device
                                var autoAccept = false
                                for (alreadyAcceptedNonce in startState.ownInvitationNoncesAcceptedOnOtherDevices) {
                                    if (alreadyAcceptedNonce.contentEquals(ownIdentityAndPermissions.groupInvitationNonce)) {
                                        autoAccept = true
                                        
                                    }
                                }

                                if (autoAccept) {
                                    // send an auto-accept message so the next protocol step is automatically executed --> no user dialog to show
                                    val coreProtocolMessage = buildCoreProtocolMessage(
                                        SendChannelInfo.createLocalChannelInfo(ownedIdentity)
                                    )
                                    val messageToSend: ChannelMessageToSend? =
                                        AutoAcceptInvitationMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                                    protocolManagerSession.channelDelegate!!.post(
                                        protocolManagerSession.session,
                                        messageToSend,
                                        prng
                                    )
                                } else {
                                    // create the accept invitation dialog (or unfreeze the previous invitation)
                                    val groupV2PendingMembers = HashSet<ObvGroupV2PendingMember>()
                                    for (identityAndPermissionsAndDetails in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                                        if (identityAndPermissionsAndDetails.identity.equals(
                                                ownedIdentity
                                            )
                                        ) {
                                            continue
                                        }
                                        groupV2PendingMembers.add(
                                            ObvGroupV2PendingMember(
                                                identityAndPermissionsAndDetails.identity.getBytes(),
                                                GroupV2.Permission.fromStrings(
                                                    @Suppress("UNCHECKED_CAST") (identityAndPermissionsAndDetails.permissionStrings as MutableCollection<String?>)
                                                ),
                                                identityAndPermissionsAndDetails.serializedIdentityDetails
                                            )
                                        )
                                    }


                                    val coreProtocolMessage = buildCoreProtocolMessage(
                                        createUserInterfaceChannelInfo(
                                            ownedIdentity, createGroupV2InvitationDialog(
                                                inviterIdentityAndBlobMainSeedCandidate.key,
                                                ObvGroupV2(
                                                    ownedIdentity.getBytes(),
                                                    startState.groupIdentifier,
                                                    GroupV2.Permission.fromStrings(
                                                        @Suppress("UNCHECKED_CAST") (ownIdentityAndPermissions.permissionStrings as MutableCollection<String?>)
                                                    ),
                                                    null,
                                                    groupV2PendingMembers,
                                                    serverBlob.serializedGroupDetails,
                                                    null, null, null, 0
                                                )
                                            ), startState.dialogUuid
                                        )
                                    )
                                    val messageToSend: ChannelMessageToSend? =
                                        DialogAcceptGroupInvitationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                                    protocolManagerSession.channelDelegate!!.post(
                                        protocolManagerSession.session,
                                        messageToSend,
                                        prng
                                    )
                                }


                                return GroupsV2Protocol.InvitationReceivedState(
                                    startState.groupIdentifier,
                                    startState.dialogUuid,
                                    inviterIdentityAndBlobMainSeedCandidate.key!!,
                                    serverBlob,
                                    blobKeys,
                                    receivedMessage.groupUpdateTimestamp
                                )
                            }
                        } catch (_: DecryptionException) {
                            // it is normal that some seed candidates are not able to decrypt
                            // can also happen if we have the right seeds but the groupAdminServerAuthenticationPrivateKey is missing
                        } catch (_: InvalidKeyException) {
                        } catch (_: DecodingException) {
                            // we have the right key, but are unable to decode the decrypted blob or the validation of the blob failed --> abort
                            protocolManagerSession.identityDelegate!!.deleteGroupV2(
                                protocolManagerSession.session,
                                ownedIdentity,
                                startState.groupIdentifier,
                                null
                            )
                            GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                                protocolManagerSession,
                                ownedIdentity,
                                startState.groupIdentifier
                            )

                            // remove the dialog if any
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

                            return FinalState()
                        }
                    }
                }
            }

            return INeedMoreSeedsState(
                startState.groupIdentifier,
                startState.dialogUuid,
                startState.invitationCollectedData,
                startState.ownInvitationNoncesAcceptedOnOtherDevices,
                startState.lastKnownOwnInvitationNonce,
                startState.lastKnownOtherGroupMemberIdentities
            )
        }
    }


    class DoNothingAfterServerQueryStep @Suppress("unused") constructor(
        startState: InitialProtocolState?,
        receivedMessage: DeleteGroupBlobFromServerMessage?,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            return FinalState()
        }
    }

    class ProcessPingStep : ProtocolStep {
        @Suppress("unused")
        internal val startState: InitialProtocolState?
        internal val receivedMessage: PingMessage
        internal val propagationNeeded: Boolean

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PingMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagationNeeded = true
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagatedPingMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagationNeeded = false
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check that the protocolInstanceUid matches the groupIdentifier
                if (!protocolInstanceUid!!.equals(receivedMessage.groupIdentifier.computeProtocolInstanceUid())) {
                    return FinalState()
                }
            }

            run {
                // check the message is not a replay
                if (GroupV2SignatureReceived.exists(
                        protocolManagerSession,
                        ownedIdentity,
                        receivedMessage.signature
                    )
                ) {
                    if (propagationNeeded) {
                        // do not log signature replays for propagated messages, they are normal
                        Logger.i("Received a group join ping with a known signature")
                    }
                    return FinalState()
                }
            }

            if (propagationNeeded) {
                // propagate the ping to other own devices, if any
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
                        val messageToSend: ChannelMessageToSend? = PropagatedPingMessage(
                            coreProtocolMessage,
                            receivedMessage.groupIdentifier,
                            receivedMessage.groupMemberInvitationNonce,
                            receivedMessage.signature,
                            receivedMessage.isResponse
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

            // check whether the group exists in db
            val ownGroupInvitationNonce =
                protocolManagerSession.identityDelegate!!.getGroupV2OwnGroupInvitationNonce(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupIdentifier
                )
            if (ownGroupInvitationNonce == null) {
                return FinalState()
            }

            var pingSenderIdentity: Identity? = null
            run {
                // find the member/pending members that sent the message
                val pingSenderCandidates: MutableList<Identity?>? =
                    protocolManagerSession.identityDelegate.getGroupV2MembersAndPendingMembersFromNonce(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupIdentifier,
                        receivedMessage.groupMemberInvitationNonce
                    )
                if (pingSenderCandidates != null) {
                    for (pingSenderCandidate in pingSenderCandidates) {
                        // check if the signature matches
                        if (Signature.verify(
                                Constants.SignatureContext.GROUP_JOIN_NONCE,
                                receivedMessage.groupIdentifier,
                                receivedMessage.groupMemberInvitationNonce,
                                ownedIdentity,
                                pingSenderCandidate!!,
                                receivedMessage.signature
                            )
                        ) {
                            pingSenderIdentity = pingSenderCandidate
                            
                        }
                    }
                }
            }

            if (pingSenderIdentity == null) {
                return FinalState()
            }

            run {
                // send a response if needed
                if (!receivedMessage.isResponse) {
                    val pingSignature =
                        protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                            protocolManagerSession.session,
                            Constants.SignatureContext.GROUP_JOIN_NONCE,
                            receivedMessage.groupIdentifier,
                            ownGroupInvitationNonce,
                            pingSenderIdentity,
                            ownedIdentity,
                            prng
                        )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(pingSenderIdentity, ownedIdentity)
                    )
                    val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                        coreProtocolMessage,
                        receivedMessage.groupIdentifier,
                        ownGroupInvitationNonce,
                        pingSignature!!,
                        true
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            run {
                // store the received signature
                GroupV2SignatureReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.signature
                )
            }

            protocolManagerSession.identityDelegate.moveGroupV2PendingMemberToMembers(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupIdentifier,
                pingSenderIdentity
            )

            return FinalState()
        }
    }

    class ProcessInvitationDialogResponseStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val startDialogUuid: UUID?
        internal val groupIdentifier: GroupV2.Identifier
        internal val propagated: Boolean
        internal val invitationAccepted: Boolean
        internal val receivedDialogUuid: UUID?
        internal val ownGroupInvitationNonce: ByteArray?
        internal val propagatedOwnGroupInvitationNonce: ByteArray?
        internal val groupMembersToNotify: MutableList<Identity?>?
        internal val autoAccept: Boolean

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: DialogAcceptGroupInvitationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = false
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = receivedMessage.dialogUuid
            this.propagatedOwnGroupInvitationNonce = null
            this.groupMembersToNotify = ArrayList<Identity?>()
            var ownGroupInvitationNonce: ByteArray? = null
            for (groupMember in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (groupMember.identity.equals(ownedIdentity)) {
                    ownGroupInvitationNonce = groupMember.groupInvitationNonce
                    continue
                }
                groupMembersToNotify.add(groupMember.identity)
            }
            this.ownGroupInvitationNonce = ownGroupInvitationNonce
            this.autoAccept = false
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: PropagateInvitationDialogResponseMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = true
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = null
            this.propagatedOwnGroupInvitationNonce = receivedMessage.ownGroupInvitationNonce
            this.groupMembersToNotify = ArrayList<Identity?>()
            var ownGroupInvitationNonce: ByteArray? = null
            for (groupMember in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (groupMember.identity.equals(ownedIdentity)) {
                    ownGroupInvitationNonce = groupMember.groupInvitationNonce
                    continue
                }
                groupMembersToNotify.add(groupMember.identity)
            }
            this.ownGroupInvitationNonce = ownGroupInvitationNonce
            this.autoAccept = false
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: AutoAcceptInvitationMessage?,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage!!, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = false
            this.invitationAccepted = true
            this.receivedDialogUuid = null
            this.propagatedOwnGroupInvitationNonce = null
            this.groupMembersToNotify = ArrayList<Identity?>()
            var ownGroupInvitationNonce: ByteArray? = null
            for (groupMember in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                if (groupMember.identity.equals(ownedIdentity)) {
                    ownGroupInvitationNonce = groupMember.groupInvitationNonce
                    continue
                }
                groupMembersToNotify.add(groupMember.identity)
            }
            this.ownGroupInvitationNonce = ownGroupInvitationNonce
            this.autoAccept = true
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState,
            receivedMessage: DialogAcceptGroupInvitationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = false
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = receivedMessage.dialogUuid
            this.propagatedOwnGroupInvitationNonce = null
            this.ownGroupInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.groupMembersToNotify =
                if (startState.lastKnownOtherGroupMemberIdentities == null) null else Arrays.asList<Identity?>(
                    *startState.lastKnownOtherGroupMemberIdentities
                )
            this.autoAccept = false
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState,
            receivedMessage: PropagateInvitationDialogResponseMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = true
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = null
            this.propagatedOwnGroupInvitationNonce = receivedMessage.ownGroupInvitationNonce
            this.ownGroupInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.groupMembersToNotify =
                if (startState.lastKnownOtherGroupMemberIdentities == null) null else Arrays.asList<Identity?>(
                    *startState.lastKnownOtherGroupMemberIdentities
                )
            this.autoAccept = false
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: DialogAcceptGroupInvitationMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = false
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = receivedMessage.dialogUuid
            this.propagatedOwnGroupInvitationNonce = null
            this.ownGroupInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.groupMembersToNotify =
                if (startState.lastKnownOtherGroupMemberIdentities == null) null else Arrays.asList<Identity?>(
                    *startState.lastKnownOtherGroupMemberIdentities
                )
            this.autoAccept = false
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: PropagateInvitationDialogResponseMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.startDialogUuid = startState.dialogUuid
            this.groupIdentifier = startState.groupIdentifier
            this.propagated = true
            this.invitationAccepted = receivedMessage.invitationAccepted
            this.receivedDialogUuid = null
            this.propagatedOwnGroupInvitationNonce = receivedMessage.ownGroupInvitationNonce
            this.ownGroupInvitationNonce = startState.lastKnownOwnInvitationNonce
            this.groupMembersToNotify =
                if (startState.lastKnownOtherGroupMemberIdentities == null) null else Arrays.asList<Identity?>(
                    *startState.lastKnownOtherGroupMemberIdentities
                )
            this.autoAccept = false
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            if (!propagated && (this.startDialogUuid != this.receivedDialogUuid) && !autoAccept) {
                // bad dialogUuid, and not an autoAccept, ignore the message
                return startState
            }


            // if we are still downloading/waiting for seeds, keep all accepted responses on the side to process once we have the blob
            if (startState is DownloadingGroupBlobState) {
                if (invitationAccepted) {
                    if (propagatedOwnGroupInvitationNonce == null) {
                        return startState
                    }

                    val nonces =
                        arrayOfNulls<ByteArray>(startState.ownInvitationNoncesAcceptedOnOtherDevices.size + 1)
                    System.arraycopy(
                        startState.ownInvitationNoncesAcceptedOnOtherDevices,
                        0,
                        nonces,
                        0,
                        nonces.size - 1
                    )
                    nonces[nonces.size - 1] = propagatedOwnGroupInvitationNonce

                    return DownloadingGroupBlobState(
                        startState.groupIdentifier,
                        startState.dialogUuid,
                        startState.invitationCollectedData,
                        nonces,
                        startState.lastKnownOwnInvitationNonce,
                        startState.lastKnownOtherGroupMemberIdentities,
                        startState.serverQueryNonce
                    )
                }
            } else if (startState is INeedMoreSeedsState) {
                if (invitationAccepted) {
                    if (propagatedOwnGroupInvitationNonce == null) {
                        return startState
                    }

                    val nonces =
                        arrayOfNulls<ByteArray>(startState.ownInvitationNoncesAcceptedOnOtherDevices.size + 1)
                    System.arraycopy(
                        startState.ownInvitationNoncesAcceptedOnOtherDevices,
                        0,
                        nonces,
                        0,
                        nonces.size - 1
                    )
                    nonces[nonces.size - 1] = propagatedOwnGroupInvitationNonce

                    return INeedMoreSeedsState(
                        startState.groupIdentifier,
                        startState.dialogUuid,
                        startState.invitationCollectedData,
                        nonces,
                        startState.lastKnownOwnInvitationNonce,
                        startState.lastKnownOtherGroupMemberIdentities
                    )
                }
            }


            // if we are not part of the group, abort !
            if (this.ownGroupInvitationNonce == null) {
                // remove the dialog
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createUserInterfaceChannelInfo(
                        ownedIdentity,
                        createDeleteDialog(),
                        startDialogUuid
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                return FinalState()
            }

            if (propagated && !this.propagatedOwnGroupInvitationNonce.contentEquals(
                    ownGroupInvitationNonce
                )
            ) {
                // propagated response for bad invitation nonce --> ignore the message
                return startState
            }


            if (!propagated && !autoAccept) {
                // propagate the dialog response to other devices
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
                            PropagateInvitationDialogResponseMessage(
                                coreProtocolMessage,
                                this.invitationAccepted,
                                ownGroupInvitationNonce
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

            if ((startState is InvitationReceivedState) && invitationAccepted) {
                // force the integrityWasChecked to true
                startState.serverBlob.administratorsChain.integrityWasChecked = true

                // create the group in db
                val success = protocolManagerSession.identityDelegate!!.createJoinedGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier,
                    startState.blobKeys,
                    startState.serverBlob,
                    false,
                    startState.inviterIdentity,
                    startState.groupUpdateTimestamp
                )

                // if success == false, this is not a retry-able failure, so we do nothing
                if (success) {
                    if (startState.serverBlob.serverPhotoInfo != null && protocolManagerSession.identityDelegate.getGroupV2PhotoUrl(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupIdentifier
                        ) == null
                    ) {
                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
                            UID(prng)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            DownloadGroupV2PhotoProtocol.InitialMessage(
                                coreProtocolMessage,
                                groupIdentifier,
                                startState.serverBlob.serverPhotoInfo
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }

                    // send a ping to all members to notify them you indeed joined the group
                    // NOTE: we send the ping even for propagated accepts as we might have missed the ping response to the main device ping
                    for (groupMember in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                        if (groupMember.identity.equals(ownedIdentity)) {
                            continue
                        }

                        val pingSignature =
                            protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                protocolManagerSession.session,
                                Constants.SignatureContext.GROUP_JOIN_NONCE,
                                groupIdentifier,
                                ownGroupInvitationNonce,
                                groupMember.identity,
                                ownedIdentity,
                                prng
                            )

                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAsymmetricBroadcastChannelInfo(
                                groupMember.identity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                            coreProtocolMessage,
                            groupIdentifier,
                            ownGroupInvitationNonce,
                            pingSignature!!,
                            false
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }

                run {
                    // remove the dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createDeleteDialog(),
                            startDialogUuid
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

                return FinalState()
            } else {
                run {
                    // remove the dialog
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity,
                            createDeleteDialog(),
                            startDialogUuid
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

                if (propagated) {
                    return FinalState()
                } else if (groupMembersToNotify != null) {
                    // only put a server log and notify others for the non-propagated response
                    val leaveSignature =
                        protocolManagerSession.identityDelegate!!.signGroupInvitationNonce(
                            protocolManagerSession.session,
                            Constants.SignatureContext.GROUP_LEAVE_NONCE,
                            groupIdentifier,
                            ownGroupInvitationNonce,
                            null,
                            ownedIdentity,
                            prng
                        )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            PutGroupLogQuery(groupIdentifier, leaveSignature!!)
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        PutGroupLogOnServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )

                    return RejectingInvitationOrLeavingGroupState(
                        groupIdentifier,
                        @Suppress("UNCHECKED_CAST") (groupMembersToNotify as MutableList<Identity>)
                    )
                } else {
                    // this should normally never happen
                    return startState
                }
            }
        }
    }


    class NotifyMembersOfRejectionOrGroupLeftStep @Suppress("unused") constructor(
        internal val startState: RejectingInvitationOrLeavingGroupState, @field:Suppress(
            "unused"
        ) internal val receivedMessage: PutGroupLogOnServerMessage?, protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            for (groupMember in startState.groupMembersToNotify) {
                // send rejection/left group update message
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createAsymmetricBroadcastChannelInfo(groupMember, ownedIdentity)
                )
                val messageToSend: ChannelMessageToSend? = InvitationRejectedBroadcastMessage(
                    coreProtocolMessage,
                    startState.groupIdentifier
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }


    class InitiateBlobReDownloadStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val groupIdentifier: GroupV2.Identifier
        internal val dialogUuid: UUID?
        internal val invitationCollectedData: InvitationCollectedData?
        internal val propagationNeeded: Boolean
        internal val rePingAllGroupMembers: Boolean
        internal val receivedPreShotVersionSeed: Seed?


        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: GroupReDownloadInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = UUID.randomUUID()
            this.invitationCollectedData = null
            this.propagationNeeded = true
            this.rePingAllGroupMembers = true
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: InvitationRejectedBroadcastMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = UUID.randomUUID()
            this.invitationCollectedData = null
            this.propagationNeeded = true
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagateInvitationRejectedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = null
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = UUID.randomUUID()
            this.invitationCollectedData = null
            this.propagationNeeded = false
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: InvitationRejectedBroadcastMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = startState.dialogUuid
            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )
            this.propagationNeeded = true
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: PropagateInvitationRejectedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = startState.dialogUuid
            this.invitationCollectedData = InvitationCollectedData()
            this.invitationCollectedData.addBlobKeysCandidates(
                startState.inviterIdentity,
                startState.blobKeys
            )
            this.propagationNeeded = false
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: GroupReDownloadInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = startState.dialogUuid
            this.invitationCollectedData = startState.invitationCollectedData
            this.propagationNeeded = true
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = null
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState,
            receivedMessage: PreShotVersionSeedMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.dialogUuid = startState.dialogUuid
            this.invitationCollectedData = startState.invitationCollectedData
            this.propagationNeeded = false
            this.rePingAllGroupMembers = false
            this.receivedPreShotVersionSeed = receivedMessage.versionSeed
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // check that the protocolInstanceUid matches the groupIdentifier
                if (!protocolInstanceUid!!.equals(groupIdentifier.computeProtocolInstanceUid())) {
                    if (startState != null) {
                        return startState
                    } else {
                        return FinalState()
                    }
                }
            }

            // propagate the message if needed
            if (propagationNeeded) {
                val numberOfOtherDevices =
                    protocolManagerSession.identityDelegate!!.getOtherDeviceUidsOfOwnedIdentity(
                        protocolManagerSession.session,
                        ownedIdentity
                    )!!.size
                if (numberOfOtherDevices > 0) {
                    try {
                        // the PropagateInvitationRejectedMessage simply triggers a blob redownload so that we get an up-to-date log of members who left the group
                        // we also send this message for user initiated reloads with GroupReDownloadInitialMessage
                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            PropagateInvitationRejectedMessage(
                                coreProtocolMessage,
                                groupIdentifier
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

            // save the preShotVersionSeed if we received one
            if (receivedPreShotVersionSeed != null) {
                GroupV2PreShotVersionSeedReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    receivedPreShotVersionSeed
                )
            }


            if (invitationCollectedData == null) {
                // fetch the blobKeys from DB
                val blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )
                if (blobKeys == null) {
                    if (startState != null) {
                        return startState
                    } else {
                        return FinalState()
                    }
                }

                if (rePingAllGroupMembers) {
                    try {
                        // do not fail the step if sending the pings fails
                        val ownGroupInvitationNonce =
                            protocolManagerSession.identityDelegate.getGroupV2OwnGroupInvitationNonce(
                                protocolManagerSession.session,
                                ownedIdentity,
                                groupIdentifier
                            )
                        if (ownGroupInvitationNonce != null) {
                            for (groupMember in protocolManagerSession.identityDelegate.getGroupV2OtherMembersAndPermissions(
                                protocolManagerSession.session,
                                ownedIdentity,
                                groupIdentifier
                            )!!) {
                                val pingSignature =
                                    protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                                        protocolManagerSession.session,
                                        Constants.SignatureContext.GROUP_JOIN_NONCE,
                                        groupIdentifier,
                                        ownGroupInvitationNonce,
                                        groupMember!!.identity,
                                        ownedIdentity,
                                        prng
                                    )

                                val coreProtocolMessage = buildCoreProtocolMessage(
                                    createAsymmetricBroadcastChannelInfo(
                                        groupMember.identity,
                                        ownedIdentity
                                    )
                                )
                                val messageToSend: ChannelMessageToSend? =
                                    GroupsV2Protocol.PingMessage(
                                        coreProtocolMessage,
                                        groupIdentifier,
                                        ownGroupInvitationNonce,
                                        pingSignature!!,
                                        false
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

                protocolManagerSession.identityDelegate.freezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    groupIdentifier
                )

                val serverQueryNonce = prng.bytes(16)
                run {
                    // run the server query to download the server blob
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            GetGroupBlobQuery(groupIdentifier, serverQueryNonce)
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DownloadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                val invitationCollectedData = InvitationCollectedData()
                invitationCollectedData.addBlobKeysCandidates(ownedIdentity, blobKeys)

                return DownloadingGroupBlobState(
                    groupIdentifier,
                    dialogUuid,
                    invitationCollectedData,
                    arrayOfNulls<ByteArray>(0),
                    null,
                    null,
                    serverQueryNonce
                )
            } else if (startState is InvitationReceivedState) {
                var ownInvitationNonce: ByteArray? = null
                val otherGroupMemberIdentities: MutableList<Identity?> = ArrayList<Identity?>()
                // We were in InvitationReceivedState, freeze the invitation dialog
                run {
                    val groupV2PendingMembers = HashSet<ObvGroupV2PendingMember>()
                    var ownPermissions = HashSet<GroupV2.Permission>()
                    for (identityAndPermissionsAndDetails in (startState as InvitationReceivedState).serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                        if (identityAndPermissionsAndDetails.identity == ownedIdentity) {
                            ownPermissions =
                                GroupV2.Permission.fromStrings(@Suppress("UNCHECKED_CAST") (identityAndPermissionsAndDetails.permissionStrings as MutableCollection<String?>))
                            ownInvitationNonce =
                                identityAndPermissionsAndDetails.groupInvitationNonce
                            continue
                        }
                        otherGroupMemberIdentities.add(identityAndPermissionsAndDetails.identity)
                        groupV2PendingMembers.add(
                            ObvGroupV2PendingMember(
                                identityAndPermissionsAndDetails.identity.getBytes(),
                                GroupV2.Permission.fromStrings(@Suppress("UNCHECKED_CAST") (identityAndPermissionsAndDetails.permissionStrings as MutableCollection<String?>)),
                                identityAndPermissionsAndDetails.serializedIdentityDetails
                            )
                        )
                    }

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createUserInterfaceChannelInfo(
                            ownedIdentity, createGroupV2FrozenInvitationDialog(
                                startState.inviterIdentity, ObvGroupV2(
                                    ownedIdentity.getBytes(),
                                    startState.groupIdentifier,
                                    ownPermissions,
                                    null,
                                    groupV2PendingMembers,
                                    startState.serverBlob.serializedGroupDetails,
                                    null, null, null, 0
                                )
                            ), startState.dialogUuid
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DialogAcceptGroupInvitationMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                val serverQueryNonce = prng.bytes(16)
                run {
                    // run the server query to re-download the server blob
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            GetGroupBlobQuery(groupIdentifier, serverQueryNonce)
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DownloadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                return DownloadingGroupBlobState(
                    groupIdentifier,
                    dialogUuid,
                    invitationCollectedData,
                    arrayOfNulls<ByteArray>(0),
                    ownInvitationNonce,
                    @Suppress("UNCHECKED_CAST") (otherGroupMemberIdentities.toTypedArray<Identity?>() as Array<Identity>),
                    serverQueryNonce
                )
            } else if (startState is INeedMoreSeedsState) {
                val serverQueryNonce = prng.bytes(16)
                run {
                    // run the server query to re-download the server blob
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            GetGroupBlobQuery(groupIdentifier, serverQueryNonce)
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        DownloadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }

                return DownloadingGroupBlobState(
                    groupIdentifier,
                    dialogUuid,
                    invitationCollectedData,
                    startState.ownInvitationNoncesAcceptedOnOtherDevices,
                    startState.lastKnownOwnInvitationNonce,
                    startState.lastKnownOtherGroupMemberIdentities,
                    serverQueryNonce
                )
            } else {
                return FinalState()
            }
        }
    }

    class InitiateGroupUpdateStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: GroupUpdateInitialMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // check that we indeed know the group and have the admin private key for group updates
            val blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupIdentifier
            )
            val adminKeyIsMissing =
                blobKeys == null || blobKeys.groupAdminServerAuthenticationPrivateKey == null

            // check that we did not remove ourself, or our GROUP_ADMIN permission in the changeSet
            val removedOurself =
                receivedMessage.changeSet.removedMembers.contains(ownedIdentity.getBytes())
            val ownPermissions =
                receivedMessage.changeSet.permissionChanges.get(ObvBytesKey(ownedIdentity.getBytes()))
            val removedOurAdminPermission =
                ownPermissions != null && !ownPermissions.contains(GroupV2.Permission.GROUP_ADMIN)

            if (adminKeyIsMissing || removedOurself || removedOurAdminPermission) {
                // invalid update, discard the changeSet and notify (for app)
                val userInfo = HashMap<String, Any>()
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY,
                    ownedIdentity
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY,
                    receivedMessage.groupIdentifier
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY,
                    true
                )
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
                    userInfo
                )

                return FinalState()
            } else if (receivedMessage.changeSet.isEmpty()) {
                // empty changeset, still notify, but without error
                val userInfo = HashMap<String, Any>()
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY,
                    ownedIdentity
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY,
                    receivedMessage.groupIdentifier
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY,
                    false
                )
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
                    userInfo
                )

                return FinalState()
            }

            protocolManagerSession.identityDelegate.freezeGroupV2(
                protocolManagerSession.session,
                ownedIdentity,
                receivedMessage.groupIdentifier
            )


            // check whether we are removing members from the group:
            // - if this is not the case, we do not change the seed
            // - if this is the case, we need to rotate the group encryption seed
            //   --> we pre-shoot it to all remaining members in case the blob is uploaded, but we fail to send the key update messages at the end.

            val preShotVersionSeed: Seed?
            if (receivedMessage.changeSet.removedMembers.isEmpty()) {
                preShotVersionSeed = null
            } else {
                preShotVersionSeed = Seed(prng)

                // compute an efficiently searchable set of removed members
                val removedIdentities = HashSet<ObvBytesKey>()
                for (identityBytes in receivedMessage.changeSet.removedMembers) {
                    removedIdentities.add(ObvBytesKey(identityBytes))
                }

                // pre-shoot the new random version seed to all current group members (minus those removed). New members will get invited later, once the blob is uploaded.
                val otherMembers =
                    protocolManagerSession.identityDelegate.getGroupV2OtherMembersAndPermissions(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupIdentifier
                    )

                // built the list of all identities to notify
                val toIdentities: MutableList<Identity> = ArrayList()
                toIdentities.add(ownedIdentity)
                if (otherMembers != null) {
                    for (otherMember in otherMembers) {
                        if (otherMember == null) continue
                        // do not include removed members
                        if (!removedIdentities.contains(ObvBytesKey(otherMember.identity.getBytes()))) {
                            toIdentities.add(otherMember.identity)
                        }
                    }
                }


                val sendChannelInfos =
                    createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                        toIdentities.toTypedArray(),
                        ownedIdentity
                    )!!
                for (sendChannelInfo in sendChannelInfos) {
                    try {
                        val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                        val messageToSend: ChannelMessageToSend? = PreShotVersionSeedMessage(
                            coreProtocolMessage,
                            receivedMessage.groupIdentifier,
                            preShotVersionSeed
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: Exception) {
                        Logger.d("One server with no channel during GroupsV2Protocol.InitiateGroupUpdateStep")
                    }
                }
            }


            // request group lock on server
            val localPrng4473 = prng
            val lockNonce = localPrng4473.bytes(Constants.GROUP_V2_LOCK_NONCE_LENGTH)
            run {
                val signature = Signature.sign(
                    Constants.SignatureContext.GROUP_LOCK_ON_SERVER,
                    lockNonce,
                    blobKeys.groupAdminServerAuthenticationPrivateKey.signaturePrivateKey,
                    localPrng4473
                )
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        LockGroupBlobQuery(receivedMessage.groupIdentifier, lockNonce, signature!!)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    RequestLockMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    localPrng4473
                )
            }

            // wait for the lock
            return WaitingForLockState(
                receivedMessage.groupIdentifier,
                receivedMessage.changeSet,
                lockNonce,
                0,
                preShotVersionSeed
            )
        }
    }


    class PrepareBlobForGroupUpdateStep(
        @field:Suppress("unused") internal val startState: WaitingForLockState,
        internal val receivedMessage: RequestLockMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(SQLException::class)
        private fun unfreezeAndNotifyUpdateFailed(
            protocolManagerSession: ProtocolManagerSession,
            error: Boolean
        ) {
            protocolManagerSession.identityDelegate!!.unfreezeGroupV2(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupIdentifier
            )

            val userInfo = HashMap<String, Any>()
            userInfo.put(
                ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY,
                startState.groupIdentifier
            )
            userInfo.put(ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY, error)
            protocolManagerSession.notificationPostingDelegate?.postNotification(
                ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
                userInfo
            )
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            run {
                if (receivedMessage.serverQueryNonce != null && !receivedMessage.serverQueryNonce.contentEquals(
                        startState.lockNonce
                    )
                ) {
                    // this serverQuery response was for another request, ignore it!
                    return startState
                }
            }

            if (receivedMessage.encryptedServerBlob == null || receivedMessage.logEntries == null || receivedMessage.groupAdminPublicKey == null) {
                unfreezeAndNotifyUpdateFailed(protocolManagerSession, true)
                return FinalState()
            }

            val blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupIdentifier
            )
            if (blobKeys == null) {
                unfreezeAndNotifyUpdateFailed(protocolManagerSession, true)
                return FinalState()
            }
            val versionSeedCandidates: MutableList<Seed> = ArrayList()
            blobKeys.blobVersionSeed?.let { versionSeedCandidates.add(it) }

            for (preShotVersionSeedReceived in GroupV2PreShotVersionSeedReceived.getAllForGroupIdentifier(
                    protocolManagerSession,
                    ownedIdentity,
                    startState.groupIdentifier
                )) {
                versionSeedCandidates.add(preShotVersionSeedReceived.versionSeed)
            }


            var initialServerBlob: ServerBlob? = null
            var initialBlobVersionSeed: Seed? = null
            for (versionSeed in versionSeedCandidates) {
                try {
                    val authEncKey = GroupV2.getSharedBlobSecretKey(
                        blobKeys.blobMainSeed!!,
                        versionSeed
                    )
                    val paddedBlobPlaintext = Suite.getAuthEnc(authEncKey)!!
                        .decrypt(authEncKey, receivedMessage.encryptedServerBlob)!!
                    val encodeds: Array<Encoded> = Encoded(paddedBlobPlaintext).decodeListWithPadding()

                    val uncheckedServerBlob = ServerBlob.of(encodeds[0])
                    val signerIdentity = encodeds[1].decodeIdentity()
                    val signature = encodeds[2].decodeBytes()

                    // check the administrators chain
                    try {
                        uncheckedServerBlob.administratorsChain.withCheckedIntegrity(
                            uncheckedServerBlob.administratorsChain.groupUid,
                            signerIdentity,
                            protocolManagerSession.identityDelegate.getGroupV2AdministratorsChain(
                                protocolManagerSession.session,
                                ownedIdentity,
                                startState.groupIdentifier
                            )
                        )
                    } catch (_: Exception) {
                        Logger.w("Downloaded a group blob with invalid administratorsChain")
                        throw DecodingException()
                    }


                    // check the signature
                    if (!Signature.verify(
                            Constants.SignatureContext.GROUP_BLOB,
                            encodeds[0].bytes,
                            signerIdentity,
                            signature
                        )
                    ) {
                        Logger.w("Downloaded a group blob with invalid signature")
                        throw DecodingException()
                    }

                    // check that admins match the administratorsChain
                    run {
                        val blobAdmins = HashSet<Identity?>()
                        for (member in uncheckedServerBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                            if (member.permissionStrings.contains(GroupV2.Permission.GROUP_ADMIN.string)) {
                                blobAdmins.add(member.identity)
                            }
                        }
                        val chainAdmins = uncheckedServerBlob.administratorsChain.adminIdentities
                        if (blobAdmins != chainAdmins) {
                            Logger.w("Downloaded a group blob with non-matching admins in AdministratorsChain")
                            throw DecodingException()
                        }

                        // also check we are still administrator of the group
                        if (!blobAdmins.contains(ownedIdentity)) {
                            Logger.w("We are no longer admin of a group we wanted to update --> aborting")
                            throw DecodingException()
                        }
                    }

                    // if no exception occurred, all checks passed, we have the right version seed
                    initialServerBlob = uncheckedServerBlob
                    initialBlobVersionSeed = versionSeed
                    break
                } catch (_: Exception) {
                    // exceptions are normal
                }
            }

            if (initialServerBlob == null) {
                Logger.w("Failed to decrypt/verify server blob during update")
                unfreezeAndNotifyUpdateFailed(protocolManagerSession, true)
                return FinalState()
            }

            // consolidate the blob with the received log entries
            initialServerBlob.consolidateWithLogEntries(
                startState.groupIdentifier,
                receivedMessage.logEntries
            )


            // check if there is anything to change in the blob, based on the received changeSet
            var changed = false

            val members =
                HashSet<IdentityAndPermissionsAndDetails>(initialServerBlob.groupMemberIdentityAndPermissionsAndDetailsList)
            val membersToInvite = HashSet<Identity?>()
            val membersToKick = HashMap<Identity?, ByteArray?>()
            run {
                // removed members
                if (!startState.changeSet.removedMembers.isEmpty()) {
                    val removedMembersSet = HashSet<Identity?>()
                    for (bytesIdentity in startState.changeSet.removedMembers) {
                        try {
                            removedMembersSet.add(Identity.of(bytesIdentity))
                        } catch (_: DecodingException) {
                        }
                    }

                    val toRemove: MutableList<IdentityAndPermissionsAndDetails> =
                        ArrayList<IdentityAndPermissionsAndDetails>()
                    for (member in members) {
                        if (removedMembersSet.contains(member.identity)) {
                            toRemove.add(member)
                        }
                    }

                    for (member in toRemove) {
                        changed = true
                        members.remove(member)
                        membersToKick.put(member.identity, member.groupInvitationNonce)
                    }
                }


                // permission changes
                if (!startState.changeSet.permissionChanges.isEmpty()) {
                    for (member in members) {
                        try {
                            val newPermissions =
                                startState.changeSet.permissionChanges.get(ObvBytesKey(member.identity.getBytes())) ?: continue
                            val initialPermissions = HashSet<GroupV2.Permission>()
                            for (permissionString in member.permissionStrings) {
                                val permission = fromString(permissionString)
                                if (permission != null) {
                                    initialPermissions.add(permission)
                                }
                            }
                            if (newPermissions == initialPermissions) {
                                continue
                            }

                            changed = true
                            member.permissionStrings.clear()
                            for (permission in newPermissions) {
                                member.permissionStrings.add(permission.string)
                            }
                        } catch (_: Exception) {
                        }
                    }
                }

                // use this opportunity to update any group member serialized details
                val updatedMembers = HashSet<IdentityAndPermissionsAndDetails?>()
                for (member in members) {
                    val serializedDetails: String?
                    if (member.identity == ownedIdentity) {
                        serializedDetails =
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfOwnedIdentity(
                                protocolManagerSession.session,
                                ownedIdentity
                            )
                    } else {
                        serializedDetails =
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                member.identity
                            )
                    }
                    if (serializedDetails != null && member.serializedIdentityDetails != serializedDetails) {
                        val updatedMember = IdentityAndPermissionsAndDetails(
                            member.identity,
                            member.permissionStrings,
                            serializedDetails,
                            member.groupInvitationNonce
                        )
                        updatedMembers.add(updatedMember)
                    }
                }
                for (updatedMember in updatedMembers) {
                    // we do not mark any change --> only update the server blob if there is a "real" change
                    members.remove(updatedMember) // remove the old element
                    members.add(updatedMember!!) // insert the updated one
                }


                // added members
                for (entry in startState.changeSet.addedMembersWithPermissions.entries) {
                    try {
                        val memberIdentity = Identity.of(entry.key!!.getBytes())
                        val permissionStrings: MutableList<String> = ArrayList()
                        for (permission in entry.value!!) {
                            permissionStrings.add(permission.string)
                        }
                        val serializedContactDetails =
                            protocolManagerSession.identityDelegate.getSerializedPublishedDetailsOfContactIdentity(
                                protocolManagerSession.session,
                                ownedIdentity,
                                memberIdentity
                            )
                        if (serializedContactDetails == null) {
                            continue
                        }

                        val newMember = IdentityAndPermissionsAndDetails(
                            memberIdentity,
                            permissionStrings,
                            serializedContactDetails,
                            prng.bytes(Constants.GROUP_V2_INVITATION_NONCE_LENGTH)
                        )
                        if (members.contains(newMember)) {
                            continue
                        }

                        changed = true
                        members.add(newMember)
                        membersToInvite.add(memberIdentity)
                    } catch (_: Exception) {
                    }
                }

                // group details
                if (startState.changeSet.updatedSerializedGroupDetails != null && startState.changeSet.updatedSerializedGroupDetails != initialServerBlob.serializedGroupDetails) {
                    changed = true
                }

                // group type
                if (startState.changeSet.updatedJsonGroupType != null && startState.changeSet.updatedJsonGroupType != initialServerBlob.serializedGroupType) {
                    changed = true
                }
                // group photoUrl
                val updatedPhotoUrl4799 = startState.changeSet.updatedPhotoUrl
                if (updatedPhotoUrl4799 != null && (initialServerBlob.serverPhotoInfo != null || !updatedPhotoUrl4799.isEmpty())) {
                    changed = true
                }
            }

            if (!changed) {
                // nothing changed --> nothing to upload, discard the changeSet and notify (for app)
                Logger.d("Nothing change in group")
                unfreezeAndNotifyUpdateFailed(protocolManagerSession, false)
                return FinalState()
            }

            // check that we indeed have an oblivious channel with all membersToInvite
            for (identity in membersToInvite) {
                if (protocolManagerSession.channelDelegate!!.getConfirmedObliviousChannelOrPreKeyDeviceUids(
                        protocolManagerSession.session,
                        ownedIdentity,
                        identity
                    ).size == 0
                ) {
                    // a new member does not have a channel --> discard the changeSet and notify (for app)
                    unfreezeAndNotifyUpdateFailed(protocolManagerSession, true)
                    return FinalState()
                }
            }


            /**///////////////////// */
            // if we reach this point, there are some changes to publish on the server


            // create the new ServerBlob
            val updatedServerBlob: ServerBlob?
            var absolutePhotoUrlToUpload: String? = null
            var adminKeyChangeRequired = false
            run {
                val updatedAdministratorsChain: AdministratorsChain?
                run {
                    val blobAdmins = HashSet<Identity?>()
                    for (member in members) {
                        if (member.permissionStrings.contains(GroupV2.Permission.GROUP_ADMIN.string)) {
                            blobAdmins.add(member.identity)
                        }
                    }
                    val chainAdmins = initialServerBlob.administratorsChain.adminIdentities
                    if (blobAdmins == chainAdmins) {
                        updatedAdministratorsChain = initialServerBlob.administratorsChain
                    } else {
                        // the admins have changed --> we need to add a block to the chain
                        if (!blobAdmins.containsAll(chainAdmins)) {
                            // some admins were removed --> key change required
                            adminKeyChangeRequired = true
                        }

                        blobAdmins.remove(ownedIdentity)
                        updatedAdministratorsChain =
                            initialServerBlob.administratorsChain.buildNewChainByAppendingABlock(
                                protocolManagerSession.session,
                                protocolManagerSession.identityDelegate,
                                ownedIdentity,
                                blobAdmins.toTypedArray<Identity?>(),
                                prng
                            )
                    }
                }

                val updatedSerializedGroupDetails: String?
                if (startState.changeSet.updatedSerializedGroupDetails != null) {
                    updatedSerializedGroupDetails =
                        startState.changeSet.updatedSerializedGroupDetails
                } else {
                    updatedSerializedGroupDetails = initialServerBlob.serializedGroupDetails
                }

                val updatedJsonGroupType: String?
                if (startState.changeSet.updatedJsonGroupType != null) {
                    updatedJsonGroupType = startState.changeSet.updatedJsonGroupType
                } else {
                    updatedJsonGroupType = initialServerBlob.serializedGroupType
                }

                val updatedServerPhotoInfo: ServerPhotoInfo?
                val updatedPhotoUrl4882 = startState.changeSet.updatedPhotoUrl
                if (updatedPhotoUrl4882 != null && updatedPhotoUrl4882.isEmpty()) {
                    // photo was removed
                    updatedServerPhotoInfo = null
                } else if (updatedPhotoUrl4882 != null) {
                    // new photo url
                    absolutePhotoUrlToUpload = updatedPhotoUrl4882
                    updatedServerPhotoInfo = ServerPhotoInfo(
                        ownedIdentity,
                        UID(prng),
                        Suite.getDefaultAuthEnc(0).generateKey(prng)!!
                    )
                } else if (initialServerBlob.serverPhotoInfo == null) {
                    // no update and there was no photo
                    updatedServerPhotoInfo = null
                } else if (initialServerBlob.serverPhotoInfo.serverPhotoIdentity == ownedIdentity) {
                    // there was a photo and we were the owner --> no need to touch it
                    updatedServerPhotoInfo = initialServerBlob.serverPhotoInfo
                } else {
                    // there was a photo, from some other administrator, check we have the photo at hand
                    absolutePhotoUrlToUpload =
                        protocolManagerSession.identityDelegate.getGroupV2PhotoUrl(
                            protocolManagerSession.session,
                            ownedIdentity,
                            startState.groupIdentifier
                        )
                    if (absolutePhotoUrlToUpload == null) {
                        // we don't have the photo --> remove it from the group
                        updatedServerPhotoInfo = null
                    } else {
                        // convert the photoUrl to an absolute path
                        absolutePhotoUrlToUpload = protocolManagerSession.fileIo.file(
                            protocolManagerSession.engineBaseDirectory,
                            absolutePhotoUrlToUpload
                        ).plainNameFile.path

                        updatedServerPhotoInfo = ServerPhotoInfo(
                            ownedIdentity,
                            UID(prng),
                            Suite.getDefaultAuthEnc(0).generateKey(prng)!!
                        )
                    }
                }
                updatedServerBlob = ServerBlob(
                    updatedAdministratorsChain!!,
                    members,
                    initialServerBlob.version + 1,
                    updatedSerializedGroupDetails!!,
                    updatedServerPhotoInfo,
                    updatedJsonGroupType
                )
            }


            val groupAdminServerAuthenticationKeyPair: KeyPair?
            if (adminKeyChangeRequired) {
                groupAdminServerAuthenticationKeyPair =
                    Suite.generateServerAuthenticationKeyPair(null, prng)
                if (groupAdminServerAuthenticationKeyPair == null) {
                    throw Exception()
                }
            } else {
                groupAdminServerAuthenticationKeyPair = KeyPair(
                    receivedMessage.groupAdminPublicKey,
                    blobKeys.groupAdminServerAuthenticationPrivateKey!!
                )
            }


            // if the start state contains a preShotVersionSeed, this means our changeset contained some member
            // removals and the blob version seed should be rotated. Otherwise, we reuse the versionSeed that was used to decrypt the blob we downloaded
            val updatedBlobKeys: BlobKeys = if (startState.preShotVersionSeed == null) {
                if (initialBlobVersionSeed == null) {
                    // this should never happen, we always have a version seed if we could decrypt the blob
                    BlobKeys(
                        blobKeys.blobMainSeed,
                        Seed(prng),
                        groupAdminServerAuthenticationKeyPair.getPrivateKey() as ServerAuthenticationPrivateKey
                    )
                } else {
                    // reuse the versionSeed that was used to decrypt the blob
                    BlobKeys(
                        blobKeys.blobMainSeed,
                        initialBlobVersionSeed,
                        groupAdminServerAuthenticationKeyPair.getPrivateKey() as ServerAuthenticationPrivateKey
                    )
                }
            } else {
                // use the preShotVersionSeed
                BlobKeys(
                    blobKeys.blobMainSeed,
                    startState.preShotVersionSeed,
                    groupAdminServerAuthenticationKeyPair.getPrivateKey() as ServerAuthenticationPrivateKey
                )
            }


            val encryptedBlob: EncryptedBytes
            run {
                // compute the encoded, signed, padded, and encrypted blob from the ServerBlob we have
                val encodedServerBlob = updatedServerBlob!!.encode()
                val signature = protocolManagerSession.identityDelegate.signBlock(
                    protocolManagerSession.session,
                    Constants.SignatureContext.GROUP_BLOB,
                    encodedServerBlob.bytes,
                    ownedIdentity,
                    prng
                )

                val encodedSignedBlob = Encoded.of(
                    arrayOf<Encoded>(
                        encodedServerBlob,
                        Encoded.of(ownedIdentity),
                        Encoded.of(signature!!),
                    )
                )

                val unpaddedLength = encodedSignedBlob.bytes.size
                val paddedLength =
                    (1 + ((unpaddedLength - 1) shr 12)) shl 12 // we pad to the smallest multiple of 4096 larger than the actual length

                val paddedBlobPlaintext = ByteArray(paddedLength)
                System.arraycopy(encodedSignedBlob.bytes, 0, paddedBlobPlaintext, 0, unpaddedLength)
                val blobEncryptionKey = GroupV2.getSharedBlobSecretKey(
                    updatedBlobKeys.blobMainSeed!!,
                    updatedBlobKeys.blobVersionSeed
                )
                encryptedBlob = Suite.getAuthEnc(blobEncryptionKey)!!
                    .encrypt(blobEncryptionKey, paddedBlobPlaintext, prng)
            }

            run {
                // upload the encrypted blob
                val encodedPublicKey = Encoded.of(groupAdminServerAuthenticationKeyPair.getPublicKey())

                val dataToSign =
                    ByteArray(startState.lockNonce.size + encryptedBlob.length + encodedPublicKey.bytes.size)
                System.arraycopy(startState.lockNonce, 0, dataToSign, 0, startState.lockNonce.size)
                System.arraycopy(
                    encryptedBlob.getBytes(),
                    0,
                    dataToSign,
                    startState.lockNonce.size,
                    encryptedBlob.length
                )
                System.arraycopy(
                    encodedPublicKey.bytes,
                    0,
                    dataToSign,
                    startState.lockNonce.size + encryptedBlob.length,
                    encodedPublicKey.bytes.size
                )

                val signature = Signature.sign(
                    Constants.SignatureContext.GROUP_UPDATE_ON_SERVER,
                    dataToSign,
                    blobKeys.groupAdminServerAuthenticationPrivateKey!!.signaturePrivateKey,
                    prng
                )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        UpdateGroupBlobQuery(
                            startState.groupIdentifier,
                            startState.lockNonce,
                            encryptedBlob,
                            encodedPublicKey,
                            signature!!
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    UploadGroupBlobMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return UploadingUpdatedGroupBlobState(
                startState.groupIdentifier,
                startState.changeSet,
                updatedServerBlob!!,
                updatedBlobKeys,
                membersToKick,
                absolutePhotoUrlToUpload,
                startState.failedUploadCounter,
                startState.preShotVersionSeed
            )
        }
    }


    class ProcessGroupUpdateBlobUploadResponseStep @Suppress("unused") constructor(
        internal val startState: UploadingUpdatedGroupBlobState,
        receivedMessage: UploadGroupBlobMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
    ) {
        internal val uploadResult: Int

        init {
            this.uploadResult = receivedMessage.uploadResult
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            if (uploadResult == 2 || (uploadResult == 1 && startState.failedUploadCounter > 9)) { // definitive fail
                protocolManagerSession.identityDelegate!!.unfreezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )

                val userInfo = HashMap<String, Any>()
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY,
                    ownedIdentity
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY,
                    startState.groupIdentifier
                )
                userInfo.put(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY,
                    true
                )
                protocolManagerSession.notificationPostingDelegate?.postNotification(
                    ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
                    userInfo
                )

                return FinalState()
            } else if (uploadResult == 1) { // retry-able fail
                // check that we still know the group and have the admin private key for group updates
                val blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
                if (blobKeys == null || blobKeys.groupAdminServerAuthenticationPrivateKey == null) {
                    // we don't have the key to update on server, discard the changeSet and notify (for app)
                    val userInfo = HashMap<String, Any>()
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY,
                        ownedIdentity
                    )
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY,
                        startState.groupIdentifier
                    )
                    userInfo.put(
                        ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY,
                        true
                    )
                    protocolManagerSession.notificationPostingDelegate?.postNotification(
                        ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
                        userInfo
                    )

                    protocolManagerSession.identityDelegate.unfreezeGroupV2(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.groupIdentifier
                    )

                    return FinalState()
                }


                // request a new group lock on server
                val localPrng5134 = prng
                val lockNonce = localPrng5134.bytes(Constants.GROUP_V2_LOCK_NONCE_LENGTH)
                run {
                    val signature = Signature.sign(
                        Constants.SignatureContext.GROUP_LOCK_ON_SERVER,
                        lockNonce,
                        blobKeys.groupAdminServerAuthenticationPrivateKey.signaturePrivateKey,
                        localPrng5134
                    )
                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createServerQueryChannelInfo(
                            ownedIdentity,
                            LockGroupBlobQuery(startState.groupIdentifier, lockNonce, signature!!)
                        )
                    )
                    val messageToSend: ChannelMessageToSend? =
                        RequestLockMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        localPrng5134
                    )
                }

                // increment fail counter and wait for the lock
                return WaitingForLockState(
                    startState.groupIdentifier,
                    startState.changeSet,
                    lockNonce,
                    startState.failedUploadCounter + 1,
                    startState.preShotVersionSeed
                )
            }


            // upload the group photo if needed
            if (startState.absolutePhotoUrlToUpload != null) {
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        PutUserDataQuery(
                            ownedIdentity,
                            startState.updatedBlob.serverPhotoInfo!!.serverPhotoLabel,
                            startState.absolutePhotoUrlToUpload,
                            startState.updatedBlob.serverPhotoInfo.serverPhotoKey
                        )
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    GroupsV2Protocol.UploadGroupPhotoMessage(coreProtocolMessage)
                        .generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            // Finalize the update immediately. We do not wait, even if there is a photo to upload.
            // This minimizes the risk of group members to receiving the updated group seeds
            run {
                val coreProtocolMessage =
                    buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                val messageToSend: ChannelMessageToSend? =
                    FinalizeGroupUpdateMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            // return an uploading photo state in all cases, even if there is no photo to upload
            return UploadingUpdatedGroupPhotoState(
                startState.groupIdentifier,
                startState.changeSet,
                startState.updatedBlob,
                startState.updatedBlobKeys,
                startState.membersToKick,
                startState.absolutePhotoUrlToUpload
            )
        }
    }

    class ProcessGroupUpdatePhotoUploadResponseStep : ProtocolStep {
        internal val startState: ConcreteProtocolState

        @Suppress("unused")
        constructor(
            startState: UploadingUpdatedGroupPhotoState,
            receivedMessage: UploadGroupPhotoMessage,
            protocol: GroupsV2Protocol?
        ) : super(ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!) {
            this.startState = startState
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState,
            receivedMessage: UploadGroupPhotoMessage,
            protocol: GroupsV2Protocol?
        ) : super(ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!) {
            this.startState = startState
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // this is for the legacy protocol and should no longer be used as we always immediately finalize the protocol
            if (startState is UploadingUpdatedGroupPhotoState) {
                // post a message to initiate the finalization of the group update
                val coreProtocolMessage =
                    buildCoreProtocolMessage(SendChannelInfo.createLocalChannelInfo(ownedIdentity))
                val messageToSend: ChannelMessageToSend? =
                    FinalizeGroupUpdateMessage(coreProtocolMessage).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            if (startState is InitialProtocolState) {
                return FinalState()
            }

            return startState
        }
    }


    class FinalizeGroupUpdateStep(
        internal val startState: UploadingUpdatedGroupPhotoState, @field:Suppress(
            "unused"
        ) internal val receivedMessage: FinalizeGroupUpdateMessage?, protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage!!, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // validate integrity of the chain so that the IdentityManager accepts it
            startState.updatedBlob.administratorsChain.withCheckedIntegrity(
                startState.groupIdentifier.groupUid,
                null,
                protocolManagerSession.identityDelegate!!.getGroupV2AdministratorsChain(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
            )
            val updateOutput = protocolManagerSession.identityDelegate.updateGroupV2WithNewBlob(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupIdentifier,
                startState.updatedBlob,
                startState.updatedBlobKeys,
                true,
                null,
                null,
                System.currentTimeMillis()
            )

            if (updateOutput == null) {
                // update failed, return null to try again
                return null
            }

            /**///////////////////// */
            // update successful
            //  - unfreeze the group
            //  - notify all members of new keys and invite new members to the group
            //  - kick removed members
            //  - copy the local photo to the IdentityManager
            protocolManagerSession.identityDelegate.unfreezeGroupV2(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupIdentifier
            )


            run {
                // for each group member & pending member, send
                //  - for members with an oblivious channel the main seed
                //  - the version seed for everyone
                //  - for admins the groupAdmin private key


                // Optimization to decrease the number of messages we send:
                // - For all users with a single device, we batch the InvitationOrMembersUpdateMessage to send less messages
                // - For users with multiple devices, as the message contains an array of notifiedDeviceUids, we send messages one at a time so they get the exact information.
                // We need to split between admins and others as we don't send them the same keys.
                val adminIdentitiesWithSingleChannel: MutableList<Identity> = ArrayList()
                val memberIdentitiesWithSingleChannel: MutableList<Identity> = ArrayList()

                // here we loop on ALL group members, including ourselves
                for (groupMember in startState.updatedBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                    val contactOrOwnedDeviceUidsWithChannel =
                        protocolManagerSession.channelDelegate!!.getConfirmedObliviousChannelOrPreKeyDeviceUids(
                            protocolManagerSession.session,
                            ownedIdentity,
                            groupMember.identity
                        )
                    val isAdmin =
                        groupMember.permissionStrings.contains(GroupV2.Permission.GROUP_ADMIN.string)

                    if (contactOrOwnedDeviceUidsWithChannel.size == 1) {
                        // single channel --> batch the message sending
                        if (isAdmin) {
                            adminIdentitiesWithSingleChannel.add(groupMember.identity)
                        } else {
                            memberIdentitiesWithSingleChannel.add(groupMember.identity)
                        }
                    } else if (contactOrOwnedDeviceUidsWithChannel.size > 1) {
                        // send through oblivious channel
                        val keysToSend: BlobKeys
                        if (isAdmin) {
                            keysToSend = startState.updatedBlobKeys
                        } else {
                            keysToSend = BlobKeys(
                                startState.updatedBlobKeys.blobMainSeed,
                                startState.updatedBlobKeys.blobVersionSeed,
                                null
                            )
                        }

                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAllConfirmedObliviousChannelsOrPreKeysInfo(
                                groupMember.identity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? = InvitationOrMembersUpdateMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier,
                            startState.updatedBlob.version,
                            keysToSend,
                            contactOrOwnedDeviceUidsWithChannel
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } else if (groupMember.identity != ownedIdentity) { // never send a broadcast message to our own devices
                        // send through broadcast channel
                        val keysToSend = BlobKeys(
                            null,
                            startState.updatedBlobKeys.blobVersionSeed,
                            if (isAdmin) startState.updatedBlobKeys.groupAdminServerAuthenticationPrivateKey else null
                        )

                        val coreProtocolMessage = buildCoreProtocolMessage(
                            createAsymmetricBroadcastChannelInfo(
                                groupMember.identity,
                                ownedIdentity
                            )
                        )
                        val messageToSend: ChannelMessageToSend? =
                            InvitationOrMembersUpdateBroadcastMessage(
                                coreProtocolMessage,
                                startState.groupIdentifier,
                                startState.updatedBlob.version,
                                keysToSend
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }

                // send a message to all admins with a single channel
                if (adminIdentitiesWithSingleChannel.isNotEmpty()) {
                    val sendChannelInfos =
                        createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            adminIdentitiesWithSingleChannel.toTypedArray(),
                            ownedIdentity
                        )!!
                    for (sendChannelInfo in sendChannelInfos) {
                        val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                        val messageToSend: ChannelMessageToSend? = InvitationOrMembersUpdateMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier,
                            startState.updatedBlob.version,
                            startState.updatedBlobKeys,
                            arrayOfNulls<UID>(0)
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }

                // send a message to all non-admin members with a single channel
                if (memberIdentitiesWithSingleChannel.isNotEmpty()) {
                    val keysToSend = BlobKeys(
                        startState.updatedBlobKeys.blobMainSeed,
                        startState.updatedBlobKeys.blobVersionSeed,
                        null
                    )
                    val sendChannelInfos =
                        createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                            memberIdentitiesWithSingleChannel.toTypedArray(),
                            ownedIdentity
                        )!!
                    for (sendChannelInfo in sendChannelInfos) {
                        val coreProtocolMessage = buildCoreProtocolMessage(sendChannelInfo)
                        val messageToSend: ChannelMessageToSend? = InvitationOrMembersUpdateMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier,
                            startState.updatedBlob.version,
                            keysToSend,
                            arrayOfNulls<UID>(0)
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    }
                }
            }

            if (!startState.membersToKick.isEmpty()) {
                // compute the encrypted administrators chain
                val chainPlaintext = startState.updatedBlob.administratorsChain.encode().bytes
                val encryptionKey = Suite.getKDF(KDF.KDF_SHA256).gen(
                    startState.updatedBlobKeys.blobMainSeed,
                    Suite.getDefaultAuthEnc(0).getKDFDelegate()
                )[0] as AuthEncKey?
                val encryptedChain = Suite.getAuthEnc(encryptionKey)!!
                    .encrypt(encryptionKey, chainPlaintext, prng)

                // kick removed members
                for (entry in startState.membersToKick.entries) {
                    val dataToSign = ByteArray(encryptedChain.length + entry.value!!.size)
                    System.arraycopy(
                        encryptedChain.getBytes(),
                        0,
                        dataToSign,
                        0,
                        encryptedChain.length
                    )
                    System.arraycopy(
                        entry.value,
                        0,
                        dataToSign,
                        encryptedChain.length,
                        entry.value!!.size
                    )

                    val signature = protocolManagerSession.identityDelegate.signBlock(
                        protocolManagerSession.session,
                        Constants.SignatureContext.GROUP_KICK,
                        dataToSign,
                        ownedIdentity,
                        prng
                    )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(entry.key, ownedIdentity)
                    )
                    val messageToSend: ChannelMessageToSend? = KickMessage(
                        coreProtocolMessage,
                        startState.groupIdentifier,
                        encryptedChain,
                        signature!!
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            // copy the photo to the IdentityManager
            if (startState.absolutePhotoUrlToUpload != null) {
                protocolManagerSession.identityDelegate.setUpdatedGroupV2PhotoUrl(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier,
                    startState.updatedBlob.version,
                    startState.absolutePhotoUrlToUpload
                )
            }

            return FinalState()
        }
    }


    class GetKickedStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val receivedMessage: KickMessage
        internal val propagated: Boolean

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: KickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState?,
            receivedMessage: KickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState?,
            receivedMessage: KickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState?,
            receivedMessage: KickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: KickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createAsymmetricChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = false
        }


        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagatedKickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState?,
            receivedMessage: PropagatedKickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState?,
            receivedMessage: PropagatedKickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState?,
            receivedMessage: PropagatedKickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: PropagatedKickMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.receivedMessage = receivedMessage
            this.propagated = true
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            run {
                // first check that the protocolInstanceUid matches the groupIdentifier
                if (!protocolInstanceUid!!.equals(receivedMessage.groupIdentifier.computeProtocolInstanceUid())) {
                    return startState
                }
            }

            if (!propagated) {
                // propagate the kick message
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
                        val messageToSend: ChannelMessageToSend? = PropagatedKickMessage(
                            coreProtocolMessage,
                            receivedMessage.groupIdentifier,
                            receivedMessage.encryptedAdministratorsChain,
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

            run {
                // check the kick message is valid
                val blobKeys: BlobKeys?
                val knownAdministratorsChain: AdministratorsChain?
                var invitationNonce: ByteArray? = null
                if (startState is InvitationReceivedState) {
                    blobKeys = startState.blobKeys
                    knownAdministratorsChain = startState.serverBlob.administratorsChain
                    var ownIdentityAndPermissionsAndDetails: IdentityAndPermissionsAndDetails? =
                        null
                    for (identityAndPermissionsAndDetails in startState.serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
                        if (identityAndPermissionsAndDetails.identity.equals(ownedIdentity)) {
                            ownIdentityAndPermissionsAndDetails = identityAndPermissionsAndDetails
                            
                        }
                    }
                    if (ownIdentityAndPermissionsAndDetails != null) {
                        invitationNonce = ownIdentityAndPermissionsAndDetails.groupInvitationNonce
                    }
                } else {
                    blobKeys = protocolManagerSession.identityDelegate!!.getGroupV2BlobKeys(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupIdentifier
                    )
                    knownAdministratorsChain =
                        protocolManagerSession.identityDelegate.getGroupV2AdministratorsChain(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.groupIdentifier
                        )
                    invitationNonce =
                        protocolManagerSession.identityDelegate.getGroupV2OwnGroupInvitationNonce(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.groupIdentifier
                        )
                }
                if (invitationNonce != null && blobKeys != null && blobKeys.blobMainSeed != null) {
                    // decrypt the AdministratorsChain
                    val encryptionKey = Suite.getKDF(KDF.KDF_SHA256).gen(
                        blobKeys.blobMainSeed,
                        Suite.getDefaultAuthEnc(0).getKDFDelegate()
                    )[0] as AuthEncKey?
                    val chainPlaintext = Suite.getAuthEnc(encryptionKey)!!
                        .decrypt(encryptionKey, receivedMessage.encryptedAdministratorsChain)!!
                    val administratorsChain = AdministratorsChain.of(Encoded(chainPlaintext))

                    // verify the chain
                    try {
                        administratorsChain.withCheckedIntegrity(
                            receivedMessage.groupIdentifier.groupUid,
                            null,
                            knownAdministratorsChain
                        )
                    } catch (_: Exception) {
                        return startState
                    }

                    // verify that the signature in the received message matches an administrator of the chain
                    val dataToSign =
                        ByteArray(receivedMessage.encryptedAdministratorsChain.length + invitationNonce.size)
                    System.arraycopy(
                        receivedMessage.encryptedAdministratorsChain.getBytes(),
                        0,
                        dataToSign,
                        0,
                        receivedMessage.encryptedAdministratorsChain.length
                    )
                    System.arraycopy(
                        invitationNonce,
                        0,
                        dataToSign,
                        receivedMessage.encryptedAdministratorsChain.length,
                        invitationNonce.size
                    )

                    var valid = false
                    var kicker: Identity? = null
                    for (identity in administratorsChain.adminIdentities) {
                        if (Signature.verify(
                                Constants.SignatureContext.GROUP_KICK,
                                dataToSign,
                                identity!!,
                                receivedMessage.signature
                            )
                        ) {
                            valid = true
                            kicker = identity

                        }
                    }

                    if (valid) {
                        // remove the dialog/delete the group
                        if (startState is InvitationReceivedState) {
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

                        protocolManagerSession.identityDelegate!!.deleteGroupV2(
                            protocolManagerSession.session,
                            ownedIdentity,
                            receivedMessage.groupIdentifier,
                            kicker
                        )
                        GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                            protocolManagerSession,
                            ownedIdentity,
                            receivedMessage.groupIdentifier
                        )

                        if (startState is DownloadingGroupBlobState || startState is INeedMoreSeedsState) {
                            return startState
                        } else {
                            return FinalState()
                        }
                    }
                }
            }

            return startState
        }
    }

    class LeaveGroupStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val groupIdentifier: GroupV2.Identifier
        internal val propagated: Boolean
        internal val ownGroupInvitationNonce: ByteArray?

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: GroupLeaveInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
            this.ownGroupInvitationNonce = null
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState?,
            receivedMessage: GroupLeaveInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
            this.ownGroupInvitationNonce = null
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState?,
            receivedMessage: GroupLeaveInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
            this.ownGroupInvitationNonce = null
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: GroupLeaveInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
            this.ownGroupInvitationNonce = null
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagatedGroupLeaveMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
            this.ownGroupInvitationNonce = receivedMessage.ownInvitationNonce
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState?,
            receivedMessage: PropagatedGroupLeaveMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
            this.ownGroupInvitationNonce = receivedMessage.ownInvitationNonce
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState?,
            receivedMessage: PropagatedGroupLeaveMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
            this.ownGroupInvitationNonce = receivedMessage.ownInvitationNonce
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: PropagatedGroupLeaveMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
            this.ownGroupInvitationNonce = receivedMessage.ownInvitationNonce
        }


        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // first check that the protocolInstanceUid matches the groupIdentifier
            if (!protocolInstanceUid!!.equals(this.groupIdentifier.computeProtocolInstanceUid())) {
                return startState
            }

            val ownGroupInvitationNonce =
                protocolManagerSession.identityDelegate!!.getGroupV2OwnGroupInvitationNonce(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier
                )

            // if we are not part of the group, abort!
            if (ownGroupInvitationNonce == null) {
                return startState
            }

            // propagated message for bad invitation nonce --> ignore the message
            if (propagated && !this.ownGroupInvitationNonce.contentEquals(ownGroupInvitationNonce)) {
                return startState
            }

            run {
                // if group is not frozen, check I am not the only admin
                val frozen = protocolManagerSession.identityDelegate.isGroupV2Frozen(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier
                )
                if (!frozen) {
                    val admin = protocolManagerSession.identityDelegate.getGroupV2AdminStatus(
                        protocolManagerSession.session,
                        ownedIdentity,
                        this.groupIdentifier
                    )
                    if (admin && !protocolManagerSession.identityDelegate.getGroupV2HasOtherAdminMember(
                            protocolManagerSession.session,
                            ownedIdentity,
                            this.groupIdentifier
                        )
                    ) {
                        return startState
                    }
                }
            }


            val groupMembersToNotify: MutableList<Identity?> = ArrayList<Identity?>()
            if (!propagated) {
                // propagate the group leave message to other devices
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
                        val messageToSend: ChannelMessageToSend? = PropagatedGroupLeaveMessage(
                            coreProtocolMessage,
                            this.groupIdentifier,
                            ownGroupInvitationNonce
                        ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (_: NoAcceptableChannelException) {
                    }
                }

                // put a group left log on server
                val leaveSignature =
                    protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                        protocolManagerSession.session,
                        Constants.SignatureContext.GROUP_LEAVE_NONCE,
                        groupIdentifier,
                        ownGroupInvitationNonce,
                        null,
                        ownedIdentity,
                        prng
                    )

                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        PutGroupLogQuery(groupIdentifier, leaveSignature!!)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    PutGroupLogOnServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                // get the list of members to notify (before deleting the group)
                for (groupMember in protocolManagerSession.identityDelegate.getGroupV2OtherMembersAndPermissions(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier
                )!!) {
                    groupMembersToNotify.add(groupMember!!.identity)
                }
            }

            run {
                // delete the group
                protocolManagerSession.identityDelegate.deleteGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier,
                    ownedIdentity
                )
                GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                    protocolManagerSession,
                    ownedIdentity,
                    this.groupIdentifier
                )
            }

            if (propagated) {
                return FinalState()
            } else {
                return RejectingInvitationOrLeavingGroupState(
                    this.groupIdentifier,
                    @Suppress("UNCHECKED_CAST") (groupMembersToNotify as MutableList<Identity>)
                )
            }
        }
    }

    class DisbandGroupStep : ProtocolStep {
        internal val startState: ConcreteProtocolState?
        internal val groupIdentifier: GroupV2.Identifier
        internal val propagated: Boolean

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: GroupDisbandInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: GroupDisbandInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: UploadingUpdatedGroupBlobState?,
            receivedMessage: GroupDisbandInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: UploadingUpdatedGroupPhotoState?,
            receivedMessage: GroupDisbandInitialMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = false
        }

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: INeedMoreSeedsState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            createAnyObliviousChannelOrPreKeyWithOwnedDeviceInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: UploadingUpdatedGroupBlobState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Suppress("unused")
        constructor(
            startState: UploadingUpdatedGroupPhotoState?,
            receivedMessage: PropagatedGroupDisbandMessage,
            protocol: GroupsV2Protocol?
        ) : super(
            ReceptionChannelInfo.createLocalChannelInfo(), receivedMessage, protocol!!
        ) {
            this.startState = startState
            this.groupIdentifier = receivedMessage.groupIdentifier
            this.propagated = true
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // first check that the protocolInstanceUid matches the groupIdentifier
            if (!protocolInstanceUid!!.equals(this.groupIdentifier.computeProtocolInstanceUid())) {
                return startState
            }

            // check I am an admin and I have the admin keys
            val admin = protocolManagerSession.identityDelegate!!.getGroupV2AdminStatus(
                protocolManagerSession.session,
                ownedIdentity,
                this.groupIdentifier
            )
            val blobKeys = protocolManagerSession.identityDelegate.getGroupV2BlobKeys(
                protocolManagerSession.session,
                ownedIdentity,
                this.groupIdentifier
            )

            if (!admin || blobKeys == null || blobKeys.groupAdminServerAuthenticationPrivateKey == null) {
                return FinalState()
            }

            if (!propagated) {
                // delete the group from the server
                val signature = Signature.sign(
                    Constants.SignatureContext.GROUP_DELETE_ON_SERVER,
                    blobKeys.groupAdminServerAuthenticationPrivateKey.signaturePrivateKey,
                    prng
                )
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createServerQueryChannelInfo(
                        ownedIdentity,
                        DeleteGroupBlobQuery(this.groupIdentifier, signature!!)
                    )
                )
                val messageToSend: ChannelMessageToSend? =
                    DeleteGroupBlobFromServerMessage(coreProtocolMessage).generateChannelServerQueryMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )

                // freeze the group
                protocolManagerSession.identityDelegate.freezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier
                )

                return DisbandingGroupState(this.groupIdentifier, blobKeys)
            } else {
                // locally delete the group
                protocolManagerSession.identityDelegate.deleteGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    this.groupIdentifier,
                    ownedIdentity
                )
                GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                    protocolManagerSession,
                    ownedIdentity,
                    this.groupIdentifier
                )

                return FinalState()
            }
        }
    }

    class FinalizeGroupDisbandStep(
        internal val startState: DisbandingGroupState,
        internal val receivedMessage: DeleteGroupBlobFromServerMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!


            if (!receivedMessage.success) {
                Logger.e("Failed to delete groupV2 blob on the server following a disband request")
                protocolManagerSession.identityDelegate!!.unfreezeGroupV2(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
                return FinalState()
            }

            run {
                // propagate the disband request
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
                        val messageToSend: ChannelMessageToSend? = PropagatedGroupDisbandMessage(
                            coreProtocolMessage,
                            startState.groupIdentifier
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
                // send kick messages to everyone else in the group
                val chainPlaintext =
                    protocolManagerSession.identityDelegate!!.getGroupV2AdministratorsChain(
                        protocolManagerSession.session,
                        ownedIdentity,
                        startState.groupIdentifier
                    )!!.encode().bytes
                val encryptionKey = Suite.getKDF(KDF.KDF_SHA256).gen(
                    startState.blobKeys.blobMainSeed,
                    Suite.getDefaultAuthEnc(0).getKDFDelegate()
                )[0] as AuthEncKey?
                val encryptedChain = Suite.getAuthEnc(encryptionKey)!!
                    .encrypt(encryptionKey, chainPlaintext, prng)

                val serverBlob = protocolManagerSession.identityDelegate.getGroupV2ServerBlob(
                    protocolManagerSession.session,
                    ownedIdentity,
                    startState.groupIdentifier
                )
                for (member in serverBlob!!.groupMemberIdentityAndPermissionsAndDetailsList) {
                    if (member.identity.equals(ownedIdentity)) {
                        continue
                    }

                    val dataToSign =
                        ByteArray(encryptedChain.length + member.groupInvitationNonce.size)
                    System.arraycopy(
                        encryptedChain.getBytes(),
                        0,
                        dataToSign,
                        0,
                        encryptedChain.length
                    )
                    System.arraycopy(
                        member.groupInvitationNonce,
                        0,
                        dataToSign,
                        encryptedChain.length,
                        member.groupInvitationNonce.size
                    )

                    val signature = protocolManagerSession.identityDelegate.signBlock(
                        protocolManagerSession.session,
                        Constants.SignatureContext.GROUP_KICK,
                        dataToSign,
                        ownedIdentity,
                        prng
                    )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(member.identity, ownedIdentity)
                    )
                    val messageToSend: ChannelMessageToSend? = KickMessage(
                        coreProtocolMessage,
                        startState.groupIdentifier,
                        encryptedChain,
                        signature!!
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            }

            // locally delete the group
            protocolManagerSession.identityDelegate!!.deleteGroupV2(
                protocolManagerSession.session,
                ownedIdentity,
                startState.groupIdentifier,
                ownedIdentity
            )
            GroupV2PreShotVersionSeedReceived.deleteAllForGroupIdentifier(
                protocolManagerSession,
                ownedIdentity,
                startState.groupIdentifier
            )

            return FinalState()
        }
    }


    class PrepareBatchKeysMessageStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateBatchKeysResendMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // get all shared groups with the contact (or owned identity)
            val identifierVersionAndKeys: Array<IdentifierVersionAndKeys>?
            if (receivedMessage.contactIdentity == ownedIdentity) {
                @Suppress("UNCHECKED_CAST")
                identifierVersionAndKeys =
                    protocolManagerSession.identityDelegate!!.getAllServerGroupsV2IdentifierVersionAndKeys(
                        protocolManagerSession.session,
                        ownedIdentity
                    ) as Array<IdentifierVersionAndKeys>?
            } else {
                @Suppress("UNCHECKED_CAST")
                identifierVersionAndKeys =
                    protocolManagerSession.identityDelegate!!.getServerGroupsV2IdentifierVersionAndKeysForContact(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.contactIdentity
                    ) as Array<IdentifierVersionAndKeys>?
            }

            if (identifierVersionAndKeys!!.size > 0) {
                val coreProtocolMessage = buildCoreProtocolMessage(
                    createObliviousChannelOrPreKeyInfo(
                        receivedMessage.contactIdentity,
                        ownedIdentity,
                        arrayOf<UID?>(receivedMessage.contactDeviceUid),
                        false
                    )
                )
                val messageToSend: ChannelMessageToSend? = BlobKeysBatchAfterChannelCreationMessage(
                    coreProtocolMessage,
                    identifierVersionAndKeys
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }


    class ProcessBatchKeysMessageStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: BlobKeysBatchAfterChannelCreationMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        createAnyObliviousChannelOrPreKeyInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // post one local message with the correct protocol uid for each group
            for (identifierVersionAndKeys in receivedMessage.groupInfos) {
                val protocolInstanceUid =
                    identifierVersionAndKeys.groupIdentifier.computeProtocolInstanceUid()

                val coreProtocolMessage = CoreProtocolMessage(
                    SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                    ConcreteProtocol.GROUPS_V2_PROTOCOL_ID,
                    protocolInstanceUid
                )
                val messageToSend: ChannelMessageToSend? = BlobKeysAfterChannelCreationMessage(
                    coreProtocolMessage,
                    receivedMessage.receptionChannelInfo!!.getRemoteIdentity()!!,
                    identifierVersionAndKeys.groupIdentifier,
                    identifierVersionAndKeys.groupVersion,
                    identifierVersionAndKeys.blobKeys
                ).generateChannelProtocolMessageToSend()
                protocolManagerSession.channelDelegate!!.post(
                    protocolManagerSession.session,
                    messageToSend,
                    prng
                )
            }

            return FinalState()
        }
    }

    class ProcessCreateOrUpdateKeycloakGroupMessage(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: CreateOrUpdateKeycloakGroupMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState? {
            val protocolManagerSession = protocolManagerSession!!

            // first check that the protocolInstanceUid matches the groupIdentifier
            if (!protocolInstanceUid!!.equals(receivedMessage.groupIdentifier.computeProtocolInstanceUid())) {
                return FinalState()
            }

            val keycloakGroupBlob: KeycloakGroupBlob
            try {
                keycloakGroupBlob = protocol.jsonObjectMapper.readValue<KeycloakGroupBlob>(
                    receivedMessage.serializedKeycloakGroupBlob,
                    KeycloakGroupBlob::class.java
                )
            } catch (e: JsonProcessingException) {
                Logger.x(e)
                // if the json can't be parsed, don't do anything
                return FinalState()
            }

            val existingGroupTimestamp =
                protocolManagerSession.identityDelegate!!.getGroupV2LastModificationTimestamp(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupIdentifier
                )

            if (existingGroupTimestamp == null) {
                // we need to create this keycloak group
                val ownGroupInvitationNonce =
                    protocolManagerSession.identityDelegate.createKeycloakGroupV2(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupIdentifier,
                        keycloakGroupBlob
                    )

                if (ownGroupInvitationNonce == null) {
                    // if we were not able to create the group, abort!
                    return null
                }

                // check if a photo download is needed
                if (keycloakGroupBlob.photoUid != null && keycloakGroupBlob.encodedPhotoKey != null) {
                    try {
                        val photoUid = UID(keycloakGroupBlob.photoUid!!)
                        val photoKey =
                            Encoded(keycloakGroupBlob.encodedPhotoKey!!).decodeSymmetricKey() as AuthEncKey?

                        val serverPhotoInfo = ServerPhotoInfo(null, photoUid, photoKey!!)

                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
                            UID(prng)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            DownloadGroupV2PhotoProtocol.InitialMessage(
                                coreProtocolMessage,
                                receivedMessage.groupIdentifier,
                                serverPhotoInfo
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (e: Exception) {
                        // if photo download fails, do not abort the whole step
                        Logger.x(e)
                    }
                }

                // send a ping to all members to notify them you indeed joined the group
                for (groupMemberAndPermissions in keycloakGroupBlob.groupMembersAndPermissions!!) {
                    val groupMemberIdentity = Identity.of(groupMemberAndPermissions!!.identity!!)
                    if (ownedIdentity.equals(groupMemberIdentity)) {
                        continue
                    }

                    val pingSignature =
                        protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                            protocolManagerSession.session,
                            Constants.SignatureContext.GROUP_JOIN_NONCE,
                            receivedMessage.groupIdentifier,
                            ownGroupInvitationNonce,
                            groupMemberIdentity,
                            ownedIdentity,
                            prng
                        )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(
                            groupMemberIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                        coreProtocolMessage,
                        receivedMessage.groupIdentifier,
                        ownGroupInvitationNonce,
                        pingSignature!!,
                        false
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            } else if (existingGroupTimestamp < keycloakGroupBlob.timestamp) {
                // we need to update this keycloak group
                val updateOutput =
                    protocolManagerSession.identityDelegate.updateKeycloakGroupV2WithNewBlob(
                        protocolManagerSession.session,
                        ownedIdentity,
                        receivedMessage.groupIdentifier,
                        keycloakGroupBlob
                    )

                if (updateOutput == null) {
                    // if we were not able to update the group, abort!
                    return null
                }

                // trigger a photo download if needed
                if (updateOutput.photoNeedsToBeDownloaded) {
                    try {
                        val photoUid = UID(keycloakGroupBlob.photoUid!!)
                        val photoKey =
                            Encoded(keycloakGroupBlob.encodedPhotoKey!!).decodeSymmetricKey() as AuthEncKey?

                        val serverPhotoInfo = ServerPhotoInfo(null, photoUid, photoKey!!)

                        val coreProtocolMessage = CoreProtocolMessage(
                            SendChannelInfo.createLocalChannelInfo(ownedIdentity),
                            ConcreteProtocol.DOWNLOAD_GROUPS_V2_PHOTO_PROTOCOL_ID,
                            UID(prng)
                        )
                        val messageToSend: ChannelMessageToSend? =
                            DownloadGroupV2PhotoProtocol.InitialMessage(
                                coreProtocolMessage,
                                receivedMessage.groupIdentifier,
                                serverPhotoInfo
                            ).generateChannelProtocolMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                    } catch (e: Exception) {
                        // if photo download fails, do not abort the whole step
                        Logger.x(e)
                    }
                }

                // send a ping to all new members to notify them you joined the group
                for (groupMemberIdentity in updateOutput.membersWithNewInvitationNonce) {
                    val pingSignature =
                        protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                            protocolManagerSession.session,
                            Constants.SignatureContext.GROUP_JOIN_NONCE,
                            receivedMessage.groupIdentifier,
                            updateOutput.ownInvitationNonce,
                            groupMemberIdentity,
                            ownedIdentity,
                            prng
                        )

                    val coreProtocolMessage = buildCoreProtocolMessage(
                        createAsymmetricBroadcastChannelInfo(
                            groupMemberIdentity,
                            ownedIdentity
                        )
                    )
                    val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                        coreProtocolMessage,
                        receivedMessage.groupIdentifier,
                        updateOutput.ownInvitationNonce,
                        pingSignature!!,
                        false
                    ).generateChannelProtocolMessageToSend()
                    protocolManagerSession.channelDelegate!!.post(
                        protocolManagerSession.session,
                        messageToSend,
                        prng
                    )
                }
            } else if (existingGroupTimestamp > keycloakGroupBlob.timestamp) {
                // this blob is outdated!
                Logger.i("Received a keycloak group blob with an older timestamp than our current group")
            } else {
                // we received the same blob (same timestamp) --> do nothing
                Logger.d("Received a keycloak blob we already received. Nothing wrong about that.")
            }

            return FinalState()
        }
    }

    class SendKeycloakGroupTargetedPingStep(
        @field:Suppress("unused") internal val startState: InitialProtocolState?,
        internal val receivedMessage: InitiateTargetedPingMessage,
        protocol: GroupsV2Protocol?
    ) : ProtocolStep(
        ReceptionChannelInfo.createLocalChannelInfo(),
        receivedMessage, protocol!!
    ) {
        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // first check that the protocolInstanceUid matches the groupIdentifier
            if (!protocolInstanceUid!!.equals(receivedMessage.groupIdentifier.computeProtocolInstanceUid())) {
                return FinalState()
            }

            // get the group own invitation nonce
            val ownInvitationNonce =
                protocolManagerSession.identityDelegate!!.getGroupV2OwnGroupInvitationNonce(
                    protocolManagerSession.session,
                    ownedIdentity,
                    receivedMessage.groupIdentifier
                )

            val pingSignature = protocolManagerSession.identityDelegate.signGroupInvitationNonce(
                protocolManagerSession.session,
                Constants.SignatureContext.GROUP_JOIN_NONCE,
                receivedMessage.groupIdentifier,
                ownInvitationNonce!!,
                receivedMessage.pendingMemberIdentity,
                ownedIdentity,
                prng
            )

            val coreProtocolMessage = buildCoreProtocolMessage(
                createAsymmetricBroadcastChannelInfo(
                    receivedMessage.pendingMemberIdentity,
                    ownedIdentity
                )
            )
            val messageToSend: ChannelMessageToSend? = GroupsV2Protocol.PingMessage(
                coreProtocolMessage,
                receivedMessage.groupIdentifier,
                ownInvitationNonce,
                pingSignature!!,
                false
            ).generateChannelProtocolMessageToSend()
            protocolManagerSession.channelDelegate!!.post(
                protocolManagerSession.session,
                messageToSend,
                prng
            )

            return FinalState()
        }
    }

    class ProcessReceivedPreShotVersionSeedStep : ProtocolStep {
        internal val startState: ConcreteProtocolState
        internal val receivedMessage: PreShotVersionSeedMessage

        @Suppress("unused")
        constructor(
            startState: InitialProtocolState,
            receivedMessage: PreShotVersionSeedMessage,
            protocol: GroupsV2Protocol?
        ) : super(createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!) {
            this.startState = startState
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: DownloadingGroupBlobState,
            receivedMessage: PreShotVersionSeedMessage,
            protocol: GroupsV2Protocol?
        ) : super(createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!) {
            this.startState = startState
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: InvitationReceivedState,
            receivedMessage: PreShotVersionSeedMessage,
            protocol: GroupsV2Protocol?
        ) : super(createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!) {
            this.startState = startState
            this.receivedMessage = receivedMessage
        }

        @Suppress("unused")
        constructor(
            startState: WaitingForLockState,
            receivedMessage: PreShotVersionSeedMessage,
            protocol: GroupsV2Protocol?
        ) : super(createAnyObliviousChannelOrPreKeyInfo(), receivedMessage, protocol!!) {
            this.startState = startState
            this.receivedMessage = receivedMessage
        }

        @Throws(Exception::class)
        override fun executeStep(): ConcreteProtocolState {
            val protocolManagerSession = protocolManagerSession!!

            // check that the protocolInstanceUid matches the groupIdentifier
            if (protocolInstanceUid!! == receivedMessage.groupIdentifier.computeProtocolInstanceUid()) {
                // store the preShotVersionSeed without checking who sent it: this might be an admin we are not yet aware of
                GroupV2PreShotVersionSeedReceived.create(
                    protocolManagerSession,
                    ownedIdentity,
                    receivedMessage.groupIdentifier,
                    receivedMessage.versionSeed
                )
            }

            return if (startState is InitialProtocolState) {
                FinalState()
            } else {
                startState
            }
        }
    }
    // endregion

    companion object {
        // region States
        private const val UPLOADING_CREATED_GROUP_DATA_STATE_ID = 1 // frozen
        private const val DOWNLOADING_GROUP_BLOB_STATE_ID = 2 // frozen
        private const val I_NEED_MORE_SEEDS_STATE_ID = 3 // frozen
        private const val INVITATION_RECEIVED_STATE_ID = 4
        private const val REJECTING_INVITATION_OR_LEAVING_GROUP_STATE_ID = 5
        private const val WAITING_FOR_LOCK_STATE_ID = 6 // frozen
        private const val UPLOADING_UPDATED_GROUP_BLOB_STATE_ID = 7 // frozen
        private const val UPLOADING_UPDATED_GROUP_PHOTO_STATE_ID = 8 // frozen
        private const val DISBANDING_GROUP_STATE_ID = 9 // frozen

        private const val FINAL_STATE_ID = 99

        fun encodeMembersToKick(membersToKick: HashMap<Identity?, ByteArray?>): Encoded {
            val encodeds = arrayOfNulls<Encoded>(2 * membersToKick.size)
            var i = 0
            for (entry in membersToKick.entries) {
                encodeds[i] = Encoded.of(entry.key!!)
                encodeds[i + 1] = Encoded.of(entry.value!!)
                i += 2
            }
            return Encoded.of(encodeds.requireNoNulls())
        }

        @Throws(DecodingException::class)
        fun decodeMembersToKick(encoded: Encoded): HashMap<Identity?, ByteArray?> {
            val membersToKick = HashMap<Identity?, ByteArray?>()
            val encodeds: Array<Encoded> = encoded.decodeList()
            var i = 0
            while (i < encodeds.size) {
                membersToKick.put(encodeds[i].decodeIdentity(), encodeds[i + 1].decodeBytes())
                i += 2
            }
            return membersToKick
        }

        // endregion
        // region Messages
        private const val GROUP_CREATION_INITIAL_MESSAGE_ID = 0
        private const val UPLOAD_GROUP_PHOTO_MESSAGE_ID = 1
        private const val UPLOAD_GROUP_BLOB_MESSAGE_ID = 2
        private const val FINALIZE_GROUP_CREATION_MESSAGE_ID = 3
        private const val INVITATION_OR_MEMBERS_UPDATE_MESSAGE_ID = 4
        private const val INVITATION_OR_MEMBERS_UPDATE_BROADCAST_MESSAGE_ID = 5
        private const val INVITATION_OR_MEMBERS_UPDATE_PROPAGATED_MESSAGE_ID = 6
        private const val DOWNLOAD_GROUP_BLOB_MESSAGE_ID = 7
        private const val FINALIZE_GROUP_UPDATE_MESSAGE_ID = 8
        private const val DELETE_GROUP_BLOB_FROM_SERVER_MESSAGE_ID = 9
        private const val DIALOG_ACCEPT_GROUP_INVITATION_MESSAGE_ID = 10
        private const val PING_MESSAGE_ID = 11
        private const val PROPAGATED_PING_MESSAGE_ID = 12
        private const val KICK_MESSAGE_ID = 13
        private const val PROPAGATE_INVITATION_DIALOG_RESPONSE_MESSAGE_ID = 14
        private const val PUT_GROUP_LOG_ON_SERVER_MESSAGE_ID = 15
        private const val INVITATION_REJECTED_BROADCAST_MESSAGE_ID = 16
        private const val PROPAGATE_INVITATION_REJECTED_MESSAGE_ID = 17
        private const val GROUP_UPDATE_INITIAL_MESSAGE_ID = 18
        private const val REQUEST_LOCK_MESSAGE_ID = 19
        private const val GROUP_LEAVE_INITIAL_MESSAGE_ID = 20
        private const val PROPAGATED_GROUP_LEAVE_MESSAGE_ID = 21
        private const val GROUP_DISBAND_INITIAL_MESSAGE_ID = 22
        private const val PROPAGATED_GROUP_DISBAND_MESSAGE_ID = 23
        private const val PROPAGATED_KICK_MESSAGE_ID = 24
        private const val GROUP_RE_DOWNLOAD_INITIAL_MESSAGE_ID = 25
        private const val INITIATE_BATCH_KEYS_RESEND_MESSAGE_ID = 26
        private const val BLOB_KEYS_BATCH_AFTER_CHANNEL_CREATION_MESSAGE_ID = 27
        private const val BLOB_KEYS_AFTER_CHANNEL_CREATION_MESSAGE_ID = 28
        private const val CREATE_OR_UPDATE_KEYCLOAK_GROUP_MESSAGE_ID = 29
        private const val INITIATE_TARGETED_PING_MESSAGE_ID = 30
        private const val PRE_SHOT_VERSION_SEED_MESSAGE_ID = 31
        private const val AUTO_ACCEPT_INVITATION_MESSAGE = 400
    }
}
