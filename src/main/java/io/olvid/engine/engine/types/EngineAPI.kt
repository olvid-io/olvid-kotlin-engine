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
package io.olvid.engine.engine.types

import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.engine.types.identities.ObvContactActiveOrInactiveReason
import io.olvid.engine.engine.types.identities.ObvGroup
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2DetailsAndPhotos
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.identities.ObvMutualScanUrl
import io.olvid.engine.engine.types.identities.ObvOwnedDevice
import io.olvid.engine.engine.types.identities.ObvTrustOrigin
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import io.olvid.engine.engine.types.sync.ObvSyncSnapshot
import org.jose4j.jwk.JsonWebKey
import java.util.EnumSet
import java.util.UUID

interface EngineAPI {
    enum class ApiKeyPermission {
        CALL,
        WEB_CLIENT,
        MULTI_DEVICE,
    }

    enum class ApiKeyStatus {
        UNKNOWN,
        VALID,
        LICENSES_EXHAUSTED,
        EXPIRED,
        OPEN_BETA_KEY,
        FREE_TRIAL_KEY,
        AWAITING_PAYMENT_GRACE_PERIOD,
        AWAITING_PAYMENT_ON_HOLD,
        FREE_TRIAL_KEY_EXPIRED,
    }

    fun startProcessing()

    // Engine notifications
    fun addNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?
    )

    fun addNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?,
        priority: ListenerPriority?
    )

    fun removeNotificationListener(
        notificationName: String?,
        engineNotificationListener: EngineNotificationListener?
    )

    fun startSendingNotifications()
    fun stopSendingNotifications()
    fun runTaskOnEngineNotificationQueue(runnable: Runnable?)

    enum class ListenerPriority {
        LOW,
        NORMAL,
        HIGH,
    }

    fun getEngineDbQueryStatistics(): MutableMap<String, EngineDbQueryStatisticsEntry>

    // ObvOwnedIdentity
    fun getServerOfIdentity(bytesIdentity: ByteArray?): String?

    @Throws(Exception::class)
    fun getOwnedIdentities(): Array<ObvIdentity>

    @Throws(Exception::class)
    fun getOwnedIdentity(bytesOwnedIdentity: ByteArray?): ObvIdentity?
    fun generateOwnedIdentity(
        server: String?,
        jsonIdentityDetails: JsonIdentityDetails?,
        keycloakState: ObvKeycloakState?,
        deviceDisplayName: String?
    ): ObvIdentity?

    fun registerOwnedIdentityApiKeyOnServer(
        bytesOwnedIdentity: ByteArray?,
        apiKey: UUID?
    ): RegisterApiKeyResult

    fun recreateServerSession(bytesOwnedIdentity: ByteArray?)

    @Throws(Exception::class)
    fun deleteOwnedIdentity(bytesOwnedIdentity: ByteArray?)

    @Throws(Exception::class)
    fun getOwnedIdentityPublishedAndLatestDetails(bytesOwnedIdentity: ByteArray?): Array<JsonIdentityDetailsWithVersionAndPhoto?>?

    @Throws(Exception::class)
    fun getOwnedIdentityKeycloakState(bytesOwnedIdentity: ByteArray?): ObvKeycloakState?

    @Throws(Exception::class)
    fun saveKeycloakAuthState(bytesOwnedIdentity: ByteArray?, serializedAuthState: String?)

    @Throws(Exception::class)
    fun saveKeycloakJwks(bytesOwnedIdentity: ByteArray?, serializedJwks: String?)

    @Throws(Exception::class)
    fun saveKeycloakApiKey(bytesOwnedIdentity: ByteArray?, apiKey: String?)

    @Throws(Exception::class)
    fun getOwnedIdentitiesWithKeycloakPushTopic(pushTopic: String?): MutableCollection<ObvIdentity>

    @Throws(Exception::class)
    fun getOwnedIdentityKeycloakUserId(bytesOwnedIdentity: ByteArray?): String?

    @Throws(Exception::class)
    fun setOwnedIdentityKeycloakUserId(bytesOwnedIdentity: ByteArray?, userId: String?)

    @Throws(Exception::class)
    fun getOwnedIdentityKeycloakSignatureKey(bytesOwnedIdentity: ByteArray?): JsonWebKey?

    @Throws(Exception::class)
    fun setOwnedIdentityKeycloakSignatureKey(
        bytesOwnedIdentity: ByteArray?,
        signatureKey: JsonWebKey?
    )

    @Throws(Exception::class)
    fun setOwnedIdentityKeycloakSupportsIdBasedAuth(
        bytesOwnedIdentity: ByteArray?,
        supportsIdBasedAuth: Boolean
    )

    fun bindOwnedIdentityToKeycloak(
        bytesOwnedIdentity: ByteArray?,
        keycloakState: ObvKeycloakState?,
        keycloakUserId: String?
    ): ObvIdentity?

    fun unbindOwnedIdentityFromKeycloak(bytesOwnedIdentity: ByteArray?)
    fun updateKeycloakTransferRestrictedIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        transferRestricted: Boolean
    )

    fun updateKeycloakPushTopicsIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        pushTopics: MutableList<String?>?
    )

    fun updateKeycloakRevocationList(
        bytesOwnedIdentity: ByteArray?,
        latestRevocationListTimestamp: Long,
        signedRevocations: MutableList<String?>?
    )

    fun setOwnedIdentityKeycloakSelfRevocationTestNonce(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?,
        nonce: String?
    )

    fun getOwnedIdentityKeycloakSelfRevocationTestNonce(
        bytesOwnedIdentity: ByteArray?,
        serverUrl: String?
    ): String?

    fun updateKeycloakGroups(
        bytesOwnedIdentity: ByteArray?,
        signedGroupBlobs: MutableList<String?>?,
        signedGroupDeletions: MutableList<String?>?,
        signedGroupKicks: MutableList<String?>?,
        keycloakCurrentTimestamp: Long
    ): Boolean

    fun performKeycloakIdBasedAuth(bytesOwnedIdentity: ByteArray?): ObvKeycloakIdBasedAuthResult?

    @Throws(Exception::class)
    fun registerToPushNotification(
        bytesOwnedIdentity: ByteArray?,
        pushNotificationType: ObvPushNotificationType?,
        reactivateCurrentDevice: Boolean,
        bytesDeviceUidToReplace: ByteArray?
    )

    fun processAndroidPushNotification(maskingUidString: String?)
    fun getOwnedIdentityFromMaskingUid(maskingUidString: String?): ByteArray?

    @Throws(Exception::class)
    fun processDeviceManagementRequest(
        bytesOwnedIdentity: ByteArray?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    )

    @Throws(Exception::class)
    fun updateLatestIdentityDetails(
        bytesOwnedIdentity: ByteArray?,
        jsonIdentityDetails: JsonIdentityDetails?
    )

    fun discardLatestIdentityDetails(bytesOwnedIdentity: ByteArray?)
    fun publishLatestIdentityDetails(bytesOwnedIdentity: ByteArray?)

    @Throws(Exception::class)
    fun updateOwnedIdentityPhoto(bytesOwnedIdentity: ByteArray?, absolutePhotoUrl: String?)

    fun getServerAuthenticationToken(bytesOwnedIdentity: ByteArray?): ByteArray?

    fun getOwnCapabilities(bytesOwnedIdentity: ByteArray?): MutableList<ObvCapability>? // returns null in case of error, empty list if there are no capabilities
    fun getOwnedDevices(bytesOwnedIdentity: ByteArray?): MutableList<ObvOwnedDevice>?
    fun queryRegisteredOwnedDevicesFromServer(bytesOwnedIdentity: ByteArray?): ObvDeviceList?
    fun refreshOwnedDeviceList(bytesOwnedIdentity: ByteArray?)
    fun recreateOwnedDeviceChannel(bytesOwnedIdentity: ByteArray?, bytesDeviceUid: ByteArray?)


    //    void resynchronizeAllOwnedDevices(byte[] bytesOwnedIdentity);
    // ObvContactIdentity
    @Throws(Exception::class)
    fun getContactsOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): Array<ObvIdentity>

    @Throws(Exception::class)
    fun getContactsInfoOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): MutableList<ObvContactInfo>
    fun getContactActiveOrInactiveReasons(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): EnumSet<ObvContactActiveOrInactiveReason>?

    fun forcefullyUnblockContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Boolean

    fun reBlockForcefullyUnblockedContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Boolean

    @Throws(Exception::class)
    fun isContactOneToOne(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?): Boolean

    @Throws(Exception::class)
    fun getContactDeviceCounts(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): ObvContactDeviceCount?

    fun forceContactDeviceDiscovery(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun getContactTrustedDetailsPhotoUrl(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): String?

    @Throws(Exception::class)
    fun getContactPublishedAndTrustedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>?

    fun trustPublishedContactDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun getContactTrustOrigins(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): Array<ObvTrustOrigin?>?

    @Throws(Exception::class)
    fun getContactTrustLevel(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?): Int
    fun getContactCapabilities(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    ): MutableList<ObvCapability>? // returns null in case of error, empty list if there are no capabilities


    // ObvGroup
    @Throws(Exception::class)
    fun getGroupsOfOwnedIdentity(bytesOwnedIdentity: ByteArray?): Array<ObvGroup>

    @Throws(Exception::class)
    fun getGroupPublishedAndLatestOrTrustedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ): Array<JsonGroupDetailsWithVersionAndPhoto?>?

    @Throws(Exception::class)
    fun getGroupTrustedDetailsPhotoUrl(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    ): String?

    fun trustPublishedGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?
    )

    @Throws(Exception::class)
    fun updateLatestGroupDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        jsonGroupDetails: JsonGroupDetails?
    )

    fun discardLatestGroupDetails(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?)
    fun publishLatestGroupDetails(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?)

    @Throws(Exception::class)
    fun updateOwnedGroupPhoto(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        absolutePhotoUrl: String?
    )

    // Group V2
    @Throws(Exception::class)
    fun getGroupsV2OfOwnedIdentity(bytesOwnedIdentity: ByteArray?): MutableList<ObvGroupV2>

    @Throws(Exception::class)
    fun trustGroupV2PublishedDetails(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    )

    fun getGroupV2DetailsAndPhotos(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ): ObvGroupV2DetailsAndPhotos?

    fun getGroupV2JsonType(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?
    ): String?

    @Throws(Exception::class)
    fun initiateGroupV2Update(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupIdentifier: ByteArray?,
        changeSet: ObvGroupV2ChangeSet?
    )

    @Throws(Exception::class)
    fun leaveGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?)

    @Throws(Exception::class)
    fun disbandGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?)

    @Throws(Exception::class)
    fun reDownloadGroupV2(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?)

    @Throws(Exception::class)
    fun getGroupV2Version(bytesOwnedIdentity: ByteArray?, bytesGroupIdentifier: ByteArray?): Int?

    @Throws(Exception::class)
    fun isGroupV2UpdateInProgress(
        bytesOwnedIdentity: ByteArray?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean


    // ObvDialog
    @Throws(Exception::class)
    fun deletePersistedDialog(uuid: UUID?)

    @Throws(Exception::class)
    fun getAllPersistedDialogUuids(): MutableSet<UUID>

    @Throws(Exception::class)
    fun resendAllPersistedDialogs()

    @Throws(Exception::class)
    fun respondToDialog(dialog: ObvDialog?)

    @Throws(Exception::class)
    fun abortProtocol(dialog: ObvDialog?)

    // Start protocols
    @Throws(Exception::class)
    fun startTrustEstablishmentProtocol(
        bytesRemoteIdentity: ByteArray?,
        contactDisplayName: String?,
        bytesOwnedIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun computeMutualScanSignedNonceUrl(
        bytesRemoteIdentity: ByteArray?,
        bytesOwnedIdentity: ByteArray?,
        ownDisplayName: String?
    ): ObvMutualScanUrl

    fun verifyMutualScanSignedNonceUrl(
        bytesOwnedIdentity: ByteArray?,
        mutualScanUrl: ObvMutualScanUrl?
    ): Boolean

    @Throws(Exception::class)
    fun startMutualScanTrustEstablishmentProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesRemoteIdentity: ByteArray?,
        signature: ByteArray?
    )

    @Throws(Exception::class)
    fun startContactMutualIntroductionProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentityA: ByteArray?,
        bytesContactIdentities: Array<ByteArray?>?
    )

    @Throws(Exception::class)
    fun startGroupCreationProtocol(
        serializedGroupDetailsWithVersionAndPhoto: String?,
        absolutePhotoUrl: String?,
        bytesOwnedIdentity: ByteArray?,
        bytesRemoteIdentities: Array<ByteArray?>?
    )

    @Throws(Exception::class)
    fun startGroupV2CreationProtocol(
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        bytesOwnedIdentity: ByteArray?,
        ownPermissions: HashSet<GroupV2.Permission?>?,
        otherGroupMembers: HashMap<ObvBytesKey?, HashSet<GroupV2.Permission?>?>?,
        serializedGroupType: String?
    )

    @Throws(Exception::class)
    fun restartAllOngoingChannelEstablishmentProtocols(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun recreateAllChannels(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?)

    @Throws(Exception::class)
    fun recreateAllChannels(bytesOwnedIdentity: ByteArray?)

    @Throws(Exception::class)
    fun inviteContactsToGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesNewMemberIdentities: Array<ByteArray?>?
    )

    @Throws(Exception::class)
    fun removeContactsFromGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesRemovedMemberIdentities: Array<ByteArray?>?
    )

    @Throws(Exception::class)
    fun reinvitePendingToGroup(
        bytesOwnedIdentity: ByteArray?,
        bytesGroupOwnerAndUid: ByteArray?,
        bytesPendingMemberIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun leaveGroup(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?)

    @Throws(Exception::class)
    fun disbandGroup(bytesOwnedIdentity: ByteArray?, bytesGroupOwnerAndUid: ByteArray?)

    @Throws(Exception::class)
    fun deleteContact(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?)

    @Throws(Exception::class)
    fun downgradeOneToOneContact(bytesOwnedIdentity: ByteArray?, bytesContactIdentity: ByteArray?)

    @Throws(Exception::class)
    fun startOneToOneInvitationProtocol(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun deleteOwnedIdentityAndNotifyContacts(
        bytesOwnedIdentity: ByteArray?,
        deleteEverywhere: Boolean
    )

    @Throws(Exception::class)
    fun queryGroupOwnerForLatestGroupMembers(
        bytesGroupOwnerAndUid: ByteArray?,
        bytesOwnedIdentity: ByteArray?
    )

    @Throws(Exception::class)
    fun addKeycloakContact(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?,
        signedContactDetails: String?
    )

    @Throws(Exception::class)
    fun initiateOwnedIdentityTransferProtocolOnSourceDevice(bytesOwnedIdentity: ByteArray?)

    @Throws(Exception::class)
    fun initiateOwnedIdentityTransferProtocolOnTargetDevice(deviceName: String?)


    // Post/receive messages
    fun getReturnReceiptNonce(): ByteArray
    fun getReturnReceiptKey(): ByteArray?
    fun deleteReturnReceipt(bytesOwnedIdentity: ByteArray?, serverUid: ByteArray?)
    fun decryptReturnReceipt(
        returnReceiptKey: ByteArray?,
        encryptedPayload: ByteArray?
    ): ObvReturnReceipt?

    fun post(
        messagePayload: ByteArray?,
        extendedMessagePayload: ByteArray?,
        outboundAttachments: Array<ObvOutboundAttachment?>?,
        bytesContactIdentities: MutableList<ByteArray?>?,
        bytesOwnedIdentity: ByteArray?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ): ObvPostMessageOutput

    fun postToSpecificDevices(
        messagePayload: ByteArray?,
        bytesContactIdentities: MutableList<ByteArray?>?,
        bytesContactDeviceUids: MutableList<ByteArray?>?,
        bytesOwnedIdentity: ByteArray?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ): ObvPostMessageOutput

    fun sendReturnReceipt(
        bytesOwnedIdentity: ByteArray?,
        bytesContactIdentity: ByteArray?,
        status: Int,
        returnReceiptNonce: ByteArray?,
        returnReceiptKeyBytes: ByteArray?,
        attachmentNumber: Int?
    )

    fun isOutboxAttachmentSent(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?,
        engineNumber: Int
    ): Boolean

    fun isOutboxMessageSent(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?
    ): Boolean

    fun cancelMessageSending(bytesOwnedIdentity: ByteArray?, engineMessageIdentifier: ByteArray?)

    fun isInboxAttachmentReceived(
        bytesOwnedIdentity: ByteArray?,
        engineMessageIdentifier: ByteArray?,
        attachmentNumber: Int
    ): Boolean

    fun downloadMessages(bytesOwnedIdentity: ByteArray?)
    fun downloadSmallAttachment(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    )

    fun downloadLargeAttachment(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    )

    fun pauseAttachmentDownload(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    )

    fun markAttachmentForDeletion(attachment: ObvAttachment?)
    fun markAttachmentForDeletion(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    )

    fun deleteMessageAndAttachments(bytesOwnedIdentity: ByteArray?, messageIdentifier: ByteArray?)
    fun markMessageForDeletion(bytesOwnedIdentity: ByteArray?, messageIdentifier: ByteArray?)
    fun markMessageAsOnHold(bytesOwnedIdentity: ByteArray?, messageIdentifier: ByteArray?)
    fun cancelAttachmentUpload(
        bytesOwnedIdentity: ByteArray?,
        messageIdentifier: ByteArray?,
        attachmentNumber: Int
    )

    @Throws(Exception::class)
    fun resendAllAttachmentNotifications()
    fun connectWebsocket(
        relyOnWebsocketForNetworkDetection: Boolean,
        os: String?,
        osVersion: String?,
        appBuild: Int,
        appVersion: String?
    )

    fun disconnectWebsocket()
    fun pingWebsocket(bytesOwnedIdentity: ByteArray?)
    fun retryScheduledNetworkTasks()

    @Throws(Exception::class)
    fun getOnHoldMessage(bytesOwnedIdentity: ByteArray?, messageIdentifier: ByteArray?): ObvMessage?

    // Backups
    fun initiateBackup(forExport: Boolean)
    fun generateDeviceBackupSeed(server: String?): String?

    @Throws(Exception::class)
    fun getDeviceBackupSeed(): String?
    fun deleteDeviceBackupSeed(deviceBackupSeed: String?)
    fun backupDeviceAndProfilesNow(): Boolean
    fun deviceBackupNeeded()
    fun profileBackupNeeded(bytesOwnedIdentity: ByteArray?)
    fun fetchDeviceBackup(server: String?, deviceBackupSeed: String?): ObvDeviceBackupForRestore?
    fun fetchProfileBackups(
        bytesIdentity: ByteArray?,
        profileBackupSeed: String?
    ): ObvProfileBackupsForRestore?

    fun deleteProfileBackupSnapshot(
        bytesIdentity: ByteArray?,
        profileBackupSeed: String?,
        threadId: ByteArray?,
        version: Long
    ): Boolean

    @Throws(Exception::class)
    fun downloadProfilePicture(
        bytesIdentity: ByteArray?,
        photoLabel: ByteArray?,
        photoKey: ByteArray?
    ): ByteArray?

    fun restoreProfile(
        snapshot: ObvSyncSnapshot?,
        deviceName: String?,
        serializedKeycloakAuthState: String?
    ): Boolean


    @Throws(Exception::class)
    fun getBackupKeyInformation(): ObvBackupKeyInformation?
    fun stopLegacyBackups()
    fun setAutoBackupEnabled(enabled: Boolean, initiateBackupNowIfNeeded: Boolean)
    fun markBackupExported(backupKeyUid: ByteArray?, version: Int)
    fun markBackupUploaded(backupKeyUid: ByteArray?, version: Int)
    fun discardBackup(backupKeyUid: ByteArray?, version: Int)
    fun validateBackupSeed(
        backupSeedString: String?,
        backupContent: ByteArray?
    ): ObvBackupKeyVerificationOutput?

    fun restoreOwnedIdentitiesFromBackup(
        backupSeed: String?,
        backupContent: ByteArray?,
        deviceDisplayName: String?
    ): Array<ObvIdentity?>?

    fun restoreContactsAndGroupsFromBackup(
        backupSeed: String?,
        backupContent: ByteArray?,
        restoredOwnedIdentities: Array<ObvIdentity?>?
    )

    fun decryptAppDataBackup(backupSeed: String?, backupContent: ByteArray?): String?
    fun appBackupSuccess(bytesBackupKeyUid: ByteArray?, version: Int, appBackupContent: String?)
    fun appBackupFailed(bytesBackupKeyUid: ByteArray?, version: Int)


    fun getTurnCredentials(
        bytesOwnedIdentity: ByteArray?,
        callUuid: UUID?,
        callerUsername: String?,
        recipientUsername: String?
    )

    fun getWellKnownTurnServers(bytesOwnedIdentity: ByteArray?): MutableList<String>?
    fun getWellKnownAltTurnServers(bytesOwnedIdentity: ByteArray?): MutableList<String>?
    fun queryApiKeyStatus(bytesOwnedIdentity: ByteArray?, apiKey: UUID?)
    fun queryApiKeyStatus(server: String?, apiKey: UUID?)
    fun queryFreeTrial(bytesOwnedIdentity: ByteArray?)
    fun startFreeTrial(bytesOwnedIdentity: ByteArray?)
    fun verifyReceipt(bytesOwnedIdentity: ByteArray?, storeToken: String?)
    fun queryServerWellKnown(server: String?)
    fun getOsmStyles(bytesOwnedIdentity: ByteArray?): MutableList<JsonOsmStyle>?
    fun getAddressServerUrl(bytesOwnedIdentity: ByteArray?): String?

    @Throws(Exception::class)
    fun propagateAppSyncAtomToAllOwnedIdentitiesOtherDevicesIfNeeded(obvSyncAtom: ObvSyncAtom)

    @Throws(Exception::class)
    fun propagateAppSyncAtomToOtherDevicesIfNeeded(
        bytesOwnedIdentity: ByteArray?,
        obvSyncAtom: ObvSyncAtom
    )

    // Run once after you upgrade from a version not handling Contact and ContactGroup UserData (profile photos) to a version able to do so
    @Throws(Exception::class)
    fun downloadAllUserData()
    fun setAllOwnedDeviceNames(deviceName: String?)

    @Throws(Exception::class)
    fun vacuumDatabase()
}
