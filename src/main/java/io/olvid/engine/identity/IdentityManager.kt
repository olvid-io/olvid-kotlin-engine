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
package io.olvid.engine.identity

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.crypto.exceptions.DecryptionException
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Constants.SignatureContext
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.GroupMembersChangedCallback
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.SessionCommitListener
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.containers.EncodedOwnedPreKey
import io.olvid.engine.datatypes.containers.Group
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.AdministratorsChain
import io.olvid.engine.datatypes.containers.GroupV2.BlobKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierAndAdminStatus
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierVersionAndKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissionsAndDetails
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializeKnownPermissions
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializePermissions
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.fromStrings
import io.olvid.engine.datatypes.containers.GroupV2.ServerBlob
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.GroupWithDetails
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.KeycloakGroupV2UpdateOutput
import io.olvid.engine.datatypes.containers.OwnedDeviceAndPreKey
import io.olvid.engine.datatypes.containers.PreKey
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo.Companion.createPreKeyChannelInfo
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createGroupTrustOrigin
import io.olvid.engine.datatypes.containers.UidAndPreKey
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.SymmetricKey
import io.olvid.engine.datatypes.notifications.BackupNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonKeycloakRevocation
import io.olvid.engine.engine.types.JsonKeycloakUserDetails
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvContactDeviceCount
import io.olvid.engine.engine.types.ObvContactInfo
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore.ObvDeviceBackupProfile
import io.olvid.engine.engine.types.identities.ObvContactActiveOrInactiveReason
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2DetailsAndPhotos
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2Member
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2PendingMember
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.IdBased
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.identities.ObvOwnedDevice
import io.olvid.engine.engine.types.identities.ObvOwnedDevice.ServerDeviceInfo
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.RestoreFinishedCallback
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate.SerializationContext
import io.olvid.engine.engine.types.sync.ObvProfileBackupSnapshot
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactDevice
import io.olvid.engine.identity.databases.ContactGroup
import io.olvid.engine.identity.databases.ContactGroupDetails
import io.olvid.engine.identity.databases.ContactGroupMembersJoin
import io.olvid.engine.identity.databases.ContactGroupV2
import io.olvid.engine.identity.databases.ContactGroupV2Details
import io.olvid.engine.identity.databases.ContactGroupV2Member
import io.olvid.engine.identity.databases.ContactGroupV2PendingMember
import io.olvid.engine.identity.databases.ContactIdentity
import io.olvid.engine.identity.databases.ContactIdentityDetails
import io.olvid.engine.identity.databases.ContactTrustOrigin
import io.olvid.engine.identity.databases.KeycloakRevokedIdentity
import io.olvid.engine.identity.databases.KeycloakServer
import io.olvid.engine.identity.databases.OwnedDevice
import io.olvid.engine.identity.databases.OwnedIdentity
import io.olvid.engine.identity.databases.OwnedIdentityDetails
import io.olvid.engine.identity.databases.OwnedPreKey
import io.olvid.engine.identity.databases.PendingGroupMember
import io.olvid.engine.identity.databases.ServerUserData
import io.olvid.engine.identity.databases.backups.IdentityManagerDeviceSnapshot
import io.olvid.engine.identity.databases.sync.IdentityManagerSyncSnapshot
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.identity.datatypes.IdentityManagerSessionFactory
import io.olvid.engine.identity.datatypes.KeycloakGroupBlob
import io.olvid.engine.identity.datatypes.KeycloakGroupDeletionData
import io.olvid.engine.identity.datatypes.KeycloakGroupMemberAndPermissions
import io.olvid.engine.identity.datatypes.KeycloakGroupMemberKickedData
import io.olvid.engine.metamanager.BackupDelegate
import io.olvid.engine.metamanager.ChannelDelegate
import io.olvid.engine.metamanager.CreateSessionDelegate
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.IdentityDelegate.DeterministicSeedContext
import io.olvid.engine.metamanager.MetaManager
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.ObvManager
import io.olvid.engine.metamanager.PreKeyEncryptionDelegate
import io.olvid.engine.metamanager.SolveChallengeDelegate
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import io.olvid.engine.storage.EngineFileIo
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.InvalidKeyException
import java.sql.SQLException
import java.util.Arrays
import java.util.EnumSet
import java.util.Map
import java.util.Timer
import java.util.TimerTask
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver


class IdentityManager(
    metaManager: MetaManager,
    private val engineBaseDirectory: String?,
    private val fileIo: EngineFileIo,
    val jsonObjectMapper: ObjectMapper,
    private val prng: PRNGService?
) : IdentityDelegate, SolveChallengeDelegate, EncryptionForIdentityDelegate,
    PreKeyEncryptionDelegate, ObvBackupAndSyncDelegate, IdentityManagerSessionFactory, ObvManager {
    private val backupNeededSessionCommitListener: SessionCommitListener

    private var createSessionDelegate: CreateSessionDelegate? = null
    private var notificationPostingDelegate: NotificationPostingDelegate? = null
    private var protocolStarterDelegate: ProtocolStarterDelegate? = null
    private var channelDelegate: ChannelDelegate? = null
    private val deviceDiscoveryTimer: Timer

    private val currentDeviceUidCache = HashMap<Identity?, UID?>()

    val profileBackupListeners: MutableMap<Identity?, SessionCommitListener?> =
        HashMap<Identity?, SessionCommitListener?>()

    private fun getSessionCommitListenerForProfileBackup(ownedIdentity: Identity): SessionCommitListener {
        var listener = profileBackupListeners.get(ownedIdentity)
        if (listener == null) {
            listener = SessionCommitListener {
                if (notificationPostingDelegate != null) {
                    notificationPostingDelegate?.postNotification(
                        BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED,
                        Map.of<String, Any>(
                            BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED_OWNED_IDENTITY,
                            ownedIdentity
                        )
                    )
                }
            }
            profileBackupListeners.put(ownedIdentity, listener)
        }
        return listener
    }

    @JvmField var deviceBackupListener: SessionCommitListener? = null

    init {
        this.backupNeededSessionCommitListener = SessionCommitListener {
            if (notificationPostingDelegate != null) {
                notificationPostingDelegate?.postNotification(
                    IdentityNotifications.NOTIFICATION_DATABASE_CONTENT_CHANGED,
                    HashMap<String, Any>()
                )
            }
        }
        this.deviceDiscoveryTimer = Timer("Engine-DeviceDiscoveryTimer")

        metaManager.requestDelegate(this, CreateSessionDelegate::class.java)
        metaManager.requestDelegate(this, NotificationPostingDelegate::class.java)
        metaManager.requestDelegate(this, ProtocolStarterDelegate::class.java)
        metaManager.requestDelegate(this, ChannelDelegate::class.java)
        metaManager.registerImplementedDelegates(this)
    }

    private val sessionCommitListenerForDeviceBackup: SessionCommitListener
        get() {
            if (deviceBackupListener == null) {
                deviceBackupListener = SessionCommitListener {
                    if (notificationPostingDelegate != null) {
                        notificationPostingDelegate?.postNotification(
                            BackupNotifications.NOTIFICATION_DEVICE_BACKUP_NEEDED,
                            HashMap<String, Any>()
                        )
                    }
                }
            }
            return deviceBackupListener!!
        }

    override fun initialQueueingPriority(): Int {
        return 20
    }

    override fun initialisationComplete() {
        // - notify if an ownedIdentity is inactive
        // - also compute a profile backup seed for legacy identities without one
        try {
            getSession().use { identityManagerSession ->
                val ownedIdentities: Array<OwnedIdentity> =
                    OwnedIdentity.getAll(identityManagerSession)
                for (ownedIdentity in ownedIdentities) {
                    if (!ownedIdentity.isActive()) {
                        val userInfo = HashMap<String, Any>()
                        userInfo[IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY] = ownedIdentity.ownedIdentity
                        userInfo[IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY] = false
                        identityManagerSession.notificationPostingDelegate?.postNotification(
                            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
                            userInfo
                        )
                    }

                    if (ownedIdentity.getBackupSeed() == null) {
                        val backupSeed = ownedIdentity.getPrivateIdentity()!!
                            .getDeterministicBackupSeedForLegacyIdentity()
                        ownedIdentity.setBackupSeed(backupSeed)
                        identityManagerSession.session.commit()
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // search for all inactive contact identities with some deviceUids and delete them
        try {
            getSession().use { identityManagerSession ->
                val contactIdentities: Array<ContactIdentity?> =
                    ContactIdentity.getAllInactiveWithDevices(identityManagerSession)
                if (contactIdentities.size > 0) {
                    Logger.i("Found " + contactIdentities.size + " inactive contacts with some devices. Cleaning them up!")
                    for (contactIdentity in contactIdentities) {
                        channelDelegate!!.deleteObliviousChannelsWithContact(
                            identityManagerSession.session,
                            contactIdentity!!.getOwnedIdentity(),
                            contactIdentity.getContactIdentity()
                        )
                        removeAllDevicesForContactIdentity(
                            identityManagerSession.session,
                            contactIdentity.getOwnedIdentity(),
                            contactIdentity.getContactIdentity()
                        )
                    }
                    identityManagerSession.session.commit()
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // prune old revocation list records
        try {
            getSession().use { identityManagerSession ->
                for (ownedIdentity in OwnedIdentity.getAll(identityManagerSession)) {
                    if (ownedIdentity.isKeycloakManaged) {
                        val keycloakServer: KeycloakServer? = ownedIdentity.keycloakServer
                        if (keycloakServer != null) {
                            val revocationPruneTime =
                                keycloakServer.latestRevocationListTimestamp - Constants.KEYCLOAK_SIGNATURE_VALIDITY_MILLIS
                            KeycloakRevokedIdentity.prune(
                                identityManagerSession,
                                ownedIdentity.ownedIdentity,
                                ownedIdentity.getKeycloakServerUrl(),
                                revocationPruneTime
                            )
                        }
                    }
                }
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // clean old ownedIdentityDetails
        try {
            getSession().use { identityManagerSession ->
                for (ownedIdentity in OwnedIdentity.getAll(identityManagerSession)) {
                    OwnedIdentityDetails.cleanup(
                        identityManagerSession,
                        ownedIdentity.ownedIdentity,
                        ownedIdentity.publishedDetailsVersion,
                        ownedIdentity.latestDetailsVersion
                    )
                }
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        // clean old contactIdentityDetails
        try {
            getSession().use { identityManagerSession ->
                for (contactIdentity in ContactIdentity.getAllForAllOwnedIdentities(
                    identityManagerSession
                )) {
                    ContactIdentityDetails.cleanup(
                        identityManagerSession,
                        contactIdentity!!.getOwnedIdentity(),
                        contactIdentity.getContactIdentity(),
                        contactIdentity.publishedDetailsVersion,
                        contactIdentity.trustedDetailsVersion
                    )
                }
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        // clean old contactGroupDetails
        try {
            getSession().use { identityManagerSession ->
                for (contactGroup in ContactGroup.getAll(identityManagerSession)) {
                    ContactGroupDetails.cleanup(
                        identityManagerSession,
                        contactGroup!!.getOwnedIdentity(),
                        contactGroup.groupOwnerAndUid,
                        contactGroup.publishedDetailsVersion,
                        contactGroup.latestOrTrustedDetailsVersion
                    )
                }
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
        // clean old ContactGroupV2Details
        try {
            getSession().use { identityManagerSession ->
                for (contactGroupV2 in ContactGroupV2.getAll(identityManagerSession)) {
                    ContactGroupV2Details.cleanup(
                        identityManagerSession,
                        contactGroupV2!!.ownedIdentity,
                        contactGroupV2.groupIdentifier,
                        contactGroupV2.version,
                        contactGroupV2.getTrustedDetailsVersion()
                    )
                }
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // get the set of all owned identity, contact, group profile picture photoUrl and remove all photoUrl not in this set
        try {
            getSession().use { identityManagerSession ->
                val photoDir = identityManagerSession.fileIo.file(
                    engineBaseDirectory,
                    Constants.IDENTITY_PHOTOS_DIRECTORY
                )
                val photoUrlsListed = photoDir.listDirectory()
                if (photoUrlsListed != null) {
                    val photoUrlsToKeep: MutableSet<String> = HashSet()
                    for (photoUrl in OwnedIdentityDetails.getAllPhotoUrl(
                        identityManagerSession
                    )) {
                        photoUrlsToKeep.add(File(photoUrl).name)
                    }
                    for (photoUrl in ContactIdentityDetails.getAllPhotoUrl(
                        identityManagerSession
                    )) {
                        photoUrlsToKeep.add(File(photoUrl).name)
                    }
                    for (photoUrl in ContactGroupDetails.getAllPhotoUrl(
                        identityManagerSession
                    )) {
                        photoUrlsToKeep.add(File(photoUrl).name)
                    }
                    for (photoUrl in ContactGroupV2Details.getAllPhotoUrl(
                        identityManagerSession
                    )) {
                        photoUrlsToKeep.add(File(photoUrl).name)
                    }

                    for (listedPhotoUrl in photoUrlsListed.managedFileList) {
                        if (!photoUrlsToKeep.contains(listedPhotoUrl.plainNameFile.name)) {
                            try {
                                listedPhotoUrl.delete()
                            } catch (e: Exception) {
                                Logger.x(e)
                            }
                        }
                    }
                    // SecureFileIo only: files still being written are not yet listed as managed
                    // (their header is incomplete). Give them a moment, then clean up any now-readable
                    // orphans. In plain mode fileList is always empty, so this block is skipped and
                    // behavior matches the legacy raw-file cleanup.
                    if (photoUrlsListed.fileList.isNotEmpty()) {
                        try {
                            Thread.sleep(5000)
                        } catch (_: InterruptedException) {
                            // do nothing
                        }
                        for (file in photoUrlsListed.fileList) {
                            val orphanCandidate = identityManagerSession.fileIo.file(file.absolutePath)
                            if (orphanCandidate.canRead() &&
                                !photoUrlsToKeep.contains(orphanCandidate.plainNameFile.name)
                            ) {
                                orphanCandidate.delete()
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // check if device capabilities changed for any current owned device
        try {
            getSession().use { identityManagerSession ->
                for (ownedIdentity in OwnedIdentity.getAll(identityManagerSession)) {
                    val ownedDevice: OwnedDevice? =
                        OwnedDevice.getCurrentDeviceOfOwnedIdentity(
                            identityManagerSession,
                            ownedIdentity.ownedIdentity
                        )

                    val currentCapabilities = HashSet<ObvCapability>(ObvCapability.currentCapabilities)
                    val publishedCapabilitiesList = ownedDevice!!.deviceCapabilities
                    val publishedCapabilities =
                        if (publishedCapabilitiesList == null) null else HashSet<ObvCapability>(
                            publishedCapabilitiesList
                        )

                    if (currentCapabilities != publishedCapabilities) {
                        protocolStarterDelegate!!.updateCurrentDeviceCapabilitiesForOwnedIdentity(
                            identityManagerSession.session,
                            ownedIdentity.ownedIdentity,
                            ObvCapability.currentCapabilities
                        )
                    }
                }
                // commit the session, in case a protocol was indeed started
                identityManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        // re-notify the app for all Keycloak groups shared settings to make sure it remains synchronized
        try {
            getSession().use { identityManagerSession ->
                for (contactGroupV2 in ContactGroupV2.getAllKeycloak(
                    identityManagerSession
                )) {
                    contactGroupV2?.serializedSharedSettings?.let { serializedSharedSettings ->
                        val userInfo = HashMap<String, Any>()
                        userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_OWNED_IDENTITY_KEY] =
                            contactGroupV2.ownedIdentity
                        userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_GROUP_IDENTIFIER_KEY] =
                            contactGroupV2.groupIdentifier
                        userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SERIALIZED_SHARED_SETTINGS_KEY] =
                            serializedSharedSettings
                        userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY] =
                            contactGroupV2.lastModificationTimestamp
                        notificationPostingDelegate?.postNotification(
                            IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS,
                            userInfo
                        )
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }

        deviceDiscoveryTimer.schedule(object : TimerTask() {
            override fun run() {
                // do an OwnedDeviceDiscoveryProtocol at every startup
                try {
                    getSession().use { identityManagerSession ->
                        for (ownedIdentity in OwnedIdentity.getAll(identityManagerSession)) {
                            if (ownedIdentity.isActive()) {
                                protocolStarterDelegate!!.startOwnedDeviceDiscoveryProtocolWithinTransaction(
                                    identityManagerSession.session,
                                    ownedIdentity.ownedIdentity
                                )
                            }
                        }
                        identityManagerSession.session.commit()
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }

                // search for all contact identities with no deviceUids and run a deviceDiscovery
                try {
                    getSession().use { identityManagerSession ->
                        val contactIdentities: Array<ContactIdentity?> =
                            ContactIdentity.getAllActiveWithoutDevices(
                                identityManagerSession,
                                System.currentTimeMillis() - Constants.NO_DEVICE_CONTACT_DEVICE_DISCOVERY_INTERVAL
                            )
                        if (contactIdentities.size > 0) {
                            Logger.i("Found " + contactIdentities.size + " contacts with no device. Starting corresponding deviceDiscoveryProtocols.")
                            for (contactIdentity in contactIdentities) {
                                // skip device discovery for contacts if the current device has not been registered yet (e.g. after a transfer)
                                val currentDevice = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
                                    identityManagerSession,
                                    contactIdentity!!.getOwnedIdentity()
                                )
                                if (currentDevice == null || currentDevice.lastRegistrationTimestamp == null) {
                                    Logger.i("Skip discovery because device is not registered yet")
                                    continue
                                }
                                protocolStarterDelegate!!.startDeviceDiscoveryProtocolWithinTransaction(
                                    identityManagerSession.session,
                                    contactIdentity.getOwnedIdentity(),
                                    contactIdentity.getContactIdentity()
                                )
                                contactIdentity.lastContactDeviceDiscoveryTimestamp = System.currentTimeMillis()
                            }
                            identityManagerSession.session.commit()
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }

                // search all active contact identities with devices without a recent device discovery
                try {
                    getSession().use { identityManagerSession ->
                        val contactIdentities: Array<ContactIdentity?> =
                            ContactIdentity.getAllActiveWithDevicesAndOldDiscovery(
                                identityManagerSession,
                                System.currentTimeMillis() - Constants.CONTACT_DEVICE_DISCOVERY_INTERVAL
                            )
                        if (contactIdentities.size > 0) {
                            Logger.i("Found " + contactIdentities.size + " contacts with outdated device discovery. Starting corresponding deviceDiscoveryProtocols.")
                            for (contactIdentity in contactIdentities) {
                                // skip device discovery for contacts if the current device has not been registered yet (e.g. after a transfer)
                                val currentDevice = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
                                    identityManagerSession,
                                    contactIdentity!!.getOwnedIdentity()
                                )
                                if (currentDevice == null || currentDevice.lastRegistrationTimestamp == null) {
                                    Logger.i("Skip discovery because device is not registered yet")
                                    continue
                                }
                                protocolStarterDelegate!!.startDeviceDiscoveryProtocolWithinTransaction(
                                    identityManagerSession.session,
                                    contactIdentity.getOwnedIdentity(),
                                    contactIdentity.getContactIdentity()
                                )
                                contactIdentity.lastContactDeviceDiscoveryTimestamp = System.currentTimeMillis()
                            }
                            identityManagerSession.session.commit()
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        }, 0, Constants.OWNED_DEVICE_DISCOVERY_INTERVAL)
    }

    @Suppress("unused")
    fun setDelegate(createSessionDelegate: CreateSessionDelegate) {
        this.createSessionDelegate = createSessionDelegate

        try {
            getSession().use { identityManagerSession ->
                OwnedIdentityDetails.createTable(identityManagerSession.session)
                KeycloakServer.createTable(identityManagerSession.session)
                KeycloakRevokedIdentity.createTable(identityManagerSession.session)
                OwnedIdentity.createTable(identityManagerSession.session)
                OwnedDevice.createTable(identityManagerSession.session)
                OwnedPreKey.createTable(identityManagerSession.session)
                ContactIdentityDetails.createTable(identityManagerSession.session)
                ContactIdentity.createTable(identityManagerSession.session)
                ContactTrustOrigin.createTable(identityManagerSession.session)
                ContactDevice.createTable(identityManagerSession.session)
                ContactGroupDetails.createTable(identityManagerSession.session)
                ContactGroup.createTable(identityManagerSession.session)
                ContactGroupMembersJoin.createTable(identityManagerSession.session)
                PendingGroupMember.createTable(identityManagerSession.session)
                ServerUserData.createTable(identityManagerSession.session)
                ContactGroupV2Details.createTable(identityManagerSession.session)
                ContactGroupV2.createTable(identityManagerSession.session)
                ContactGroupV2Member.createTable(identityManagerSession.session)
                ContactGroupV2PendingMember.createTable(identityManagerSession.session)
                identityManagerSession.session.commit()
            }
        } catch (e: SQLException) {
            Logger.x(e)
            throw RuntimeException("Unable to create identity databases")
        }
    }

    @Suppress("unused")
    fun setDelegate(notificationPostingDelegate: NotificationPostingDelegate?) {
        this.notificationPostingDelegate = notificationPostingDelegate
    }

    @Suppress("unused")
    fun setDelegate(protocolStarterDelegate: ProtocolStarterDelegate) {
        this.protocolStarterDelegate = protocolStarterDelegate
    }

    @Suppress("unused")
    fun setDelegate(channelDelegate: ChannelDelegate) {
        this.channelDelegate = channelDelegate
    }

    @Throws(SQLException::class)
    override fun getSession(): IdentityManagerSession {
        if (createSessionDelegate == null) {
            throw SQLException("No CreateSessionDelegate was set in IdentityManager.")
        }
        return IdentityManagerSession(
            createSessionDelegate!!.session,
            notificationPostingDelegate,
            this,
            engineBaseDirectory,
            fileIo,
            jsonObjectMapper,
            prng
        )
    }

    private fun wrapSession(session: Session): IdentityManagerSession {
        return IdentityManagerSession(
            session,
            notificationPostingDelegate,
            this,
            engineBaseDirectory,
            fileIo,
            jsonObjectMapper,
            prng
        )
    }


    // region Implement SolveChallengeDelegate
    @Throws(Exception::class)
    override fun solveChallenge(
        challenge: ByteArray,
        identity: Identity?,
        prng: PRNGService
    ): ByteArray? {
        try {
            getSession().use { identityManagerSession ->
                val ownedIdentity: OwnedIdentity =
                    OwnedIdentity.get(identityManagerSession, identity) ?: throw Exception("Unknown owned identity")
                val privateIdentity = ownedIdentity.getPrivateIdentity()
                val serverAuth =
                    Suite.getServerAuthentication(privateIdentity!!.getServerAuthenticationPublicKey())!!
                return serverAuth.solveChallenge(
                    challenge,
                    privateIdentity.serverAuthenticationPrivateKey,
                    privateIdentity.getServerAuthenticationPublicKey(),
                    prng
                )
            }
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
    }


    // endregion
    // region Implement IdentityDelegate
    // region OwnedIdentity
    @Throws(SQLException::class)
    override fun isOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        excludeMarkedForDeletionIdentities: Boolean
    ): Boolean {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        return ownedIdentityObject != null && (!excludeMarkedForDeletionIdentities || !ownedIdentityObject.isMarkedForDeletion)
    }

    @Throws(SQLException::class)
    override fun isActiveOwnedIdentity(session: Session, ownedIdentity: Identity?): Boolean {
        return OwnedIdentity.isActive(wrapSession(session), ownedIdentity)
    }

    @Throws(SQLException::class)
    override fun generateOwnedIdentity(
        session: Session,
        server: String?,
        jsonIdentityDetails: JsonIdentityDetails?,
        keycloakState: ObvKeycloakState?,
        deviceDisplayName: String?,
        prng: PRNGService?
    ): Identity? {
        if (!session.isInTransaction) {
            session.startTransaction()
        }
        val ownedIdentity: OwnedIdentity? = OwnedIdentity.create(
            wrapSession(session),
            server!!,
            null,
            null,
            jsonIdentityDetails,
            deviceDisplayName,
            prng!!
        )
        if (ownedIdentity == null) {
            return null
        }

        try {
            protocolStarterDelegate!!.updateCurrentDeviceCapabilitiesForOwnedIdentity(
                session,
                ownedIdentity.ownedIdentity,
                ObvCapability.currentCapabilities
            )
        } catch (e: Exception) {
            Logger.w("Failed to update generated identity capabilities")
            Logger.x(e)
        }

        if (keycloakState != null) {
            var clientId: String? = null
            var clientSecret: String? = null
            var supportsIdBasedAuth = false
            for (authType in keycloakState.supportedAuthenticationMethods) {
                if (authType is OpenIdConnect) {
                    clientId = authType.clientId
                    clientSecret = authType.clientSecret
                } else if (authType is IdBased) {
                    supportsIdBasedAuth = true
                }
            }
            val keycloakServer: KeycloakServer? = KeycloakServer.create(
                wrapSession(session),
                keycloakState.keycloakServer,
                ownedIdentity.ownedIdentity,
                keycloakState.jwks!!.toJson(),
                if (keycloakState.signatureKey == null) null else keycloakState.signatureKey.toJson(),
                clientId,
                clientSecret,
                keycloakState.transferRestricted,
                supportsIdBasedAuth
            )
            if (keycloakServer == null) {
                return null
            }
            ownedIdentity.setKeycloakServerUrl(keycloakServer.serverUrl)
            KeycloakServer.saveAuthState(
                wrapSession(session),
                keycloakState.keycloakServer,
                ownedIdentity.ownedIdentity,
                keycloakState.serializedAuthState
            )
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity.ownedIdentity))
        return ownedIdentity.ownedIdentity
    }

    @Throws(SQLException::class)
    override fun deleteOwnedIdentity(session: Session, ownedIdentity: Identity?) {
        currentDeviceUidCache.remove(ownedIdentity)
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            // delete all contact groups (and associated details)
            //  - this cascade deletes ContactGroupMembersJoin
            //  - this cascade deletes PendingGroupMember
            val contactGroups: Array<ContactGroup> =
                ContactGroup.getAllForIdentity(wrapSession(session), ownedIdentity!!)
            for (contactGroup in contactGroups) {
                contactGroup.delete()
            }

            // delete all contact groupsV2 (and associated details)
            //  - this cascade deletes ContactGroupV2Members
            //  - this cascade deletes ContactGroupV2PendingMember
            val contactGroupsV2: MutableList<ContactGroupV2?> =
                ContactGroupV2.getAllForIdentity(wrapSession(session), ownedIdentity)
            for (contactGroupV2 in contactGroupsV2) {
                contactGroupV2!!.delete()
            }

            // delete all contacts (and associated details)
            //  - this cascade deletes ContactDevice
            //  - this cascade deletes ContactTrustOrigin
            val contactIdentities: Array<ContactIdentity> =
                ContactIdentity.getAll(wrapSession(session), ownedIdentity)
            for (contactIdentity in contactIdentities) {
                contactIdentity.delete()
            }

            // delete server user data
            ServerUserData.deleteAllForOwnedIdentity(wrapSession(session), ownedIdentity)

            // delete the ownedIdentity (and associated details)
            //  - this cascade deletes OwnedDevice
            ownedIdentityObject.delete()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
        }
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentities(session: Session): Array<Identity> {
        val ownedIdentities: Array<OwnedIdentity> =
            OwnedIdentity.getAll(wrapSession(session))

        return ownedIdentities.map { it.ownedIdentity }.toTypedArray()
    }

    @Throws(Exception::class)
    override fun updateLatestIdentityDetails(
        session: Session,
        ownedIdentity: Identity?,
        jsonIdentityDetails: JsonIdentityDetails?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            ownedIdentityObject.setLatestDetails(jsonIdentityDetails)
            session.addSessionCommitListener(backupNeededSessionCommitListener)
        }
    }

    @Throws(Exception::class)
    override fun updateOwnedIdentityPhoto(
        session: Session,
        ownedIdentity: Identity?,
        absolutePhotoUrl: String?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            ownedIdentityObject.setPhoto(absolutePhotoUrl)
        }
    }

    @Throws(Exception::class)
    override fun setOwnedDetailsDownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        version: Int,
        decryptedPhoto: ByteArray?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        ownedIdentityObject?.setDetailsDownloadedPhotoUrl(version, decryptedPhoto!!)
    }


    @Throws(SQLException::class)
    override fun setOwnedIdentityDetailsServerLabelAndKey(
        session: Session,
        ownedIdentity: Identity?,
        version: Int,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            ownedIdentityObject.setPhotoLabelAndKey(version, photoServerLabel!!, photoServerKey)
            if (ServerUserData.createForOwnedIdentityDetails(
                    wrapSession(session),
                    ownedIdentity,
                    photoServerLabel
                ) == null
            ) {
                throw SQLException()
            }
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        }
    }

    @Throws(SQLException::class)
    override fun createOwnedIdentityServerUserData(
        session: Session,
        ownedIdentity: Identity?,
        photoServerLabel: UID?
    ) {
        if (ServerUserData.createForOwnedIdentityDetails(
                wrapSession(session),
                ownedIdentity,
                photoServerLabel
            ) == null
        ) {
            throw SQLException()
        }
    }

    @Throws(SQLException::class)
    override fun publishLatestIdentityDetails(session: Session, ownedIdentity: Identity?): Int {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
            return ownedIdentityObject.publishLatestDetails()
        }
        return -1
    }

    @Throws(SQLException::class)
    override fun discardLatestIdentityDetails(session: Session, ownedIdentity: Identity?) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            ownedIdentityObject.discardLatestDetails()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
        }
    }

    @Throws(SQLException::class)
    override fun setOwnedIdentityDetailsFromOtherDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
    ): Boolean {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
            return ownedIdentityObject.setOwnedIdentityDetailsFromOtherDevice(
                ownDetailsWithVersionAndPhoto!!
            )
        }
        return false
    }

    override fun getSerializedPublishedDetailsOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): String? {
        return OwnedIdentity.getSerializedPublishedDetails(
            wrapSession(session),
            ownedIdentity!!
        )
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityPublishedDetails(
        session: Session,
        ownedIdentity: Identity?
    ): JsonIdentityDetailsWithVersionAndPhoto? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.publishedDetails!!
                .jsonIdentityDetailsWithVersionAndPhoto
        }
        return null
    }

    @Throws(SQLException::class)
    override fun isOwnedIdentityKeycloakManaged(
        session: Session,
        ownedIdentity: Identity?
    ): Boolean {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.isKeycloakManaged
        }
        return false
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentitiesWithKeycloakPushTopic(
        session: Session,
        pushTopic: String?
    ): MutableCollection<ObvIdentity> {
        val keycloakServers: MutableList<KeycloakServer?> =
            KeycloakServer.getAllWithPushTopic(wrapSession(session), pushTopic)
        val keycloakGroups: MutableList<ContactGroupV2?> =
            ContactGroupV2.getAllWithPushTopic(wrapSession(session), pushTopic)
        val ownedIdentities = HashSet<ObvIdentity>()
        for (keycloakServer in keycloakServers) {
            ownedIdentities.add(ObvIdentity(session, this, keycloakServer!!.getOwnedIdentity()))
        }
        for (keycloakGroup in keycloakGroups) {
            ownedIdentities.add(ObvIdentity(session, this, keycloakGroup!!.ownedIdentity))
        }
        return ownedIdentities
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityKeycloakState(
        session: Session,
        ownedIdentity: Identity?
    ): ObvKeycloakState? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.keycloakState
        }
        return null
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityKeycloakSignatureKey(
        session: Session,
        ownedIdentity: Identity?
    ): JsonWebKey? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.keycloakSignatureKey
        }
        return null
    }

    @Throws(SQLException::class)
    override fun setOwnedIdentityKeycloakSignatureKey(
        session: Session,
        ownedIdentity: Identity?,
        signatureKey: JsonWebKey?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.setSignatureKey(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                signatureKey
            )
            if (signatureKey == null) {
                ContactGroupV2.deleteAllKeycloakGroupsForOwnedIdentity(
                    wrapSession(session),
                    ownedIdentity
                )
            }
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }

    @Throws(SQLException::class)
    override fun setOwnedIdentityKeycloakSupportsIdBasedAuth(
        session: Session,
        ownedIdentity: Identity?,
        supportsIdBasedAuth: Boolean
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.setSupportsIdBasedAuth(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                supportsIdBasedAuth
            )
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }

    @Throws(SQLException::class)
    override fun setKeycloakLatestRevocationListTimestamp(
        session: Session,
        ownedIdentity: Identity?,
        latestRevocationListTimestamp: Long
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.setLatestRevocationListTimestamp(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                latestRevocationListTimestamp
            )
            val revocationPruneTime =
                latestRevocationListTimestamp - Constants.KEYCLOAK_SIGNATURE_VALIDITY_MILLIS
            KeycloakRevokedIdentity.prune(
                wrapSession(session),
                ownedIdentity,
                ownedIdentityObject.getKeycloakServerUrl(),
                revocationPruneTime
            )
        }
    }

    override fun unCertifyExpiredSignedContactDetails(
        session: Session,
        ownedIdentity: Identity?,
        latestRevocationListTimestamp: Long
    ) {
        for (contactIdentity in ContactIdentity.getAllCertifiedByKeycloak(
            wrapSession(
                session
            ), ownedIdentity!!
        )) {
            try {
                val noVerificationConsumer = JwtConsumerBuilder()
                    .setSkipSignatureVerification()
                    .setSkipAllValidators()
                    .build()
                val publishedDetails: ContactIdentityDetails? = contactIdentity!!.publishedDetails
                val claims = noVerificationConsumer.processToClaims(
                    publishedDetails!!.jsonIdentityDetails!!.getSignedUserDetails()
                )
                val jsonKeycloakUserDetails = jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                    claims.getRawJson(),
                    JsonKeycloakUserDetails::class.java
                )

                if (jsonKeycloakUserDetails.getTimestamp() != null && jsonKeycloakUserDetails.getTimestamp()!! < latestRevocationListTimestamp - Constants.KEYCLOAK_SIGNATURE_VALIDITY_MILLIS) {
                    // signature no longer valid --> remove certification
                    contactIdentity.setCertifiedByOwnKeycloak(
                        false,
                        publishedDetails.getSerializedJsonDetails()
                    )
                }
            } catch (_: Exception) { }
        }
    }

    @Throws(SQLException::class)
    override fun getKeycloakPushTopics(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<String> {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject == null || !ownedIdentityObject.isKeycloakManaged) {
            return ArrayList(0)
        }
        val pushTopics: MutableList<String> = ArrayList()

        val keycloakServer: KeycloakServer? = KeycloakServer.get(
            wrapSession(session),
            ownedIdentityObject.getKeycloakServerUrl(),
            ownedIdentity!!
        )
        if (keycloakServer != null) {
            pushTopics.addAll(keycloakServer.pushTopics)
        }
        val groupPushTopics: MutableList<String>? =
            ContactGroupV2.getAllKeycloakPushTopics(wrapSession(session), ownedIdentity)
        if (groupPushTopics != null) {
            pushTopics.addAll(groupPushTopics)
        }

        return pushTopics
    }

    @Throws(Exception::class)
    override fun verifyAndAddRevocationList(
        session: Session,
        ownedIdentity: Identity?,
        signedRevocations: MutableList<String?>?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            val keycloakServer = ownedIdentityObject.keycloakServer
            if (keycloakServer != null) {
                val jwksResolver: JwksVerificationKeyResolver
                val signatureKey = keycloakServer.signatureKey
                if (signatureKey != null) {
                    jwksResolver =
                        JwksVerificationKeyResolver(mutableListOf<JsonWebKey?>(signatureKey))
                } else {
                    val jwks = keycloakServer.jwks
                    jwksResolver = JwksVerificationKeyResolver(jwks.getJsonWebKeys())
                }
                val jwtConsumer = JwtConsumerBuilder()
                    .setExpectedAudience(false)
                    .setVerificationKeyResolver(jwksResolver)
                    .build()

                for (signedRevocation in signedRevocations!!) {
                    try {
                        val context = jwtConsumer.process(signedRevocation)
                        if (context.getJwtClaims() == null) {
                            // signature is invalid, ignore this entry and proceed with the next one
                            continue
                        }

                        val jsonKeycloakRevocation =
                            jsonObjectMapper.readValue<JsonKeycloakRevocation?>(
                                context.getJwtClaims().getRawJson(),
                                JsonKeycloakRevocation::class.java
                            )
                        if (jsonKeycloakRevocation == null || jsonKeycloakRevocation.getBytesRevokedIdentity() == null || jsonKeycloakRevocation.getRevocationTimestamp() == 0L) {
                            // signature content is invalid, ignore this entry and proceed with the next one
                            continue
                        }
                        val revokedIdentity =
                            Identity.of(jsonKeycloakRevocation.getBytesRevokedIdentity()!!)
                        val keycloakRevokedIdentities: MutableList<KeycloakRevokedIdentity?>? =
                            KeycloakRevokedIdentity.get(
                                wrapSession(session),
                                ownedIdentity,
                                revokedIdentity
                            )
                        if (keycloakRevokedIdentities != null) {
                            var found = false
                            for (keycloakRevokedIdentity in keycloakRevokedIdentities) {
                                if (keycloakServer.serverUrl == keycloakRevokedIdentity!!.keycloakServerUrl
                                    && jsonKeycloakRevocation.revocationType == keycloakRevokedIdentity.revocationType && jsonKeycloakRevocation.revocationTimestamp == keycloakRevokedIdentity.revocationTimestamp
                                ) {
                                    // this revocation was already inserted
                                    found = true
                                    break
                                }
                            }
                            if (found) {
                                // revocation already in database -> ignore this entry and proceed with the next one
                                continue
                            }
                        }

                        // this revocation is valid and not present in database
                        KeycloakRevokedIdentity.create(
                            wrapSession(session),
                            ownedIdentity,
                            keycloakServer.serverUrl,
                            revokedIdentity,
                            jsonKeycloakRevocation.getRevocationType(),
                            jsonKeycloakRevocation.getRevocationTimestamp()
                        )

                        // now, check if the revokedIdentity is part of our contacts
                        val contactIdentity: ContactIdentity? = ContactIdentity.get(
                            wrapSession(session),
                            ownedIdentity,
                            revokedIdentity
                        )
                        if (contactIdentity != null) {
                            when (jsonKeycloakRevocation.getRevocationType()) {
                                KeycloakRevokedIdentity.TYPE_LEFT_COMPANY -> if (contactIdentity.isCertifiedByOwnKeycloak) {
                                    val noVerificationConsumer = JwtConsumerBuilder()
                                        .setSkipSignatureVerification()
                                        .setSkipAllValidators()
                                        .build()
                                    val publishedDetails = contactIdentity.publishedDetails
                                    val claims = noVerificationConsumer.processToClaims(
                                        publishedDetails!!.jsonIdentityDetails!!
                                            .getSignedUserDetails()
                                    )
                                    val jsonKeycloakUserDetails =
                                        jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                                            claims.getRawJson(),
                                            JsonKeycloakUserDetails::class.java
                                        )

                                    if (jsonKeycloakUserDetails.getTimestamp() == null || jsonKeycloakRevocation.getRevocationTimestamp() > jsonKeycloakUserDetails.getTimestamp()!!) {
                                        // the user left the company after the signature of his details --> unmark as certified
                                        contactIdentity.setCertifiedByOwnKeycloak(
                                            false,
                                            publishedDetails.getSerializedJsonDetails()
                                        )
                                    }
                                }

                                KeycloakRevokedIdentity.TYPE_COMPROMISED -> {
                                    // user key is compromised: mark the contact as revoked and delete all devices/channels from this contact
                                    if (!contactIdentity.isForcefullyTrustedByUser()) {
                                        channelDelegate!!.deleteObliviousChannelsWithContact(
                                            session,
                                            ownedIdentity,
                                            revokedIdentity
                                        )
                                        removeAllDevicesForContactIdentity(
                                            session,
                                            ownedIdentity,
                                            revokedIdentity
                                        )
                                    }
                                    val publishedDetails = contactIdentity.publishedDetails
                                    contactIdentity.setCertifiedByOwnKeycloak(
                                        false,
                                        publishedDetails!!.getSerializedJsonDetails()
                                    )
                                    contactIdentity.setRevokedAsCompromised(true)
                                }

                                else -> {
                                    if (!contactIdentity.isForcefullyTrustedByUser()) {
                                        channelDelegate!!.deleteObliviousChannelsWithContact(
                                            session,
                                            ownedIdentity,
                                            revokedIdentity
                                        )
                                        removeAllDevicesForContactIdentity(
                                            session,
                                            ownedIdentity,
                                            revokedIdentity
                                        )
                                    }
                                    val publishedDetails = contactIdentity.publishedDetails
                                    contactIdentity.setCertifiedByOwnKeycloak(
                                        false,
                                        publishedDetails!!.getSerializedJsonDetails()
                                    )
                                    contactIdentity.setRevokedAsCompromised(true)
                                }
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    override fun verifyKeycloakIdentitySignature(
        session: Session,
        ownedIdentity: Identity?,
        signature: String?
    ): JsonKeycloakUserDetails? {
        try {
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(wrapSession(session), ownedIdentity)
            if (ownedIdentityObject == null || !ownedIdentityObject.isKeycloakManaged) {
                return null
            }
            val keycloakServer = ownedIdentityObject.keycloakServer

            val jwksResolver: JwksVerificationKeyResolver
            val signatureKey = keycloakServer!!.signatureKey
            if (signatureKey != null) {
                jwksResolver = JwksVerificationKeyResolver(mutableListOf<JsonWebKey?>(signatureKey))
            } else {
                val jwks = keycloakServer.jwks
                jwksResolver = JwksVerificationKeyResolver(jwks.jsonWebKeys)
            }
            val jwtConsumer = JwtConsumerBuilder()
                .setExpectedAudience(false)
                .setVerificationKeyResolver(jwksResolver)
                .build()


            val context = jwtConsumer.process(signature)
            if (context.getJwtClaims() != null) {
                // signature is valid, now check for a revocation
                val jsonKeycloakUserDetails = jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                    context.getJwtClaims().getRawJson(), JsonKeycloakUserDetails::class.java
                )

                if (jsonKeycloakUserDetails.getIdentity() != null) {
                    try {
                        val identityToVerify = Identity.of(jsonKeycloakUserDetails.getIdentity()!!)

                        val keycloakRevokedIdentities: MutableList<KeycloakRevokedIdentity?>? =
                            KeycloakRevokedIdentity.get(
                                wrapSession(session),
                                ownedIdentity,
                                identityToVerify
                            )
                        if (keycloakRevokedIdentities != null) {
                            // there was a revocation!
                            for (keycloakRevokedIdentity in keycloakRevokedIdentities) {
                                when (keycloakRevokedIdentity!!.revocationType) {
                                    KeycloakRevokedIdentity.TYPE_LEFT_COMPANY -> if (jsonKeycloakUserDetails.getTimestamp() == null || keycloakRevokedIdentity.revocationTimestamp > jsonKeycloakUserDetails.getTimestamp()!!) {
                                        // the user left the company after the signature of his details --> reject
                                        return null
                                    }

                                    KeycloakRevokedIdentity.TYPE_COMPROMISED -> return null
                                    else -> return null
                                }
                            }
                        }
                    } catch (_: DecodingException) {
                    }
                }

                if (jsonKeycloakUserDetails.getTimestamp() != null && jsonKeycloakUserDetails.getTimestamp()!! < keycloakServer.latestRevocationListTimestamp - Constants.KEYCLOAK_SIGNATURE_VALIDITY_MILLIS) {
                    // this signature is too old --> reject
                    return null
                }

                return jsonKeycloakUserDetails
            }
        } catch (_: Exception) {
        }
        return null
    }


    override fun verifyKeycloakSignature(
        session: Session,
        ownedIdentity: Identity?,
        signature: String?
    ): String? {
        try {
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(wrapSession(session), ownedIdentity)
            if (ownedIdentityObject == null || !ownedIdentityObject.isKeycloakManaged) {
                return null
            }
            val keycloakServer = ownedIdentityObject.keycloakServer

            val jwksResolver: JwksVerificationKeyResolver
            val signatureKey = keycloakServer!!.signatureKey
            if (signatureKey != null) {
                jwksResolver = JwksVerificationKeyResolver(mutableListOf<JsonWebKey?>(signatureKey))
            } else {
                val jwks = keycloakServer.jwks
                jwksResolver = JwksVerificationKeyResolver(jwks.getJsonWebKeys())
            }
            val jwtConsumer = JwtConsumerBuilder()
                .setExpectedAudience(false)
                .setVerificationKeyResolver(jwksResolver)
                .build()

            val context = jwtConsumer.process(signature)
            if (context.getJwtClaims() != null) {
                // signature is valid
                return context.getJwtClaims().getRawJson()
            }
        } catch (_: Exception) {
        }
        return null
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityKeycloakServerUrl(
        session: Session,
        ownedIdentity: Identity?
    ): String? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.getKeycloakServerUrl()
        }
        return null
    }

    @Throws(SQLException::class)
    override fun saveKeycloakAuthState(
        session: Session,
        ownedIdentity: Identity?,
        serializedAuthState: String?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.saveAuthState(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                serializedAuthState
            )
        }
    }

    @Throws(SQLException::class)
    override fun saveKeycloakJwks(
        session: Session,
        ownedIdentity: Identity?,
        serializedJwks: String?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.saveJwks(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                serializedJwks
            )
        }
    }

    @Throws(SQLException::class)
    override fun saveKeycloakApiKey(session: Session, ownedIdentity: Identity?, apiKey: String?) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.saveApiKey(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                apiKey
            )
        }
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityKeycloakUserId(
        session: Session,
        ownedIdentity: Identity?
    ): String? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.keycloakUserId
        }
        return null
    }

    @Throws(SQLException::class)
    override fun setOwnedIdentityKeycloakUserId(
        session: Session,
        ownedIdentity: Identity?,
        userId: String?
    ) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && ownedIdentityObject.isKeycloakManaged) {
            KeycloakServer.setKeycloakUserId(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity!!,
                userId
            )
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }

    @Throws(Exception::class)
    override fun bindOwnedIdentityToKeycloak(
        session: Session,
        ownedIdentity: Identity?,
        keycloakUserId: String?,
        keycloakState: ObvKeycloakState?
    ) {
        if (ownedIdentity == null || keycloakState == null || keycloakUserId == null) {
            Logger.e("Error in bindOwnedIdentityToKeycloak: bad inputs --> aborting")
            throw Exception()
        }
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject == null) {
            Logger.e("Owned identity not found in bindOwnedIdentityToKeycloak")
            throw Exception()
        }
        var clientId: String? = null
        var clientSecret: String? = null
        var supportsIdBasedAuth = false
        for (authType in keycloakState.supportedAuthenticationMethods) {
            if (authType is OpenIdConnect) {
                clientId = authType.clientId
                clientSecret = authType.clientSecret
            } else if (authType is IdBased) {
                supportsIdBasedAuth = true
            }
        }

        if (ownedIdentityObject.isKeycloakManaged) {
            // identity already managed --> unbind from previous keycloak (if it is different)
            val keycloakServer: KeycloakServer? = KeycloakServer.get(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity
            )
            if (keycloakServer != null) {
                if (keycloakServer.serverUrl == keycloakState.keycloakServer
                    && keycloakServer.clientId == clientId
                    && keycloakServer.clientSecret == clientSecret
                ) {
                    // the content of the keycloak QR code is the same, so no need to unbind and rebind
                    return
                }

                ownedIdentityObject.setKeycloakServerUrl(null)
                keycloakServer.delete()
            } else {
                // this case should never happen, but just in case, we set the keycloakServerUrl to null
                ownedIdentityObject.setKeycloakServerUrl(null)
            }
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))

        val keycloakServer: KeycloakServer? = KeycloakServer.create(
            wrapSession(session),
            keycloakState.keycloakServer,
            ownedIdentity,
            keycloakState.jwks!!.toJson(),
            if (keycloakState.signatureKey == null) null else keycloakState.signatureKey.toJson(),
            clientId,
            clientSecret,
            keycloakState.transferRestricted,
            supportsIdBasedAuth
        )
        if (keycloakServer == null) {
            Logger.e("Unable to create new KeycloakServer db entry")
            throw Exception()
        }
        ownedIdentityObject.setKeycloakServerUrl(keycloakServer.serverUrl)
        keycloakServer.setKeycloakUserId(keycloakUserId)
        KeycloakServer.saveAuthState(
            wrapSession(session),
            keycloakState.keycloakServer,
            ownedIdentity,
            keycloakState.serializedAuthState
        )
    }


    @Throws(Exception::class)
    override fun unbindOwnedIdentityFromKeycloak(session: Session, ownedIdentity: Identity?): Int {
        if (ownedIdentity == null) {
            Logger.e("Error in unbindOwnedIdentityToKeycloak: bad inputs --> aborting")
            throw Exception()
        }
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject == null) {
            Logger.e("Owned identity not found in unbindOwnedIdentityFromKeycloak")
            throw Exception()
        }
        // only do something if the identity is indeed managed
        if (ownedIdentityObject.isKeycloakManaged) { /**////// */
            // remove the keycloak server
            val keycloakServer: KeycloakServer? = KeycloakServer.get(
                wrapSession(session),
                ownedIdentityObject.getKeycloakServerUrl(),
                ownedIdentity
            )
            ownedIdentityObject.setKeycloakServerUrl(null)
            if (keycloakServer != null) {
                keycloakServer.delete()
            }

            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))

            /**///// */
            // update owned identity details to remove signed part
            val jsonIdentityDetails =
                ownedIdentityObject.publishedDetails!!.jsonIdentityDetails
            jsonIdentityDetails!!.setSignedUserDetails(null)
            // also remove position and company
            jsonIdentityDetails.setPosition(null)
            jsonIdentityDetails.setCompany(null)

            ownedIdentityObject.discardLatestDetails()
            ownedIdentityObject.setLatestDetails(jsonIdentityDetails)
            return ownedIdentityObject.publishLatestDetails()
        }
        return -2
    }


    @Throws(SQLException::class)
    override fun getOwnedIdentityPublishedAndLatestDetails(
        session: Session,
        ownedIdentity: Identity?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            val res: Array<JsonIdentityDetailsWithVersionAndPhoto?>?
            if (ownedIdentityObject.publishedDetailsVersion == ownedIdentityObject.latestDetailsVersion) {
                res = arrayOfNulls<JsonIdentityDetailsWithVersionAndPhoto>(1)
                res[0] = ownedIdentityObject.publishedDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
            } else {
                res = arrayOfNulls<JsonIdentityDetailsWithVersionAndPhoto>(2)
                res[0] = ownedIdentityObject.publishedDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
                res[1] = ownedIdentityObject.latestDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
            }
            return res
        }
        return null
    }

    @Throws(SQLException::class)
    override fun updateKeycloakTransferRestrictedIfNeeded(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        transferRestricted: Boolean
    ) {
        val keycloakServer: KeycloakServer? =
            KeycloakServer.get(wrapSession(session), serverUrl, ownedIdentity!!)

        if (keycloakServer != null) {
            if (transferRestricted xor keycloakServer.isTransferRestricted()) {
                keycloakServer.setTransferRestricted(transferRestricted)
                session.addSessionCommitListener(
                    getSessionCommitListenerForProfileBackup(
                        ownedIdentity
                    )
                )
            }
        }
    }

    @Throws(SQLException::class)
    override fun updateKeycloakPushTopicsIfNeeded(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        pushTopics: MutableList<String?>?
    ): Boolean {
        val keycloakServer: KeycloakServer? =
            KeycloakServer.get(wrapSession(session), serverUrl, ownedIdentity!!)

        if (keycloakServer != null) {
            val oldSet = HashSet<String?>(keycloakServer.pushTopics)
            val newSet = HashSet<String?>()
            if (pushTopics != null) {
                newSet.addAll(pushTopics)
            }

            if (oldSet != newSet) {
                @Suppress("UNCHECKED_CAST")
                keycloakServer.setPushTopics(pushTopics as MutableList<String>?)
                return true
            }
        }
        return false
    }

    @Throws(SQLException::class)
    override fun setOwnedIdentityKeycloakSelfRevocationTestNonce(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        nonce: String?
    ) {
        val keycloakServer: KeycloakServer? =
            KeycloakServer.get(wrapSession(session), serverUrl, ownedIdentity!!)

        if (keycloakServer != null && keycloakServer.getSelfRevocationTestNonce() != nonce) {
            keycloakServer.setSelfRevocationTestNonce(nonce)
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityKeycloakSelfRevocationTestNonce(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?
    ): String? {
        val keycloakServer: KeycloakServer? =
            KeycloakServer.get(wrapSession(session), serverUrl, ownedIdentity!!)

        if (keycloakServer != null) {
            return keycloakServer.getSelfRevocationTestNonce()
        }
        return null
    }

    @Throws(Exception::class)
    override fun updateKeycloakGroups(
        session: Session,
        ownedIdentity: Identity?,
        signedGroupBlobs: MutableList<String?>?,
        signedGroupDeletions: MutableList<String?>?,
        signedGroupKicks: MutableList<String?>?,
        keycloakCurrentTimestamp: Long
    ) {
        if (!session.isInTransaction) {
            Logger.e("Called updateKeycloakGroups outside a transaction")
            throw Exception()
        }
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject == null || !ownedIdentityObject.isKeycloakManaged) {
            Logger.e("Called updateKeycloakGroups for an identity that is not keycloak managed")
            throw Exception()
        }
        val keycloakServer = ownedIdentityObject.keycloakServer

        val jwksResolver: JwksVerificationKeyResolver
        val signatureKey = keycloakServer!!.signatureKey
        if (signatureKey != null) {
            jwksResolver = JwksVerificationKeyResolver(mutableListOf<JsonWebKey?>(signatureKey))
        } else {
            val jwks = keycloakServer.jwks
            jwksResolver = JwksVerificationKeyResolver(jwks.getJsonWebKeys())
        }
        val jwtConsumer = JwtConsumerBuilder()
            .setExpectedAudience(false)
            .setVerificationKeyResolver(jwksResolver)
            .build()


        // first process group deletions
        if (signedGroupDeletions != null) {
            for (signedGroupDeletion in signedGroupDeletions) {
                try {
                    val claims = jwtConsumer.processToClaims(signedGroupDeletion)
                    if (claims == null) {
                        // invalid signature --> ignore it
                        continue
                    }

                    val keycloakGroupDeletionData =
                        jsonObjectMapper.readValue<KeycloakGroupDeletionData>(
                            claims.getRawJson(),
                            KeycloakGroupDeletionData::class.java
                        )
                    val groupUid = UID(keycloakGroupDeletionData!!.groupUid!!)
                    val groupIdentifier = GroupV2.Identifier(
                        groupUid,
                        keycloakServer.serverUrl!!,
                        GroupV2.Identifier.CATEGORY_KEYCLOAK
                    )

                    val groupLastModificationTimestamp: Long? =
                        ContactGroupV2.getLastModificationTimestamp(
                            wrapSession(session),
                            ownedIdentity!!,
                            groupIdentifier
                        )
                    if (groupLastModificationTimestamp == null || groupLastModificationTimestamp > keycloakGroupDeletionData.timestamp) {
                        // if the group is not found, or is more recent than the signed deletion, do not do anything
                        continue
                    }

                    // group was disbanded, delete it locally
                    deleteGroupV2(session, ownedIdentity, groupIdentifier, null)
                } catch (e: InvalidJwtException) {
                    // unable to process signed deletion --> ignore it
                    Logger.x(e)
                } catch (e: JsonProcessingException) {
                    Logger.x(e)
                } catch (e: IllegalArgumentException) {
                    Logger.x(e)
                }
            }
        }

        // then group kicks
        if (signedGroupKicks != null) {
            for (signedGroupKick in signedGroupKicks) {
                try {
                    val claims = jwtConsumer.processToClaims(signedGroupKick)
                    if (claims == null) {
                        // invalid signature --> ignore it
                        continue
                    }

                    val keycloakGroupMemberKickedData =
                        jsonObjectMapper.readValue<KeycloakGroupMemberKickedData>(
                            claims.getRawJson(),
                            KeycloakGroupMemberKickedData::class.java
                        )
                    val groupUid = UID(keycloakGroupMemberKickedData!!.groupUid!!)
                    // verify it's indeed me who's getting kicked
                    if (!ownedIdentity!!.getBytes()
                            .contentEquals(keycloakGroupMemberKickedData.identity)
                    ) {
                        continue
                    }
                    val groupIdentifier = GroupV2.Identifier(
                        groupUid,
                        keycloakServer.serverUrl!!,
                        GroupV2.Identifier.CATEGORY_KEYCLOAK
                    )

                    val groupLastModificationTimestamp: Long? =
                        ContactGroupV2.getLastModificationTimestamp(
                            wrapSession(session),
                            ownedIdentity,
                            groupIdentifier
                        )
                    if (groupLastModificationTimestamp == null || groupLastModificationTimestamp > keycloakGroupMemberKickedData.timestamp) {
                        // if the group is not found, or is more recent than the signed deletion, do not do anything
                        continue
                    }

                    // I was kicked from the group, delete it locally
                    deleteGroupV2(session, ownedIdentity, groupIdentifier, null)
                } catch (e: InvalidJwtException) {
                    // unable to process signed deletion --> ignore it
                    Logger.x(e)
                } catch (e: JsonProcessingException) {
                    Logger.x(e)
                } catch (e: IllegalArgumentException) {
                    Logger.x(e)
                }
            }
        }

        // update group blobs
        if (signedGroupBlobs != null) {
            for (signedGroupBlob in signedGroupBlobs) {
                try {
                    val claims = jwtConsumer.processToClaims(signedGroupBlob)
                    if (claims == null) {
                        // invalid signature --> ignore it
                        continue
                    }

                    val serializedKeycloakGroupBlob = claims.getRawJson()
                    val keycloakGroupBlob = jsonObjectMapper.readValue<KeycloakGroupBlob>(
                        serializedKeycloakGroupBlob,
                        KeycloakGroupBlob::class.java
                    )
                    val groupUid = UID(keycloakGroupBlob!!.bytesGroupUid!!)
                    val groupIdentifier = GroupV2.Identifier(
                        groupUid,
                        keycloakServer.serverUrl!!,
                        GroupV2.Identifier.CATEGORY_KEYCLOAK
                    )

                    if (keycloakGroupBlob.timestamp < keycloakCurrentTimestamp - Constants.KEYCLOAK_SIGNATURE_VALIDITY_MILLIS) {
                        Logger.w("Received a signed keycloak group blob with an outdated signature")
                        continue
                    }

                    protocolStarterDelegate!!.createOrUpdateKeycloakGroupV2(
                        session,
                        ownedIdentity,
                        groupIdentifier,
                        serializedKeycloakGroupBlob
                    )
                } catch (e: InvalidJwtException) {
                    // unable to process signed deletion --> ignore it
                    Logger.x(e)
                } catch (e: JsonProcessingException) {
                    Logger.x(e)
                } catch (e: IllegalArgumentException) {
                    Logger.x(e)
                }
            }
        }

        // finally set the lastGroupUpdateTimestamp
        keycloakServer.setLatestGroupUpdateTimestamp(keycloakCurrentTimestamp)
    }

    @Throws(SQLException::class)
    override fun reactivateOwnedIdentityIfNeeded(session: Session, ownedIdentity: Identity?) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null && !ownedIdentityObject.isActive()) {
            ownedIdentityObject.setActive(true)

            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))

            /**///////// */
            // After reactivating an identity, we must recreate all channels (that were destroyed after the deactivation)
            //  - restart channel creation for all owned devices (those were not deleted during deactivation)
            //  - restart all device discovery protocols
            //  - also do an owned device discovery
            try {
                for (ownedDeviceUid in getOtherDeviceUidsOfOwnedIdentity(
                    session,
                    ownedIdentity
                )!!) {
                    protocolStarterDelegate!!.startChannelCreationProtocolWithOwnedDevice(
                        session,
                        ownedIdentity,
                        ownedDeviceUid
                    )
                }
            } catch (e: Exception) {
                Logger.x(e)
            }

            val contactIdentities: Array<ContactIdentity> =
                ContactIdentity.getAll(wrapSession(session), ownedIdentity)
            for (contactIdentity in contactIdentities) {
                try {
                    protocolStarterDelegate!!.startDeviceDiscoveryProtocolWithinTransaction(
                        session,
                        ownedIdentity,
                        contactIdentity.getContactIdentity()
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
            try {
                protocolStarterDelegate!!.startOwnedDeviceDiscoveryProtocolWithinTransaction(
                    session,
                    ownedIdentity
                )
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
    }

    @Throws(SQLException::class)
    override fun deactivateOwnedIdentity(session: Session, ownedIdentity: Identity?) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        // set inactive even if it is already deactivated to trigger the notification
        ownedIdentityObject!!.setActive(false)
        // also clear any timestamp in the current device
        val ownedDevice: OwnedDevice = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        ) ?: return
        ownedDevice.setTimestamps(null, null)
        /**///////// */
        // After deactivating an identity, we must delete all channels
        //  - clear all contact deviceUid
        //  - delete all channels
        //  - we keep our owned devices, so that the app still knows the list
        //  - we trigger all ongoing sync protocols so that they detect the channel is gone and can finish
        ContactDevice.deleteAll(wrapSession(session), ownedIdentity!!)
        channelDelegate!!.deleteAllChannelsForOwnedIdentity(session, ownedIdentity)
        //        protocolStarterDelegate.triggerOwnedDevicesSync(session, ownedIdentity);
    }

    @Throws(SQLException::class)
    override fun markOwnedIdentityForDeletion(session: Session, ownedIdentity: Identity?) {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            ownedIdentityObject.markForDeletion()

            session.addSessionCommitListener(this.sessionCommitListenerForDeviceBackup)
        }
    }

    // endregion
    // region device Uids
    @Throws(SQLException::class)
    override fun getDeviceUidsOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): Array<UID?>? {
        val ownedIdentityObject: OwnedIdentity =
            OwnedIdentity.get(wrapSession(session), ownedIdentity) ?: return null
        return ownedIdentityObject.allDeviceUids
    }

    @Throws(SQLException::class)
    override fun getOtherDeviceUidsOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): Array<UID?>? {
        val ownedIdentityObject: OwnedIdentity =
            OwnedIdentity.get(wrapSession(session), ownedIdentity) ?: return null
        return ownedIdentityObject.otherDeviceUids
    }

    @Throws(SQLException::class)
    override fun getCurrentDeviceUidOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): UID? {
        val cachedUid = currentDeviceUidCache.get(ownedIdentity)
        if (cachedUid != null) {
            return cachedUid
        }
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            val deviceUid = ownedIdentityObject.currentDeviceUid
            currentDeviceUidCache.put(ownedIdentity, deviceUid)
            return deviceUid
        }
        return null
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityForCurrentDeviceUid(
        session: Session,
        currentDeviceUid: UID?
    ): Identity? {
        val ownedDevice: OwnedDevice? =
            OwnedDevice.get(wrapSession(session), currentDeviceUid!!)
        if (ownedDevice != null && ownedDevice.isCurrentDevice) {
            return ownedDevice.getOwnedIdentity()
        }
        return null
    }

    @Throws(SQLException::class)
    override fun addDeviceForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        deviceUid: UID?,
        displayName: String?,
        expirationTimestamp: Long?,
        lastRegistrationTimestamp: Long?,
        preKeyBlob: PreKeyBlobOnServer?,
        channelCreationAlreadyInProgress: Boolean
    ) {
        // check if the device already exists first
        var ownedDevice: OwnedDevice? = OwnedDevice.get(wrapSession(session), deviceUid!!)
        if (ownedDevice != null && ownedDevice.getOwnedIdentity() != ownedIdentity) {
            Logger.e("Error: trying to addDeviceForOwnedIdentity for a deviceUid already used by another identity")
            throw SQLException()
        }
        // only create the device if it does not already exist
        if (ownedDevice == null) {
            ownedDevice = OwnedDevice.createOtherDevice(
                wrapSession(session),
                deviceUid,
                ownedIdentity,
                displayName,
                expirationTimestamp,
                lastRegistrationTimestamp,
                preKeyBlob,
                channelCreationAlreadyInProgress
            )
            if (ownedDevice == null) {
                throw SQLException()
            }
        }
    }

    @Throws(SQLException::class)
    override fun updateOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        deviceUid: UID?,
        displayName: String?,
        expirationTimestamp: Long?,
        lastRegistrationTimestamp: Long?,
        preKeyBlob: PreKeyBlobOnServer?
    ) {
        // check that the device exists and is for the right ownedIdentity
        val ownedDevice: OwnedDevice? = OwnedDevice.get(wrapSession(session), deviceUid!!)
        if (ownedDevice != null && ownedDevice.getOwnedIdentity() == ownedIdentity) {
            if (displayName != ownedDevice.getDisplayName()) {
                ownedDevice.setDisplayName(displayName)
                session.addSessionCommitListener(
                    getSessionCommitListenerForProfileBackup(
                        ownedIdentity
                    )
                )
            }
            if (expirationTimestamp != ownedDevice.expirationTimestamp || lastRegistrationTimestamp != ownedDevice.lastRegistrationTimestamp) {
                // check if this is the first registration of the current device
                if (ownedDevice.isCurrentDevice && ownedDevice.lastRegistrationTimestamp == null && lastRegistrationTimestamp != null) {
                    // after the first registration of the current device, start all contact device discoveries
                    val contactIdentities = getContactsOfOwnedIdentity(session, ownedIdentity)
                    if (contactIdentities != null && contactIdentities.isNotEmpty()) {
                        Logger.i("Found " + contactIdentities.size + " contacts for first device discovery. Starting corresponding deviceDiscoveryProtocols.")
                        for (contactIdentity in contactIdentities) {
                            try {
                                protocolStarterDelegate!!.startDeviceDiscoveryProtocolWithinTransaction(session, ownedIdentity, contactIdentity)
                            } catch (e: Exception) {
                                Logger.x(e)
                            }
                        }
                    }
                }
                ownedDevice.setTimestamps(expirationTimestamp, lastRegistrationTimestamp)
            }
            if (preKeyBlob == null) {
                if (ownedDevice.preKey != null) {
                    ownedDevice.preKey = null
                }
            } else {
                if (!ownedDevice.hasPreKey() || ownedDevice.preKey!!.keyId != preKeyBlob.preKey.keyId) {
                    ownedDevice.preKey = preKeyBlob.preKey
                }
                if (ownedDevice.deviceCapabilities == null) {
                    ownedDevice.rawDeviceCapabilities = preKeyBlob.rawDeviceCapabilities
                }
            }
        }
    }

    @Throws(SQLException::class)
    override fun removeDeviceForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        deviceUid: UID?
    ) {
        val ownedDevice: OwnedDevice? = OwnedDevice.get(wrapSession(session), deviceUid!!)
        if (ownedDevice != null && ownedDevice.getOwnedIdentity().equals(ownedIdentity)) {
            ownedDevice.delete()
        }
    }

    @Throws(SQLException::class)
    override fun isCurrentDeviceNeverRegistered(session: Session, ownedIdentity: Identity?): Boolean {
        val currentDevice = OwnedDevice.getCurrentDeviceOfOwnedIdentity(wrapSession(session), ownedIdentity)
        return currentDevice != null && currentDevice.lastRegistrationTimestamp == null
    }


    @Throws(SQLException::class)
    override fun getDevicesOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<ObvOwnedDevice> {
        if (!isOwnedIdentity(session, ownedIdentity, true)) {
            // always return an empty list for owned identity that are marked for deletion
            return mutableListOf()
        }
        val ownedDevices: MutableList<OwnedDevice> =
            OwnedDevice.getAllDevicesOfIdentity(wrapSession(session), ownedIdentity!!)
        val obvOwnedDevices: MutableList<ObvOwnedDevice> = ArrayList()
        for (ownedDevice in ownedDevices) {
            obvOwnedDevices.add(
                ObvOwnedDevice(
                    ownedDevice.getOwnedIdentity().getBytes(),
                    ownedDevice.uid.bytes,
                    ServerDeviceInfo(
                        ownedDevice.getDisplayName(),
                        ownedDevice.expirationTimestamp,
                        ownedDevice.lastRegistrationTimestamp
                    ),
                    ownedDevice.isCurrentDevice,
                    channelDelegate!!.checkIfObliviousChannelIsConfirmed(
                        session,
                        ownedIdentity,
                        ownedDevice.uid,
                        ownedIdentity
                    ),
                    ownedDevice.hasPreKey()
                )
            )
        }
        return obvOwnedDevices
    }

    @Throws(SQLException::class)
    override fun getDevicesAndPreKeysOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<OwnedDeviceAndPreKey?> {
        val ownedDevices: MutableList<OwnedDevice> =
            OwnedDevice.getAllDevicesOfIdentity(wrapSession(session), ownedIdentity!!)
        val ownedDeviceAndPreKeys: MutableList<OwnedDeviceAndPreKey?> =
            ArrayList<OwnedDeviceAndPreKey?>()
        for (ownedDevice in ownedDevices) {
            ownedDeviceAndPreKeys.add(
                OwnedDeviceAndPreKey(
                    ownedDevice.getOwnedIdentity(),
                    ownedDevice.uid,
                    ownedDevice.isCurrentDevice,
                    ownedDevice.preKey,
                    ServerDeviceInfo(
                        ownedDevice.getDisplayName(),
                        ownedDevice.expirationTimestamp,
                        ownedDevice.lastRegistrationTimestamp
                    )
                )
            )
        }
        return ownedDeviceAndPreKeys
    }

    @Throws(SQLException::class)
    override fun getCurrentDeviceDisplayName(session: Session, ownedIdentity: Identity?): String? {
        val device: OwnedDevice? = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        return device?.getDisplayName()
    }

    @Throws(SQLException::class)
    override fun getLatestPreKeyForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): EncodedOwnedPreKey? {
        val ownedPreKey: OwnedPreKey? =
            OwnedPreKey.getLatest(wrapSession(session), ownedIdentity!!)
        if (ownedPreKey != null) {
            return EncodedOwnedPreKey(
                ownedPreKey.keyId,
                ownedPreKey.expirationTimestamp,
                ownedPreKey.encodedSignedPreKey
            )
        }
        return null
    }

    @Throws(SQLException::class)
    override fun generateNewPreKey(
        session: Session,
        ownedIdentity: Identity?,
        expirationTimestamp: Long
    ): Encoded? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        val device: OwnedDevice? = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        if (ownedIdentityObject != null && device != null) {
            val ownedPreKey: OwnedPreKey? = OwnedPreKey.create(
                wrapSession(session),
                ownedIdentity,
                ownedIdentityObject.getPrivateIdentity(),
                device.uid,
                expirationTimestamp,
                prng!!
            )
            if (ownedPreKey != null) {
                return ownedPreKey.encodedSignedPreKey
            }
        }
        return null
    }

    @Throws(SQLException::class)
    override fun expireContactAndOwnedPreKeys(
        session: Session,
        ownedIdentity: Identity?,
        server: String?,
        serverTimestamp: Long
    ) {
        if (ownedIdentity!!.server == server) {
            // expire own pre-keys
            val ownedDevices: MutableList<OwnedDevice> =
                OwnedDevice.getAllWithExpiredPreKey(
                    wrapSession(session),
                    ownedIdentity,
                    serverTimestamp
                )
            for (ownedDevice in ownedDevices) {
                ownedDevice.preKey = null
            }
        }

        val contactDevices: MutableList<ContactDevice?> =
            ContactDevice.getAllWithExpiredPreKey(
                wrapSession(session),
                ownedIdentity,
                serverTimestamp
            )
        for (contactDevice in contactDevices) {
            if (contactDevice!!.getContactIdentity().server == server) {
                contactDevice.setPreKey(null)
            }
        }
    }

    @Throws(SQLException::class)
    override fun expireCurrentDeviceOwnedPreKeys(
        session: Session,
        ownedIdentity: Identity?,
        currentServerTimestamp: Long
    ) {
        OwnedPreKey.deleteExpired(
            wrapSession(session),
            ownedIdentity!!,
            currentServerTimestamp - Constants.PRE_KEY_CONSERVATION_DURATION
        )
    }

    @Throws(SQLException::class)
    override fun getLatestChannelCreationPingTimestampForOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?
    ): Long {
        val ownedDevice: OwnedDevice? =
            OwnedDevice.get(wrapSession(session), ownedDeviceUid!!)
        if (ownedDevice != null && ownedDevice.getOwnedIdentity().equals(ownedIdentity)) {
            return ownedDevice.getLatestChannelCreationPingTimestamp()
        }
        return -1
    }

    @Throws(Exception::class)
    override fun setLatestChannelCreationPingTimestampForOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?,
        timestamp: Long
    ) {
        val ownedDevice: OwnedDevice? =
            OwnedDevice.get(wrapSession(session), ownedDeviceUid!!)
        if (ownedDevice != null && ownedDevice.getOwnedIdentity().equals(ownedIdentity)) {
            ownedDevice.setLatestChannelCreationPingTimestamp(timestamp)
        }
    }


    // endregion
    @Throws(Exception::class)
    override fun addContactIdentity(
        session: Session,
        contactIdentity: Identity?,
        serializedDetails: String?,
        ownedIdentity: Identity?,
        trustOrigin: TrustOrigin?,
        oneToOne: Boolean
    ) {
        try {
            if (contactIdentity!!.equals(ownedIdentity)) {
                throw Exception("Error: trying to add your ownedIdentity as a contact")
            }

            val jsonIdentityDetailsWithVersionAndPhoto = JsonIdentityDetailsWithVersionAndPhoto()
            jsonIdentityDetailsWithVersionAndPhoto.setVersion(-1)
            val jsonIdentityDetails = jsonObjectMapper.readValue<JsonIdentityDetails?>(
                serializedDetails,
                JsonIdentityDetails::class.java
            )
            jsonIdentityDetailsWithVersionAndPhoto.setIdentityDetails(jsonIdentityDetails)

            var contactIsRevoked = false
            val keycloakRevokedIdentities: MutableList<KeycloakRevokedIdentity?>? =
                KeycloakRevokedIdentity.get(
                    wrapSession(session),
                    ownedIdentity,
                    contactIdentity
                )
            if (keycloakRevokedIdentities != null) {
                for (keycloakRevokedIdentity in keycloakRevokedIdentities) {
                    if (keycloakRevokedIdentity!!.revocationType == KeycloakRevokedIdentity.TYPE_COMPROMISED) {
                        contactIsRevoked = true
                        break
                    }
                }
            }

            val contactIdentityObject: ContactIdentity? = ContactIdentity.create(
                wrapSession(session),
                contactIdentity,
                ownedIdentity,
                jsonIdentityDetailsWithVersionAndPhoto,
                trustOrigin,
                contactIsRevoked,
                oneToOne
            )
            if (contactIdentityObject == null) {
                Logger.w("An error occurred while creating a ContactIdentity.")
                throw SQLException()
            }
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        } catch (e: Exception) {
            Logger.x(e)
            throw Exception()
        }
    }

    @Throws(SQLException::class)
    override fun addTrustOriginToContact(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        trustOrigin: TrustOrigin?,
        markContactAsOneToOne: Boolean
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject == null) {
            Logger.e("Error in addTrustOriginToContact: contactIdentity is not a ContactIdentity of ownedIdentity")
            throw SQLException()
        }
        contactIdentityObject.addTrustOrigin(trustOrigin!!)
        if (markContactAsOneToOne && !contactIdentityObject.isOneToOne()) {
            contactIdentityObject.setOneToOne(true)
        }
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
    }

    override fun getContactsOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): Array<Identity>? {
        try {
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(wrapSession(session), ownedIdentity)
            if (ownedIdentityObject != null) {
                val contactIdentities = ownedIdentityObject.contactIdentities
                return contactIdentities.map { it.getContactIdentity() }.toTypedArray()
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return null
    }

    @Throws(Exception::class)
    fun getContactDeviceCounts(
        session: Session,
        ownedIdentity: Identity,
        contactIdentity: Identity
    ): ObvContactDeviceCount {
        var count = 0
        var established = 0
        var preKey = 0
        val confirmedChannelUids = HashSet<UID?>(
            listOf<UID?>(
                *channelDelegate!!.getConfirmedObliviousChannelDeviceUids(
                    session,
                    ownedIdentity,
                    contactIdentity
                )
            )
        )
        for (uidAndPreKey in getDeviceUidsAndPreKeysOfContactIdentity(
            session,
            ownedIdentity,
            contactIdentity
        )) {
            count++
            if (confirmedChannelUids.contains(uidAndPreKey!!.uid)) {
                established++
            } else if (uidAndPreKey.preKey != null) {
                preKey++
            }
        }
        return ObvContactDeviceCount(count, established, preKey)
    }

    @Throws(Exception::class)
    fun getContactsInfoOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity
    ): MutableList<ObvContactInfo> {
        val contactIdentities: Array<ContactIdentity> =
            ContactIdentity.getAll(wrapSession(session), ownedIdentity)
        val contactInfos: MutableList<ObvContactInfo> = ArrayList()
        for (contactIdentity in contactIdentities) {
            val trustedDetails = contactIdentity.trustedDetails
            contactInfos.add(
                ObvContactInfo(
                    contactIdentity.getOwnedIdentity().getBytes(),
                    contactIdentity.getContactIdentity().getBytes(),
                    trustedDetails!!.jsonIdentityDetails,
                    contactIdentity.isCertifiedByOwnKeycloak,
                    contactIdentity.isOneToOne(),
                    trustedDetails.getPhotoUrl(),
                    contactIdentity.isActive,
                    contactIdentity.isRecentlyOnline(),
                    contactIdentity.getTrustLevel().major,
                    getContactDeviceCounts(
                        session,
                        ownedIdentity,
                        contactIdentity.getContactIdentity()
                    )
                )
            )
        }
        return contactInfos
    }

    @Throws(SQLException::class)
    override fun trustPublishedContactDetails(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): JsonIdentityDetailsWithVersionAndPhoto? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            val details = contactIdentityObject.trustPublishedDetails()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
            return details
        }
        return null
    }

    @Throws(Exception::class)
    override fun setContactPublishedDetails(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?,
        allowDowngrade: Boolean
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            contactIdentityObject.updatePublishedDetails(
                jsonIdentityDetailsWithVersionAndPhoto,
                allowDowngrade
            )
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        }
    }

    @Throws(Exception::class)
    override fun setContactDetailsDownloadedPhoto(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        version: Int,
        photo: ByteArray?
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            contactIdentityObject.setDetailsDownloadedPhotoUrl(version, photo!!)
        }
    }

    override fun getSerializedPublishedDetailsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): String? {
        return ContactIdentity.getSerializedPublishedDetails(
            wrapSession(session),
            ownedIdentity!!,
            contactIdentity!!
        )
    }

    @Throws(SQLException::class)
    override fun getContactIdentityTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): JsonIdentityDetails? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            return contactIdentityObject.trustedDetails!!.jsonIdentityDetails
        }
        return null
    }

    @Throws(SQLException::class)
    override fun getContactTrustedDetailsPhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): String? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            return contactIdentityObject.trustedDetails!!.getPhotoUrl()
        }
        return null
    }

    @Throws(SQLException::class)
    override fun contactHasUntrustedPublishedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            return contactIdentityObject.publishedDetailsVersion != contactIdentityObject.trustedDetailsVersion
        }
        return false
    }


    @Throws(SQLException::class)
    override fun getContactPublishedAndTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            val res: Array<JsonIdentityDetailsWithVersionAndPhoto?>?
            if (contactIdentityObject.publishedDetailsVersion == contactIdentityObject.trustedDetailsVersion) {
                res = arrayOfNulls<JsonIdentityDetailsWithVersionAndPhoto>(1)
                res[0] = contactIdentityObject.publishedDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
            } else {
                res = arrayOfNulls<JsonIdentityDetailsWithVersionAndPhoto>(2)
                res[0] = contactIdentityObject.publishedDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
                res[1] = contactIdentityObject.trustedDetails!!
                    .jsonIdentityDetailsWithVersionAndPhoto
            }
            return res
        }
        return null
    }

    @Throws(SQLException::class)
    override fun isContactIdentityCertifiedByOwnKeycloak(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            return contactIdentityObject.isCertifiedByOwnKeycloak
        }
        return false
    }

    @Throws(SQLException::class)
    override fun unmarkAllCertifiedByOwnKeycloakContacts(
        session: Session,
        ownedIdentity: Identity?
    ) {
        ContactIdentity.unmarkAllCertifiedByOwnKeycloakContacts(
            wrapSession(session),
            ownedIdentity!!
        )
    }

    @Throws(SQLException::class)
    override fun reCheckAllCertifiedByOwnKeycloakContacts(
        session: Session,
        ownedIdentity: Identity?
    ) {
        for (contactIdentity in ContactIdentity.getAll(
            wrapSession(session),
            ownedIdentity!!
        )) {
            val publishedDetails: ContactIdentityDetails? = contactIdentity.publishedDetails

            if (publishedDetails != null) {
                val identityDetails = publishedDetails.jsonIdentityDetails
                if (identityDetails != null && identityDetails.signedUserDetails != null) {
                    val jsonKeycloakUserDetails = verifyKeycloakIdentitySignature(
                        session,
                        ownedIdentity,
                        identityDetails.signedUserDetails
                    )

                    if (jsonKeycloakUserDetails != null) {
                        // the contact has some valid signed details
                        try {
                            val certifiedJsonIdentityDetails =
                                jsonKeycloakUserDetails.getIdentityDetails(identityDetails.signedUserDetails)
                            contactIdentity.markContactAsCertifiedByOwnKeycloak(
                                certifiedJsonIdentityDetails
                            )
                            continue
                        } catch (e: Exception) {
                            // error parsing signed details --> do nothing
                            Logger.x(e)
                        }
                    }
                }
            }

            if (contactIdentity.isCertifiedByOwnKeycloak) {
                contactIdentity.setCertifiedByOwnKeycloak(false, null)
            }
        }
    }

    override fun getTrustOriginsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<TrustOrigin?> {
        val contactTrustOrigins: Array<ContactTrustOrigin?> = ContactTrustOrigin.getAll(
            wrapSession(session),
            contactIdentity!!,
            ownedIdentity!!
        )
        val trustOrigins = arrayOfNulls<TrustOrigin>(contactTrustOrigins.size)
        for (i in contactTrustOrigins.indices) {
            trustOrigins[i] = contactTrustOrigins[i]!!.trustOrigin
        }
        return trustOrigins
    }

    @Throws(Exception::class)
    override fun getContactTrustLevel(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): TrustLevel? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            return contactIdentityObject.getTrustLevel()
        }
        return null
    }

    @Throws(Exception::class)
    override fun deleteContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        failIfGroup: Boolean
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            // check there are no Groups where this contact is
            if (failIfGroup) {
                val memberGroupUids: Array<ByteArray> =
                    ContactGroupMembersJoin.getGroupOwnerAndUidsOfGroupsContainingContact(
                        wrapSession(session),
                        contactIdentity!!,
                        ownedIdentity!!
                    )
                if (memberGroupUids.isNotEmpty()) {
                    Logger.w("Attempted to delete a contact still member of some groups.")
                    throw Exception()
                }

                if (ContactGroupV2Member.isContactMemberOfAGroupV2(
                        wrapSession(session),
                        ownedIdentity,
                        contactIdentity
                    )
                ) {
                    Logger.w("Attempted to delete a contact still member of some groups v2.")
                    throw Exception()
                }
            }

            // delete the contact
            contactIdentityObject.delete()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        }
    }

    @Throws(Exception::class)
    override fun getGroupOwnerAndUidsOfGroupsOwnedByContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<ByteArray?> {
        return ContactGroup.getGroupOwnerAndUidsOfGroupsOwnedByContact(
            wrapSession(session),
            ownedIdentity!!,
            contactIdentity!!
        )
    }

    @Throws(SQLException::class)
    override fun isIdentityAnActiveContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        return (contactIdentityObject != null && contactIdentityObject.isActive)
    }

    @Throws(SQLException::class)
    override fun isIdentityAContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        return (contactIdentityObject != null)
    }

    @Throws(SQLException::class)
    override fun isIdentityAOneToOneContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        return (contactIdentityObject != null && contactIdentityObject.isOneToOne())
    }

    @Throws(SQLException::class)
    override fun isIdentityANotOneToOneContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        return (contactIdentityObject != null && contactIdentityObject.isNotOneToOne)
    }


    // this method always sets to ONE_TO_ONE_STATUS_TRUE or ONE_TO_ONE_STATUS_FALSE, but never leaves in ONE_TO_ONE_STATUS_UNKNOWN
    @Throws(SQLException::class)
    override fun setContactOneToOne(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        oneToOne: Boolean
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        // only actually call the setter if the oneToOne is changed (or if contact oneToOne was unknown)
        if (contactIdentityObject != null
            && ((oneToOne && !contactIdentityObject.isOneToOne()) || (!oneToOne && !contactIdentityObject.isNotOneToOne))
        ) {
            contactIdentityObject.setOneToOne(oneToOne)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        }
    }

    @Throws(SQLException::class)
    override fun getContactActiveOrInactiveReasons(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): EnumSet<ObvContactActiveOrInactiveReason>? {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject == null) {
            return null
        }
        val reasons =
            EnumSet.noneOf<ObvContactActiveOrInactiveReason>(ObvContactActiveOrInactiveReason::class.java)
        if (contactIdentityObject.isRevokedAsCompromised()) {
            reasons.add(ObvContactActiveOrInactiveReason.REVOKED)
        }
        if (contactIdentityObject.isForcefullyTrustedByUser()) {
            reasons.add(ObvContactActiveOrInactiveReason.FORCEFULLY_UNBLOCKED)
        }
        return reasons
    }

    @Throws(SQLException::class)
    override fun forcefullyUnblockContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject == null) {
            return false
        }
        contactIdentityObject.setForcefullyTrustedByUser(true)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
        return true
    }

    @Throws(SQLException::class)
    override fun reBlockForcefullyUnblockedContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject == null || !contactIdentityObject.isForcefullyTrustedByUser()) {
            return false
        }
        try {
            if (contactIdentityObject.isRevokedAsCompromised()) {
                channelDelegate!!.deleteObliviousChannelsWithContact(
                    session,
                    ownedIdentity,
                    contactIdentity
                )
                removeAllDevicesForContactIdentity(session, ownedIdentity, contactIdentity)
            }
            contactIdentityObject.setForcefullyTrustedByUser(false)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
            return true
        } catch (e: Exception) {
            Logger.x(e)
            return false
        }
    }

    @Throws(SQLException::class)
    override fun setContactRecentlyOnline(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        recentlyOnline: Boolean
    ) {
        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contactIdentityObject != null) {
            contactIdentityObject.setRecentlyOnline(recentlyOnline)
        }
    }

    @Throws(SQLException::class)
    override fun addDeviceForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?,
        preKeyBlob: PreKeyBlobOnServer?,
        channelCreationAlreadyInProgress: Boolean
    ): Boolean {
        val contact: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        if (contact != null && contact.isActive) {
            var contactDevice: ContactDevice? = ContactDevice.get(
                wrapSession(session),
                deviceUid!!,
                contactIdentity!!,
                ownedIdentity!!
            )
            // only create the contact device if it does not already exist
            if (contactDevice == null) {
                contactDevice = ContactDevice.create(
                    wrapSession(session),
                    deviceUid,
                    contactIdentity,
                    ownedIdentity,
                    preKeyBlob,
                    channelCreationAlreadyInProgress
                )
                if (contactDevice == null) {
                    throw SQLException()
                }
                return true
            }
        }
        return false
    }

    @Throws(SQLException::class)
    override fun isContactDeviceKnown(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Boolean {
        return ContactDevice.exists(
            wrapSession(session),
            contactDeviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
    }

    @Throws(SQLException::class)
    override fun updateContactDevicePreKey(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?,
        preKeyBlob: PreKeyBlobOnServer?
    ) {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            deviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        if (contactDevice != null) {
            contactDevice.setPreKey(preKeyBlob)
        }
    }

    @Throws(SQLException::class)
    override fun removeDeviceForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?
    ) {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            deviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        if (contactDevice != null) {
            contactDevice.delete()
        }
    }

    @Throws(SQLException::class)
    override fun removeAllDevicesForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ) {
        val contactDevices: Array<ContactDevice?> =
            ContactDevice.getAll(wrapSession(session), contactIdentity!!, ownedIdentity!!)
        for (contactDevice in contactDevices) {
            contactDevice!!.delete()
        }
    }

    override fun getDeviceUidsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<UID?> {
        try {
            val contactDevices: Array<ContactDevice?> =
                ContactDevice.getAll(wrapSession(session), contactIdentity!!, ownedIdentity!!)
            val uids = arrayOfNulls<UID>(contactDevices.size)
            for (i in contactDevices.indices) {
                uids[i] = contactDevices[i]!!.uid
            }
            return uids
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return arrayOfNulls(0)
    }

    override fun getDeviceUidsAndPreKeysOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): MutableList<UidAndPreKey?> {
        try {
            val uids: MutableList<UidAndPreKey?> = ArrayList<UidAndPreKey?>()
            val contactDevices: Array<ContactDevice?> =
                ContactDevice.getAll(wrapSession(session), contactIdentity!!, ownedIdentity!!)
            for (contactDevice in contactDevices) {
                uids.add(UidAndPreKey(contactDevice!!.uid, contactDevice.preKey))
            }
            return uids
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return mutableListOf<UidAndPreKey?>()
    }

    @Throws(SQLException::class)
    override fun getAllDeviceUidsOfAllContactsOfAllOwnedIdentities(session: Session): MutableMap<Identity?, MutableMap<Identity?, MutableSet<UID?>?>?> {
        val output = HashMap<Identity?, MutableMap<Identity?, MutableSet<UID?>?>?>()
        val contactDevices: Array<ContactDevice?> =
            ContactDevice.getAll(wrapSession(session))
        for (contactDevice in contactDevices) {
            var ownedIdentityMap = output.get(contactDevice!!.getOwnedIdentity())
            if (ownedIdentityMap == null) {
                ownedIdentityMap = HashMap<Identity?, MutableSet<UID?>?>()
                output.put(contactDevice.getOwnedIdentity(), ownedIdentityMap)
            }
            var contactDeviceUids = ownedIdentityMap.get(contactDevice.getContactIdentity())
            if (contactDeviceUids == null) {
                contactDeviceUids = HashSet<UID?>()
                ownedIdentityMap.put(contactDevice.getContactIdentity(), contactDeviceUids)
            }
            contactDeviceUids.add(contactDevice.uid)
        }
        return output
    }

    @Throws(SQLException::class)
    override fun getLatestChannelCreationPingTimestampForContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Long {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            contactDeviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        if (contactDevice != null) {
            return contactDevice.getLatestChannelCreationPingTimestamp()
        }
        return -1
    }

    @Throws(Exception::class)
    override fun setLatestChannelCreationPingTimestampForContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        timestamp: Long
    ) {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            contactDeviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        contactDevice?.setLatestChannelCreationPingTimestamp(timestamp)
    }

    @Throws(SQLException::class)
    override fun getContactCapabilities(
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): MutableList<ObvCapability> {
        // for now, we compute the intersection of all device capabilities. This may change in the future depending on capabilities we will add
        getSession().use { identityManagerSession ->
            return getContactCapabilities(identityManagerSession, ownedIdentity!!, contactIdentity!!)
        }
    }

    @Throws(SQLException::class)
    private fun getContactCapabilities(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity,
        contactIdentity: Identity
    ): MutableList<ObvCapability> {
        val contactDevices: Array<ContactDevice?> =
            ContactDevice.getAll(identityManagerSession!!, contactIdentity, ownedIdentity)
        var contactCapabilities: HashSet<ObvCapability>? = null
        for (contactDevice in contactDevices) {
            val deviceCapabilities = contactDevice!!.deviceCapabilities ?: continue
            if (deviceCapabilities.isEmpty()) {
                return ArrayList()
            }
            if (contactCapabilities == null) {
                contactCapabilities = HashSet(deviceCapabilities)
            } else {
                contactCapabilities.retainAll(deviceCapabilities)
                if (contactCapabilities.isEmpty()) {
                    return ArrayList()
                }
            }
        }
        if (contactCapabilities == null) {
            return ArrayList()
        }
        return ArrayList(contactCapabilities)
    }

    @Throws(SQLException::class)
    override fun getContactDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Array<String> {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            contactDeviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        if (contactDevice != null) {
            return contactDevice.rawDeviceCapabilities
        }
        return emptyArray()
    }

    @Throws(Exception::class)
    override fun setContactDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        rawDeviceCapabilities: Array<String>?
    ) {
        val contactDevice: ContactDevice? = ContactDevice.get(
            wrapSession(session),
            contactDeviceUid!!,
            contactIdentity!!,
            ownedIdentity!!
        )
        if (contactDevice == null) {
            throw Exception()
        }
        contactDevice.setRawDeviceCapabilities(rawDeviceCapabilities)
    }

    @Throws(SQLException::class)
    override fun getOwnCapabilities(ownedIdentity: Identity?): MutableList<ObvCapability> {
        // for now, we compute the intersection of all device capabilities. This may change in the future depending on capabilities we will add
        getSession().use { identityManagerSession ->
            // initialize with current capabilities
            val ownCapabilities = HashSet(ObvCapability.currentCapabilities)

            // update with other devices
            val ownedDevices: Array<OwnedDevice> =
                OwnedDevice.getOtherDevicesOfOwnedIdentity(
                    identityManagerSession,
                    ownedIdentity!!
                )
            for (ownedDevice in ownedDevices) {
                val deviceCapabilities = ownedDevice.deviceCapabilities
                    ?: continue // skip this device, we do not know its capabilities yet

                if (deviceCapabilities.isEmpty()) {
                    return ArrayList()
                }
                ownCapabilities.retainAll(deviceCapabilities)
                if (ownCapabilities.isEmpty()) {
                    return ArrayList()
                }
            }
            return ArrayList(ownCapabilities)
        }
    }

    @Throws(Exception::class)
    override fun getCurrentDevicePublishedCapabilities(
        session: Session,
        ownedIdentity: Identity?
    ): List<ObvCapability> {
        val ownedDevice: OwnedDevice? = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        return ownedDevice?.deviceCapabilities ?: emptyList()
    }

    @Throws(Exception::class)
    override fun setCurrentDevicePublishedCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        capabilities: MutableList<ObvCapability>?
    ) {
        val ownedDevice: OwnedDevice? = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            wrapSession(session),
            ownedIdentity
        )
        ownedDevice?.rawDeviceCapabilities = if (capabilities != null) ObvCapability.capabilityListToStringArray(capabilities) else null
    }

    @Throws(Exception::class)
    override fun getOtherOwnedDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        otherDeviceUid: UID?
    ): Array<String>? {
        val ownedDevice: OwnedDevice? =
            OwnedDevice.get(wrapSession(session), otherDeviceUid!!)
        if (ownedDevice == null || !ownedDevice.getOwnedIdentity().equals(ownedIdentity)) {
            throw Exception()
        }
        return ownedDevice.rawDeviceCapabilities
    }

    @Throws(Exception::class)
    override fun setOtherOwnedDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        otherOwnedDeviceUID: UID?,
        rawDeviceCapabilities: Array<String>?
    ) {
        val ownedDevice: OwnedDevice? =
            OwnedDevice.get(wrapSession(session), otherOwnedDeviceUID!!)
        if (ownedDevice == null || !ownedDevice.getOwnedIdentity().equals(ownedIdentity)) {
            throw Exception()
        }
        ownedDevice.rawDeviceCapabilities = rawDeviceCapabilities
    }

    @Throws(Exception::class)
    override fun getDeterministicSeedForOwnedIdentity(
        ownedIdentity: Identity?,
        diversificationTag: ByteArray?,
        context: DeterministicSeedContext?
    ): Seed {
        if (diversificationTag!!.isEmpty()) {
            throw Exception()
        }
        getSession().use { identityManagerSession ->
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(identityManagerSession, ownedIdentity)
            if (ownedIdentity == null) {
                throw SQLException("OwnedIdentity not found")
            }
            val privateIdentity = ownedIdentityObject!!.getPrivateIdentity()
            return privateIdentity!!.getDeterministicSeedForOwnedIdentity(diversificationTag, context!!)
        }
    }


    @Throws(Exception::class)
    override fun signIdentities(
        session: Session,
        signatureContext: SignatureContext?,
        identities: Array<Identity?>?,
        ownedIdentity: Identity?,
        prng: PRNGService
    ): ByteArray? {
        try {
            val identityManagerSession = wrapSession(session)
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(identityManagerSession, ownedIdentity)
            if (ownedIdentityObject == null) {
                throw Exception("Unknown owned identity")
            }
            val privateIdentity = ownedIdentityObject.getPrivateIdentity()
            val signaturePublicKey =
                ownedIdentity!!.serverAuthenticationPublicKey.signaturePublicKey
            val signaturePrivateKey =
                privateIdentity!!.serverAuthenticationPrivateKey.signaturePrivateKey

            val baos = ByteArrayOutputStream()
            baos.write(Constants.getSignatureChallengePrefix(signatureContext!!))
            for (identity in identities!!) {
                baos.write(identity!!.getBytes())
            }
            val padding = prng.bytes(Constants.SIGNATURE_PADDING_LENGTH)
            baos.write(padding)
            val challenge = baos.toByteArray()
            baos.close()
            val signature = Suite.getSignature(signaturePrivateKey)!!
            val signatureBytes =
                signature.sign(signaturePrivateKey, signaturePublicKey, challenge, prng)!!
            val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
            System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
            System.arraycopy(
                signatureBytes,
                0,
                output,
                Constants.SIGNATURE_PADDING_LENGTH,
                signatureBytes.size
            )
            return output
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        }
    }


    @Throws(Exception::class)
    override fun signChannel(
        session: Session,
        signatureContext: SignatureContext?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?,
        prng: PRNGService?
    ): ByteArray? {
        try {
            val identityManagerSession = wrapSession(session)
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(identityManagerSession, ownedIdentity)
            if (ownedIdentityObject == null) {
                throw Exception("Unknown owned identity")
            }
            val privateIdentity = ownedIdentityObject.getPrivateIdentity()
            val signaturePublicKey =
                ownedIdentity!!.serverAuthenticationPublicKey.signaturePublicKey
            val signaturePrivateKey =
                privateIdentity!!.serverAuthenticationPrivateKey.signaturePrivateKey

            val baos = ByteArrayOutputStream()
            baos.write(Constants.getSignatureChallengePrefix(signatureContext!!))
            baos.write(contactDeviceUid!!.bytes)
            baos.write(ownedDeviceUid!!.bytes)
            baos.write(contactIdentity!!.getBytes())
            baos.write(ownedIdentity.getBytes())
            val padding = prng!!.bytes(Constants.SIGNATURE_PADDING_LENGTH)
            baos.write(padding)
            val challenge = baos.toByteArray()
            baos.close()
            val signature = Suite.getSignature(signaturePrivateKey)!!
            val signatureBytes =
                signature.sign(signaturePrivateKey, signaturePublicKey, challenge, prng)!!
            val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
            System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
            System.arraycopy(
                signatureBytes,
                0,
                output,
                Constants.SIGNATURE_PADDING_LENGTH,
                signatureBytes.size
            )
            return output
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    override fun signBlock(
        session: Session,
        signatureContext: SignatureContext?,
        block: ByteArray?,
        ownedIdentity: Identity?,
        prng: PRNGService?
    ): ByteArray? {
        try {
            val identityManagerSession = wrapSession(session)
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(identityManagerSession, ownedIdentity)
            if (ownedIdentityObject == null) {
                throw Exception("Unknown owned identity")
            }
            val privateIdentity = ownedIdentityObject.getPrivateIdentity()
            val signaturePublicKey =
                ownedIdentity!!.serverAuthenticationPublicKey.signaturePublicKey
            val signaturePrivateKey =
                privateIdentity!!.serverAuthenticationPrivateKey.signaturePrivateKey

            val prefix = Constants.getSignatureChallengePrefix(signatureContext!!)
            val padding = prng!!.bytes(Constants.SIGNATURE_PADDING_LENGTH)
            val challenge =
                ByteArray(prefix.size + block!!.size + Constants.SIGNATURE_PADDING_LENGTH)
            System.arraycopy(prefix, 0, challenge, 0, prefix.size)
            System.arraycopy(block, 0, challenge, prefix.size, block.size)
            System.arraycopy(
                padding,
                0,
                challenge,
                prefix.size + block.size,
                Constants.SIGNATURE_PADDING_LENGTH
            )

            val signature = Suite.getSignature(signaturePrivateKey)!!
            val signatureBytes =
                signature.sign(signaturePrivateKey, signaturePublicKey, challenge, prng)!!
            val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
            System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
            System.arraycopy(
                signatureBytes,
                0,
                output,
                Constants.SIGNATURE_PADDING_LENGTH,
                signatureBytes.size
            )
            return output
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    override fun signGroupInvitationNonce(
        session: Session,
        signatureContext: SignatureContext?,
        groupIdentifier: GroupV2.Identifier?,
        nonce: ByteArray,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        prng: PRNGService
    ): ByteArray? {
        try {
            val identityManagerSession = wrapSession(session)
            val ownedIdentityObject: OwnedIdentity =
                OwnedIdentity.get(identityManagerSession, ownedIdentity) ?: throw Exception("Unknown owned identity")
            val privateIdentity = ownedIdentityObject.getPrivateIdentity()
            val signaturePublicKey =
                ownedIdentity!!.serverAuthenticationPublicKey.signaturePublicKey
            val signaturePrivateKey =
                privateIdentity!!.serverAuthenticationPrivateKey.signaturePrivateKey

            val baos = ByteArrayOutputStream()
            baos.write(Constants.getSignatureChallengePrefix(signatureContext!!))
            baos.write(groupIdentifier!!.bytes)
            baos.write(nonce)
            if (contactIdentity != null) {
                baos.write(contactIdentity.getBytes())
            }
            val padding = prng.bytes(Constants.SIGNATURE_PADDING_LENGTH)
            baos.write(padding)
            val challenge = baos.toByteArray()
            baos.close()

            val signature = Suite.getSignature(signaturePrivateKey)!!
            val signatureBytes =
                signature.sign(signaturePrivateKey, signaturePublicKey, challenge, prng)!!
            val output = ByteArray(Constants.SIGNATURE_PADDING_LENGTH + signatureBytes.size)
            System.arraycopy(padding, 0, output, 0, Constants.SIGNATURE_PADDING_LENGTH)
            System.arraycopy(
                signatureBytes,
                0,
                output,
                Constants.SIGNATURE_PADDING_LENGTH,
                signatureBytes.size
            )
            return output
        } catch (e: InvalidKeyException) {
            Logger.x(e)
            return null
        }
    }


    // region groups
    @Throws(Exception::class)
    override fun createContactGroup(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?,
        groupMembers: Array<Identity?>?,
        pendingGroupMembers: Array<IdentityWithSerializedDetails?>?,
        createdByMeOnOtherDevice: Boolean
    ) {
        // check that all members are indeed existing contacts
        for (groupMember in groupMembers!!) {
            if (!isIdentityAContactOfOwnedIdentity(session, ownedIdentity, groupMember)) {
                Logger.e("Error in createContactGroup: a GroupMember is not a Contact.")
                throw Exception()
            }
        }

        val identityManagerSession = wrapSession(session)
        ContactGroup.create(
            identityManagerSession,
            groupInformation!!.getGroupOwnerAndUid(),
            ownedIdentity,
            groupInformation.serializedGroupDetailsWithVersionAndPhoto,
            if (groupInformation.groupOwnerIdentity.equals(ownedIdentity)) null else groupInformation.groupOwnerIdentity,
            createdByMeOnOtherDevice
        )
        for (groupMember in groupMembers) {
            ContactGroupMembersJoin.create(
                identityManagerSession,
                groupInformation.getGroupOwnerAndUid(),
                ownedIdentity,
                groupMember
            )
        }
        for (pendingGroupMember in pendingGroupMembers!!) {
            PendingGroupMember.create(
                identityManagerSession,
                groupInformation.getGroupOwnerAndUid(),
                ownedIdentity,
                pendingGroupMember!!.identity,
                pendingGroupMember.serializedDetails
            )
        }
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
    }

    // only for groups you do not own, when you get kicked, or you leave
    @Throws(Exception::class)
    override fun leaveGroup(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?
    ) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in leaveGroup: group not found")
            throw Exception()
        }
        if (contactGroup.groupOwner == null) {
            Logger.e("Error in leaveGroup: you are the group owner")
            throw Exception()
        }

        contactGroup.delete()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
    }

    // only for groups you own, when disbanding
    @Throws(Exception::class)
    override fun deleteGroup(session: Session, groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in deleteGroup: group not found")
            throw Exception()
        }
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in deleteGroup: you are not the group owner")
            throw Exception()
        }

        contactGroup.delete()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
    }

    // only for groups you own
    @Throws(Exception::class)
    override fun addPendingMembersToGroup(
        session: Session,
        groupUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentities: Array<Identity?>?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    ) {
        // check that the group exists
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in addPendingMembersToGroup: ContactGroup not found.")
            throw Exception()
        }
        // check that you are the owner of the group
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in addPendingMembersToGroup: you are not the owner of the group.")
            throw Exception()
        }

        val group = getGroup(session, ownedIdentity, groupUid)
        // check the contactIdentities are indeed ContactIdentity of the ownedIdentity
        for (contactIdentity in contactIdentities!!) {
            if (!isIdentityAContactOfOwnedIdentity(session, ownedIdentity, contactIdentity)) {
                Logger.e("Error in addPendingMembersToGroup: contactIdentity is not a Contact.")
                throw Exception()
            }
            if (group!!.isMember(contactIdentity) || group.isPendingMember(contactIdentity)) {
                Logger.e("Error in addPendingMembersToGroup: contactIdentity is already in group.")
                throw Exception()
            }
        }
        if (!session.isInTransaction) {
            Logger.e("Called addPendingMembersToGroup outside a transaction")
            throw Exception()
        }
        // create the pending group members
        for (contactIdentity in contactIdentities) {
            val contactSerializedDetails = getSerializedPublishedDetailsOfContactIdentity(
                session,
                ownedIdentity,
                contactIdentity
            )
            PendingGroupMember.create(
                wrapSession(session),
                groupUid,
                ownedIdentity,
                contactIdentity,
                contactSerializedDetails
            )
        }

        // increment the group members version;
        contactGroup.incrementGroupMembersVersion()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        if (groupMembersChangedCallback != null) {
            groupMembersChangedCallback.callback()
        }
    }

    // only for groups you own
    @Throws(Exception::class)
    override fun removeMembersAndPendingFromGroup(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentities: Array<Identity?>?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    ) {
        // check that the group exists
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in removeMembersAndPendingFromGroup: ContactGroup not found.")
            throw Exception()
        }
        // check that you are the owner of the group
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in removeMembersAndPendingFromGroup: you are not the owner of the group.")
            throw Exception()
        }

        val group = getGroup(session, ownedIdentity, groupOwnerAndUid)
        // check the contactIdentities are indeed group members or pending
        for (contactIdentity in contactIdentities!!) {
            if (!group!!.isMember(contactIdentity) && !group.isPendingMember(contactIdentity)) {
                Logger.e("Error in removeMembersAndPendingFromGroup: contactIdentity is not member or pending.")
                throw Exception()
            }
        }

        if (!session.isInTransaction) {
            Logger.e("Called removeMembersAndPendingFromGroup outside a transaction")
            throw Exception()
        }
        // remove the group members
        for (contactIdentity in contactIdentities) {
            val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
                wrapSession(session),
                groupOwnerAndUid,
                ownedIdentity,
                contactIdentity
            )
            if (pendingGroupMember != null) {
                pendingGroupMember.delete()
            }
            val contactGroupMembersJoin: ContactGroupMembersJoin? =
                ContactGroupMembersJoin.get(
                    wrapSession(session),
                    groupOwnerAndUid,
                    ownedIdentity,
                    contactIdentity!!
                )
            if (contactGroupMembersJoin != null) {
                contactGroupMembersJoin.delete()
            }
        }

        // increment the group members version;
        contactGroup.incrementGroupMembersVersion()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        if (groupMembersChangedCallback != null) {
            groupMembersChangedCallback.callback()
        }
    }


    // only for groups you own
    @Throws(Exception::class)
    override fun addGroupMemberFromPendingMember(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    ) {
        // check that the group exists
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in addGroupMemberFromPendingMember: ContactGroup not found.")
            throw Exception()
        }
        // check that you are the owner of the group
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in addGroupMemberFromPendingMember: you are not the owner of the group.")
            throw Exception()
        }
        // check the contactIdentity is indeed a ContactIdentity of the ownedIdentity
        if (!isIdentityAContactOfOwnedIdentity(session, ownedIdentity, contactIdentity)) {
            Logger.e("Error in addGroupMemberFromPendingMember: contactIdentity is not a Contact.")
            throw Exception()
        }
        if (!session.isInTransaction) {
            Logger.e("Called addGroupMemberFromPendingMember outside a transaction")
            throw Exception()
        }
        // remove the pending group member (if present)
        val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
            wrapSession(session),
            groupOwnerAndUid,
            ownedIdentity,
            contactIdentity
        )
        if (pendingGroupMember != null) {
            pendingGroupMember.delete()
        }

        ContactGroupMembersJoin.create(
            wrapSession(session),
            groupOwnerAndUid,
            ownedIdentity,
            contactIdentity
        )

        // increment the group members version;
        contactGroup.incrementGroupMembersVersion()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        if (groupMembersChangedCallback != null) {
            groupMembersChangedCallback.callback()
        }
    }

    // only for groups you own
    @Throws(Exception::class)
    override fun demoteGroupMemberToDeclinedPendingMember(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    ) {
        // check that the group exists
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup == null) {
            Logger.e("Error in demoteGroupMemberToDeclinedPendingMember: ContactGroup not found.")
            throw Exception()
        }
        // check that you are the owner of the group
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in demoteGroupMemberToDeclinedPendingMember: you are not the owner of the group.")
            throw Exception()
        }

        val contactIdentityObject: ContactIdentity? =
            ContactIdentity.get(wrapSession(session), ownedIdentity, contactIdentity)
        // check the contactIdentity is indeed a ContactIdentity of the ownedIdentity
        if (contactIdentityObject == null) {
            Logger.e("Error in demoteGroupMemberToDeclinedPendingMember: contactIdentity is not a Contact.")
            throw Exception()
        }
        if (!session.isInTransaction) {
            Logger.e("Called demoteGroupMemberToDeclinedPendingMember outside a transaction")
            throw Exception()
        }
        // remove the group member (if present)
        val contactGroupMembersJoin: ContactGroupMembersJoin? =
            ContactGroupMembersJoin.get(
                wrapSession(session),
                groupOwnerAndUid,
                ownedIdentity,
                contactIdentity!!
            )
        if (contactGroupMembersJoin != null) {
            contactGroupMembersJoin.delete()
        }

        val pendingGroupMember: PendingGroupMember? = PendingGroupMember.create(
            wrapSession(session),
            groupOwnerAndUid,
            ownedIdentity,
            contactIdentity,
            contactIdentityObject.publishedDetails!!.getSerializedJsonDetails()
        )
        pendingGroupMember!!.setDeclined(true)

        // increment the group members version;
        contactGroup.incrementGroupMembersVersion()
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        if (groupMembersChangedCallback != null) {
            groupMembersChangedCallback.callback()
        }
    }

    @Throws(Exception::class)
    override fun setPendingMemberDeclined(
        session: Session,
        groupUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        declined: Boolean
    ) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupUid, ownedIdentity!!)
        // check that the group exists
        if (contactGroup == null) {
            Logger.e("Error in setPendingMemberDeclined: ContactGroup not found.")
            throw Exception()
        }

        // check that you are group owner
        if (contactGroup.groupOwner != null) {
            Logger.e("Error in setPendingMemberDeclined: you are not the groupOwner.")
            throw Exception()
        }

        // get the pending group member and mark him as "declined"
        val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
            wrapSession(session),
            groupUid,
            ownedIdentity,
            contactIdentity
        )
        if (pendingGroupMember != null) {
            pendingGroupMember.setDeclined(declined)
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }


    @Throws(Exception::class)
    override fun updateGroupMembersAndDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?,
        groupMembers: HashSet<IdentityWithSerializedDetails?>?,
        pendingMembers: HashSet<IdentityWithSerializedDetails?>?,
        membersVersion: Long
    ) {
        if (!session.isInTransaction) {
            Logger.e("Calling updateGroupMembersAndDetails from outside a transaction")
            throw Exception()
        }

        val iAmTheGroupOwner = ownedIdentity!!.equals(groupInformation!!.groupOwnerIdentity)

        val contactGroup: ContactGroup? = ContactGroup.get(
            wrapSession(session),
            groupInformation.getGroupOwnerAndUid(),
            ownedIdentity
        )
        if (contactGroup == null) {
            Logger.w("Error: in updateGroupMembersAndDetails, group not found")
            throw Exception()
        }

        // first, update the details (if needed)
        val jsonGroupDetailsWithVersionAndPhoto =
            jsonObjectMapper.readValue<JsonGroupDetailsWithVersionAndPhoto?>(
                groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                JsonGroupDetailsWithVersionAndPhoto::class.java
            )
        if (contactGroup.updatePublishedDetails(jsonGroupDetailsWithVersionAndPhoto, false)) {
            if (iAmTheGroupOwner) {
                // If I updated the group, auto-trust new details
                contactGroup.trustPublishedDetails()
            }
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }


        // second, update members version number
        if (contactGroup.getGroupMembersVersion() < membersVersion) {
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
            contactGroup.setGroupMembersVersion(membersVersion)

            // group members diff
            val group = getGroup(session, ownedIdentity, groupInformation.getGroupOwnerAndUid())
            if (group == null) {
                Logger.e("A ContactGroup exists but getGroup returned null")
                throw Exception()
            }
            val oldMembers = HashSet<Identity>(Arrays.asList<Identity>(*group.getGroupMembers()))
            val oldPendings = HashSet<IdentityWithSerializedDetails>(
                Arrays.asList<IdentityWithSerializedDetails>(*group.getPendingGroupMembers())
            )

            for (groupMember in groupMembers!!) {
                if (groupMember!!.identity.equals(ownedIdentity)) {
                    continue
                }

                if (oldMembers.contains(groupMember.identity)) {
                    oldMembers.remove(groupMember.identity)
                } else {
                    // we need to add a new member. If he is pending, remove him from pending

                    // remove the pending group member (if present)

                    val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
                        wrapSession(session),
                        groupInformation.getGroupOwnerAndUid(),
                        ownedIdentity,
                        groupMember.identity
                    )
                    if (pendingGroupMember != null) {
                        pendingGroupMember.delete()
                        oldPendings.remove(groupMember)
                    }

                    // create contact if it does not exist
                    val contactIdentityObject: ContactIdentity? = ContactIdentity.get(
                        wrapSession(session),
                        ownedIdentity,
                        groupMember.identity
                    )
                    if (contactIdentityObject == null) {
                        if (ownedIdentity.equals(groupInformation.groupOwnerIdentity)) {
                            // We are forced to create a contact without a contact origin
                            // --> this is not good, but we don't have a choice. A group was created/updated on another device, but we do not know this contact yet...
                            addContactIdentity(
                                session,
                                groupMember.identity,
                                groupMember.serializedDetails,
                                ownedIdentity,
                                null,
                                false
                            )
                        } else {
                            addContactIdentity(
                                session,
                                groupMember.identity,
                                groupMember.serializedDetails,
                                ownedIdentity,
                                createGroupTrustOrigin(
                                    System.currentTimeMillis(), groupInformation.groupOwnerIdentity
                                ),
                                false
                            )
                        }
                    } else if (!ownedIdentity.equals(groupInformation.groupOwnerIdentity)) {
                        addTrustOriginToContact(
                            session, groupMember.identity, ownedIdentity, createGroupTrustOrigin(
                                System.currentTimeMillis(), groupInformation.groupOwnerIdentity
                            ), false
                        )
                    }

                    // add contact to group
                    ContactGroupMembersJoin.create(
                        wrapSession(session),
                        groupInformation.getGroupOwnerAndUid(),
                        ownedIdentity,
                        groupMember.identity
                    )
                }
            }
            // now remove remaining old group members
            for (oldMember in oldMembers) {
                val contactGroupMembersJoin: ContactGroupMembersJoin? =
                    ContactGroupMembersJoin.get(
                        wrapSession(session),
                        groupInformation.getGroupOwnerAndUid(),
                        ownedIdentity,
                        oldMember
                    )
                if (contactGroupMembersJoin != null) {
                    contactGroupMembersJoin.delete()
                }
            }

            // pending members diff
            for (pendingMember in pendingMembers!!) {
                if (oldPendings.contains(pendingMember)) {
                    oldPendings.remove(pendingMember)
                } else {
                    // create a new pending Member
                    PendingGroupMember.create(
                        wrapSession(session),
                        groupInformation.getGroupOwnerAndUid(),
                        ownedIdentity,
                        pendingMember!!.identity,
                        pendingMember.serializedDetails
                    )
                }
            }
            // now remove remaining old pending members
            for (oldPending in oldPendings) {
                val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
                    wrapSession(session),
                    groupInformation.getGroupOwnerAndUid(),
                    ownedIdentity,
                    oldPending.identity
                )
                if (pendingGroupMember != null) {
                    pendingGroupMember.delete()
                }
            }
        }
    }

    @Throws(Exception::class)
    override fun resetGroupMembersAndPublishedDetailsVersions(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?
    ) {
        if (!session.isInTransaction) {
            Logger.e("Calling resetGroupMembersAndPublishedDetailsVersions from outside a transaction")
            throw Exception()
        }

        // this method should only be called for groups you do not own
        if (ownedIdentity!!.equals(groupInformation!!.groupOwnerIdentity)) {
            Logger.w("Error: in resetGroupMembersAndPublishedDetailsVersions, group is owned")
            throw Exception()
        }

        val contactGroup: ContactGroup? = ContactGroup.get(
            wrapSession(session),
            groupInformation.getGroupOwnerAndUid(),
            ownedIdentity
        )
        if (contactGroup == null) {
            Logger.w("Error: in resetGroupMembersAndPublishedDetailsVersions, group not found")
            throw Exception()
        }

        // first, rollback group details (if needed)
        val jsonGroupDetailsWithVersionAndPhoto =
            jsonObjectMapper.readValue<JsonGroupDetailsWithVersionAndPhoto?>(
                groupInformation.serializedGroupDetailsWithVersionAndPhoto,
                JsonGroupDetailsWithVersionAndPhoto::class.java
            )
        contactGroup.updatePublishedDetails(jsonGroupDetailsWithVersionAndPhoto, true)

        // then, set groupMembersVersion to 0 to make sure the next update is taken into account
        contactGroup.setGroupMembersVersion(0)
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
    }

    @Throws(SQLException::class)
    override fun forcefullyRemoveMemberOrPendingFromJoinedGroup(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        contactIdentity: Identity?
    ) {
        val pendingGroupMember: PendingGroupMember? = PendingGroupMember.get(
            wrapSession(session),
            groupOwnerAndUid,
            ownedIdentity,
            contactIdentity
        )
        if (pendingGroupMember != null) {
            pendingGroupMember.delete()
        }
        val contactGroupMembersJoin: ContactGroupMembersJoin? =
            ContactGroupMembersJoin.get(
                wrapSession(session),
                groupOwnerAndUid,
                ownedIdentity!!,
                contactIdentity!!
            )
        contactGroupMembersJoin?.delete()
    }

    @Throws(Exception::class)
    override fun getGroupsForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): Array<GroupWithDetails> {
        if (ownedIdentity == null) {
            throw Exception()
        }
        val contactGroups: Array<ContactGroup> =
            ContactGroup.getAllForIdentity(wrapSession(session), ownedIdentity)
        return contactGroups.map { contactGroup ->
            GroupWithDetails(
                contactGroup.groupOwnerAndUid,
                ownedIdentity,
                ContactGroupMembersJoin.getContactIdentitiesInGroup(
                    wrapSession(session),
                    contactGroup.groupOwnerAndUid,
                    ownedIdentity
                ),
                PendingGroupMember.getPendingMembersInGroup(
                    wrapSession(session),
                    contactGroup.groupOwnerAndUid,
                    ownedIdentity
                ),
                PendingGroupMember.getDeclinedPendingMembersInGroup(
                    wrapSession(session),
                    contactGroup.groupOwnerAndUid,
                    ownedIdentity
                ),
                contactGroup.groupOwner,
                contactGroup.getGroupMembersVersion(),
                contactGroup.publishedDetails!!.jsonGroupDetails,
                contactGroup.latestOrTrustedDetails!!.jsonGroupDetails,
                contactGroup.latestOrTrustedDetails!!.version != contactGroup.publishedDetails!!.version
            )
        }.toTypedArray()
    }

    @Throws(Exception::class)
    override fun getGroup(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): Group? {
        if (ownedIdentity == null || groupOwnerAndUid == null) {
            return null
        }
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity)
        if (contactGroup == null) {
            return null
        }
        @Suppress("UNCHECKED_CAST")
        return Group(
            contactGroup.groupOwnerAndUid,
            ownedIdentity,
            ContactGroupMembersJoin.getContactIdentitiesInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            PendingGroupMember.getPendingMembersInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            PendingGroupMember.getDeclinedPendingMembersInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            contactGroup.groupOwner,
            contactGroup.getGroupMembersVersion()
        )
    }

    @Throws(Exception::class)
    override fun getGroupWithDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): GroupWithDetails? {
        if (ownedIdentity == null || groupOwnerAndUid == null) {
            return null
        }
        val contactGroup: ContactGroup =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity) ?: return null
        @Suppress("UNCHECKED_CAST")
        return GroupWithDetails(
            contactGroup.groupOwnerAndUid,
            ownedIdentity,
            ContactGroupMembersJoin.getContactIdentitiesInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            PendingGroupMember.getPendingMembersInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            PendingGroupMember.getDeclinedPendingMembersInGroup(
                wrapSession(session),
                contactGroup.groupOwnerAndUid,
                ownedIdentity
            ),
            contactGroup.groupOwner,
            contactGroup.getGroupMembersVersion(),
            contactGroup.publishedDetails!!.jsonGroupDetails,
            contactGroup.latestOrTrustedDetails!!.jsonGroupDetails,
            contactGroup.publishedDetails!!
                .version != contactGroup.latestOrTrustedDetails!!.version
        )
    }

    @Throws(Exception::class)
    override fun getGroupInformation(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): GroupInformation? {
        if (ownedIdentity == null || groupOwnerAndUid == null) {
            return null
        }
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity)
        if (contactGroup == null) {
            return null
        }
        return contactGroup.groupInformation
    }

    @Throws(SQLException::class)
    override fun getGroupPublishedAndLatestOrTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): Array<JsonGroupDetailsWithVersionAndPhoto?>? {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            val res: Array<JsonGroupDetailsWithVersionAndPhoto?>?
            if (contactGroup.publishedDetailsVersion == contactGroup.latestOrTrustedDetailsVersion) {
                res = arrayOfNulls<JsonGroupDetailsWithVersionAndPhoto>(1)
                res[0] = contactGroup.publishedDetails!!.jsonGroupDetailsWithVersionAndPhoto
            } else {
                res = arrayOfNulls<JsonGroupDetailsWithVersionAndPhoto>(2)
                res[0] = contactGroup.publishedDetails!!.jsonGroupDetailsWithVersionAndPhoto
                res[1] = contactGroup.latestOrTrustedDetails!!
                    .jsonGroupDetailsWithVersionAndPhoto
            }
            return res
        }
        return null
    }

    @Throws(SQLException::class)
    override fun getGroupPhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): String? {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            if (contactGroup.groupOwner == null) {
                return contactGroup.publishedDetails!!.photoUrl
            } else {
                return contactGroup.latestOrTrustedDetails!!.photoUrl
            }
        }
        return null
    }

    @Throws(SQLException::class)
    override fun trustPublishedGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): JsonGroupDetailsWithVersionAndPhoto? {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            val details = contactGroup.trustPublishedDetails()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
            return details
        }
        return null
    }

    @Throws(Exception::class)
    override fun updateLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        jsonGroupDetails: JsonGroupDetails?
    ) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            contactGroup.setLatestDetails(jsonGroupDetails)
            session.addSessionCommitListener(backupNeededSessionCommitListener)
        }
    }

    @Throws(Exception::class)
    override fun setOwnedGroupDetailsServerLabelAndKey(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        version: Int,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            contactGroup.setPhotoLabelAndKey(version, photoServerLabel!!, photoServerKey)
            if (ServerUserData.createForOwnedGroupDetails(
                    wrapSession(session),
                    ownedIdentity,
                    photoServerLabel,
                    groupOwnerAndUid
                ) == null
            ) {
                throw SQLException()
            }
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        }
    }

    @Throws(SQLException::class)
    override fun createGroupV1ServerUserData(
        session: Session,
        ownedIdentity: Identity?,
        photoServerLabel: UID?,
        groupOwnerAndUid: ByteArray?
    ) {
        if (ServerUserData.createForOwnedGroupDetails(
                wrapSession(session),
                ownedIdentity,
                photoServerLabel,
                groupOwnerAndUid
            ) == null
        ) {
            throw SQLException()
        }
    }

    @Throws(Exception::class)
    override fun updateOwnedGroupPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        absolutePhotoUrl: String?,
        partOfGroupCreation: Boolean
    ) {
        val group: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (group != null) {
            group.setOwnedGroupPhoto(absolutePhotoUrl, partOfGroupCreation)
        }
    }

    @Throws(Exception::class)
    override fun setContactGroupDownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        version: Int,
        photo: ByteArray?
    ) {
        val group: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (group != null) {
            group.setDetailsDownloadedPhotoUrl(version, photo!!)
        }
    }

    @Throws(SQLException::class)
    override fun publishLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): Int {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
            return contactGroup.publishLatestDetails()
        }
        return -1
    }

    @Throws(SQLException::class)
    override fun discardLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ) {
        val contactGroup: ContactGroup? =
            ContactGroup.get(wrapSession(session), groupOwnerAndUid, ownedIdentity!!)
        if (contactGroup != null) {
            contactGroup.discardLatestDetails()
            session.addSessionCommitListener(backupNeededSessionCommitListener)
        }
    }

    override fun getGroupOwnerAndUidOfGroupsWhereContactIsPending(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): Array<ByteArray> {
        return PendingGroupMember.getGroupOwnerAndUidOfGroupsWhereContactIsPending(
            wrapSession(session),
            contactIdentity,
            ownedIdentity,
            false
        )
    }

    @Throws(SQLException::class)
    override fun getGroupOwnerAndUidsOfGroupsContainingContact(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): Array<ByteArray> {
        return ContactGroupMembersJoin.getGroupOwnerAndUidsOfGroupsContainingContact(
            wrapSession(session),
            contactIdentity!!,
            ownedIdentity!!
        )
    }

    override fun refreshMembersOfGroupsOwnedByGroupOwner(
        currentDeviceUid: UID?,
        groupOwner: Identity?
    ) {
        try {
            getSession().use { identityManagerSession ->
                val ownedDevice: OwnedDevice? =
                    OwnedDevice.get(identityManagerSession, currentDeviceUid!!)
                if (ownedDevice == null || !ownedDevice.isCurrentDevice) {
                    return
                }
                val ownedIdentity = ownedDevice.getOwnedIdentity()
                val groupOwnerAndUids: Array<ByteArray?> =
                    ContactGroup.getGroupOwnerAndUidsOfGroupsOwnedByContact(
                        identityManagerSession,
                        ownedIdentity,
                        groupOwner!!
                    )
                for (groupOwnerAndUid in groupOwnerAndUids) {
                    try {
                        protocolStarterDelegate!!.queryGroupMembers(groupOwnerAndUid, ownedIdentity)
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun pushMembersOfOwnedGroupsToContact(
        currentDeviceUid: UID?,
        contactIdentity: Identity?
    ) {
        try {
            getSession().use { identityManagerSession ->
                val ownedDevice: OwnedDevice? =
                    OwnedDevice.get(identityManagerSession, currentDeviceUid!!)
                if (ownedDevice == null || !ownedDevice.isCurrentDevice) {
                    return
                }
                val ownedIdentity = ownedDevice.getOwnedIdentity()
                run {
                    val groupOwnerAndUids: Array<ByteArray?> =
                        ContactGroup.getGroupOwnerAndUidsOfOwnedGroupsWithContact(
                            identityManagerSession,
                            ownedIdentity,
                            contactIdentity!!
                        )
                    for (groupOwnerAndUid in groupOwnerAndUids) {
                        try {
                            protocolStarterDelegate!!.reinviteAndPushMembersToContact(
                                groupOwnerAndUid,
                                ownedIdentity,
                                contactIdentity
                            )
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }
                }
                run {
                    val groupOwnerAndUids: Array<ByteArray> =
                        PendingGroupMember.getGroupOwnerAndUidOfGroupsWhereContactIsPending(
                            identityManagerSession,
                            contactIdentity,
                            ownedIdentity,
                            true
                        )
                    for (groupOwnerAndUid in groupOwnerAndUids) {
                        try {
                            protocolStarterDelegate!!.reinvitePendingToGroup(
                                groupOwnerAndUid,
                                ownedIdentity,
                                contactIdentity
                            )
                        } catch (e: Exception) {
                            Logger.x(e)
                        }
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }


    // endregion
    // region Groups v2
    @Throws(Exception::class)
    override fun createNewGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        serverPhotoInfo: ServerPhotoInfo?,
        verifiedAdministratorsChain: ByteArray?,
        blobKeys: BlobKeys?,
        ownGroupInvitationNonce: ByteArray?,
        ownPermissionStrings: MutableList<String?>?,
        otherGroupMembers: HashSet<IdentityAndPermissionsAndDetails?>?,
        serializedGroupType: String?
    ) {
        if (!ownPermissionStrings!!.contains(GroupV2.Permission.GROUP_ADMIN.string)) {
            Logger.e("Error in createNewContactGroupV2: ownPermissions do not contain GROUP_ADMIN.")
            throw Exception()
        }
        for (groupMember in otherGroupMembers!!) {
            if (!isIdentityAContactOfOwnedIdentity(session, ownedIdentity, groupMember!!.identity)) {
                Logger.e("Error in createNewContactGroupV2: a groupMember is not a Contact.")
                throw Exception()
            }
            if (!getContactCapabilities(
                    wrapSession(session),
                    ownedIdentity!!,
                    groupMember.identity
                ).contains(ObvCapability.GROUPS_V2)
            ) {
                Logger.e("Error in createNewContactGroupV2: a groupMember does not have groupV2 capability.")
                throw Exception()
            }
        }

        val identityManagerSession = wrapSession(session)
        val group: ContactGroupV2? = ContactGroupV2.createNew(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            serializedGroupDetails,
            absolutePhotoUrl,
            serverPhotoInfo,
            verifiedAdministratorsChain,
            blobKeys,
            ownGroupInvitationNonce,
            ownPermissionStrings,
            serializedGroupType
        )
        if (group == null) {
            throw Exception("Unable to create ContactGroupV2")
        }
        // if any, add the user data to the ServerUserData
        if (serverPhotoInfo != null) {
            if (ServerUserData.createForGroupV2(
                    identityManagerSession,
                    ownedIdentity,
                    serverPhotoInfo.serverPhotoLabel,
                    groupIdentifier!!.encode().bytes
                ) == null
            ) {
                throw Exception("Unable to create ServerUserData")
            }
        }

        // add pending group members
        for (groupMember in otherGroupMembers) {
            val pendingMember: ContactGroupV2PendingMember? =
                ContactGroupV2PendingMember.create(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    groupMember!!.identity,
                    groupMember.serializedIdentityDetails,
                    groupMember.permissionStrings,
                    groupMember.groupInvitationNonce
                )

            if (pendingMember == null) {
                throw Exception("Unable to create ContactGroupV2PendingMember")
            }
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
    }

    @Throws(Exception::class)
    override fun createJoinedGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        blobKeys: BlobKeys?,
        serverBlob: ServerBlob?,
        createdByMeOnOtherDevice: Boolean,
        inviterIdentity: Identity?,
        groupUpdateTimestamp: Long?
    ): Boolean {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) || (serverBlob == null)) {
            throw Exception()
        }

        if (!session.isInTransaction) {
            throw SQLException("Called IdentityManager.createJoinedGroupV2 outside of a transaction!")
        }

        val identityManagerSession = wrapSession(session)

        if (ContactGroupV2.get(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier
            ) != null
        ) {
            Logger.e("Called IdentityManager.createJoinedGroupV2 for an existing group!")
            return false
        }

        if (!serverBlob.administratorsChain.integrityWasChecked) {
            Logger.e("In IdentityManager.createJoinedGroupV2, serverBlob.administratorsChain has integrityWasChecked false")
            return false
        }

        // check I am member of the group
        var ownIdentityAndPermissionsAndDetails: IdentityAndPermissionsAndDetails? = null
        for (identityAndPermissionsAndDetails in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
            if (identityAndPermissionsAndDetails.identity.equals(ownedIdentity)) {
                ownIdentityAndPermissionsAndDetails = identityAndPermissionsAndDetails
                break
            }
        }
        if (ownIdentityAndPermissionsAndDetails == null) {
            Logger.e("In IdentityManager.createJoinedGroupV2, ownedIdentity not part of the group")
            return false
        }

        val group: ContactGroupV2? = ContactGroupV2.createJoined(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            serverBlob.version,
            serverBlob.serializedGroupDetails,
            serverBlob.serverPhotoInfo,
            serverBlob.administratorsChain.encode().bytes,
            blobKeys,
            ownIdentityAndPermissionsAndDetails.groupInvitationNonce,
            @Suppress("UNCHECKED_CAST")
            (ownIdentityAndPermissionsAndDetails.permissionStrings as MutableList<String?>),
            serverBlob.serializedGroupType,
            createdByMeOnOtherDevice,
            inviterIdentity,
            groupUpdateTimestamp
        )
        if (group == null) {
            throw Exception("Unable to create joined ContactGroupV2")
        }
        for (groupMember in serverBlob.groupMemberIdentityAndPermissionsAndDetailsList) {
            if (groupMember.identity.equals(ownedIdentity)) {
                continue
            }

            val pendingMember: ContactGroupV2PendingMember? =
                ContactGroupV2PendingMember.create(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    groupMember.identity,
                    groupMember.serializedIdentityDetails,
                    groupMember.permissionStrings,
                    groupMember.groupInvitationNonce
                )

            if (pendingMember == null) {
                throw Exception("Unable to create ContactGroupV2PendingMember")
            }
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        return true
    }

    @Throws(SQLException::class)
    override fun getGroupV2ServerBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ServerBlob? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return null
        }

        return ContactGroupV2.getServerBlob(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier
        )
    }

    @Throws(SQLException::class)
    override fun getGroupV2PhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): String? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }

        return ContactGroupV2.getPhotoUrl(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier
        )
    }

    @Throws(SQLException::class)
    override fun deleteGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        deletedBy: Identity?
    ) {
        if (groupIdentifier == null) {
            return
        }
        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 != null) {
            groupV2.setDeletedBy(deletedBy)
            groupV2.delete()
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity!!))
    }

    @Throws(SQLException::class)
    override fun freezeGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return
        }
        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 != null) {
            groupV2.setFrozen(true)
        }
    }

    @Throws(SQLException::class)
    override fun unfreezeGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ) {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return
        }
        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 != null) {
            groupV2.setFrozen(false)
        }
    }

    @Throws(SQLException::class)
    override fun getGroupV2Version(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Int? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null
        return groupV2.version
    }

    @Throws(SQLException::class)
    override fun getGroupV2JsonGroupType(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): String? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null
        return groupV2.serializedJsonGroupType
    }

    @Throws(SQLException::class)
    override fun isGroupV2Frozen(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return false
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return false
        return groupV2.isFrozen()
    }

    @Throws(SQLException::class)
    override fun getGroupV2BlobKeys(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): BlobKeys? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return null
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null
        return BlobKeys(
            groupV2.blobMainSeed,
            groupV2.blobVersionSeed,
            groupV2.groupAdminServerAuthenticationPrivateKey
        )
    }

    @Throws(Exception::class)
    override fun getGroupV2OtherMembersAndPermissions(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): HashSet<IdentityAndPermissions?>? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        return ContactGroupV2.getGroupV2OtherMembersAndPermissions(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier
        )
    }

    @Throws(Exception::class)
    override fun getGroupV2HasOtherAdminMember(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            throw Exception()
        }
        return ContactGroupV2.getGroupV2HasOtherAdminMember(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier
        )
    }

    @Throws(SQLException::class)
    override fun updateGroupV2WithNewBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverBlob: ServerBlob?,
        blobKeys: BlobKeys?,
        updatedByMe: Boolean,
        updatedBy: Identity?,
        leavers: MutableList<Identity?>?,
        groupUpdateTimestamp: Long?
    ): MutableList<Identity?>? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) || (serverBlob == null) || (blobKeys == null)) {
            return null
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))

        return groupV2.updateWithNewBlob(
            serverBlob,
            blobKeys,
            updatedByMe,
            updatedBy,
            leavers,
            groupUpdateTimestamp
        )
    }

    @Throws(Exception::class)
    override fun getGroupV2MembersAndPendingMembersFromNonce(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        groupMemberInvitationNonce: ByteArray?
    ): MutableList<Identity?>? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupMemberInvitationNonce == null)) {
            return null
        }
        return ContactGroupV2.getGroupV2MembersAndPendingMembersFromNonce(
            wrapSession(
                session
            ), ownedIdentity, groupIdentifier, groupMemberInvitationNonce
        )
    }

    @Throws(SQLException::class)
    override fun getGroupV2OwnGroupInvitationNonce(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ByteArray? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null

        return groupV2.ownGroupInvitationNonce
    }

    @Throws(Exception::class)
    override fun moveGroupV2PendingMemberToMembers(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        groupMemberIdentity: Identity?
    ) {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupMemberIdentity == null)) {
            return
        }
        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return

        groupV2.movePendingMemberToMembers(groupMemberIdentity)

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
    }

    @Throws(Exception::class)
    override fun setGroupV2DownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverPhotoInfo: ServerPhotoInfo?,
        photo: ByteArray?
    ) {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (serverPhotoInfo == null) || (photo == null)) {
            return
        }

        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return

        groupV2.setDownloadedPhotoUrl(ownedIdentity, serverPhotoInfo, photo)
    }

    @Throws(Exception::class)
    override fun getObvGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ObvGroupV2? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }

        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return null

        return groupV2toObvGroupV2(wrapSession(session), ownedIdentity, groupIdentifier, groupV2)
    }

    @Throws(SQLException::class)
    override fun trustGroupV2PublishedDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Int {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return -1
        }

        val groupV2: ContactGroupV2 =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier) ?: return -1
        val trustedVersion = groupV2.getTrustedDetailsVersion()
        if (trustedVersion != groupV2.version) {
            groupV2.setTrustedDetailsVersion(groupV2.version)
            ContactGroupV2Details.cleanup(
                wrapSession(session),
                ownedIdentity,
                groupIdentifier,
                groupV2.version,
                groupV2.version
            )
        }
        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        return groupV2.version
    }

    // only for CATEGORY_SERVER groups. This is only used for UserData management
    override fun getGroupV2PublishedServerPhotoInfo(
        session: Session,
        ownedIdentity: Identity?,
        bytesGroupIdentifier: ByteArray?
    ): ServerPhotoInfo? {
        if ((ownedIdentity == null) || (bytesGroupIdentifier == null)) {
            return null
        }
        try {
            val groupIdentifier = GroupV2.Identifier.of(bytesGroupIdentifier)
            if (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
                return null
            }
            return ContactGroupV2.getServerPhotoInfo(
                wrapSession(session),
                ownedIdentity,
                groupIdentifier
            )
        } catch (e: Exception) {
            Logger.x(e)
        }
        return null
    }

    override fun getGroupV2DetailsAndPhotos(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ObvGroupV2DetailsAndPhotos? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        try {
            val groupV2: ContactGroupV2? =
                ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
            if (groupV2 == null) {
                return null
            }

            val trustedDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                wrapSession(session),
                ownedIdentity,
                groupIdentifier,
                groupV2.getTrustedDetailsVersion()
            )
            if (trustedDetails == null) {
                return null
            }

            val serializedGroupDetails = trustedDetails.serializedJsonDetails
            var photoUrl = trustedDetails.getPhotoUrl()
            if (photoUrl == null && trustedDetails.serverPhotoInfo != null) { // photo not downloaded yet
                photoUrl = ""
            }

            val serializedPublishedDetails: String?
            var publishedPhotoUrl: String?
            if (groupV2.version != groupV2.getTrustedDetailsVersion()) {
                val publishedDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                    wrapSession(session),
                    ownedIdentity,
                    groupIdentifier,
                    groupV2.version
                )
                if (publishedDetails == null) {
                    return null
                }
                serializedPublishedDetails = publishedDetails.serializedJsonDetails
                publishedPhotoUrl = publishedDetails.getPhotoUrl()
                if (publishedPhotoUrl == null && publishedDetails.serverPhotoInfo != null) { // photo not downloaded yet
                    publishedPhotoUrl = ""
                }
            } else {
                serializedPublishedDetails = null
                publishedPhotoUrl = null
            }

            return ObvGroupV2DetailsAndPhotos(
                serializedGroupDetails!!,
                photoUrl,
                serializedPublishedDetails,
                publishedPhotoUrl
            )
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    override fun setUpdatedGroupV2PhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        version: Int,
        absolutePhotoUrl: String?
    ) {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (absolutePhotoUrl == null)) {
            return
        }

        val details: ContactGroupV2Details? = ContactGroupV2Details.get(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier,
            version
        )
        if (details == null) {
            return
        }

        details.setAbsolutePhotoUrl(absolutePhotoUrl)
    }

    @Throws(Exception::class)
    override fun getGroupV2AdministratorsChain(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): AdministratorsChain? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return null
        }
        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 == null) {
            return null
        }

        val serializedAdministratorsChain = groupV2.verifiedAdministratorsChain

        return AdministratorsChain.of(Encoded(serializedAdministratorsChain!!))
    }

    @Throws(Exception::class)
    override fun getGroupV2AdminStatus(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK)) {
            return false
        }
        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 == null) {
            return false
        }

        return groupV2.ownPermissionStrings.contains(GroupV2.Permission.GROUP_ADMIN.string)
    }

    @Throws(Exception::class)
    override fun getObvGroupsV2ForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<ObvGroupV2> {
        if (ownedIdentity == null) {
            throw Exception()
        }

        val identityManagerSession = wrapSession(session)
        val groupsV2: MutableList<ContactGroupV2?> =
            ContactGroupV2.getAllForIdentity(identityManagerSession, ownedIdentity)

        val obvGroupsV2: MutableList<ObvGroupV2> = ArrayList()
        for (groupV2 in groupsV2) {
            val obvGroupV2: ObvGroupV2? = groupV2toObvGroupV2(
                identityManagerSession,
                ownedIdentity,
                groupV2!!.groupIdentifier,
                groupV2
            )
            if (obvGroupV2 != null) {
                obvGroupsV2.add(obvGroupV2)
            }
        }
        return obvGroupsV2
    }

    @Throws(Exception::class)
    override fun getServerGroupsV2IdentifierVersionAndKeysForContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<IdentifierVersionAndKeys?> {
        if (ownedIdentity == null || contactIdentity == null) {
            throw Exception()
        }

        return ContactGroupV2.getServerGroupsV2IdentifierVersionAndKeysForContact(
            wrapSession(session),
            ownedIdentity,
            contactIdentity
        )
    }


    @Throws(Exception::class)
    override fun getAllServerGroupsV2IdentifierVersionAndKeys(
        session: Session,
        ownedIdentity: Identity?
    ): Array<IdentifierVersionAndKeys?>? {
        if (ownedIdentity == null) {
            throw Exception()
        }

        return ContactGroupV2.getAllServerGroupsV2IdentifierVersionAndKeys(
            wrapSession(
                session
            ), ownedIdentity
        )
    }


    @Throws(Exception::class)
    override fun getServerGroupsV2IdentifierAndMyAdminStatusForContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<IdentifierAndAdminStatus?>? {
        if (ownedIdentity == null || contactIdentity == null) {
            throw Exception()
        }

        return ContactGroupV2.getServerGroupsV2IdentifierAndMyAdminStatusForContact(
            wrapSession(session),
            ownedIdentity,
            contactIdentity
        )
    }


    override fun initiateGroupV2BatchKeysResend(
        currentDeviceUid: UID?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ) {
        if (contactIdentity == null || contactDeviceUid == null) {
            return
        }

        try {
            getSession().use { identityManagerSession ->
                val ownedIdentity = getOwnedIdentityForCurrentDeviceUid(
                    identityManagerSession.session,
                    currentDeviceUid
                )
                if (ownedIdentity == null) {
                    return
                }
                try {
                    protocolStarterDelegate!!.initiateGroupV2BatchKeysResend(
                        identityManagerSession.session,
                        ownedIdentity,
                        contactIdentity,
                        contactDeviceUid
                    )
                    identityManagerSession.session.commit()
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    @Throws(SQLException::class)
    override fun forcefullyRemoveMemberOrPendingFromNonAdminGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        contactIdentity: Identity?
    ) {
        val contactGroupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (contactGroupV2 != null) {
            if (groupIdentifier!!.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
                moveKeycloakMemberToPendingMember(
                    wrapSession(session),
                    groupIdentifier,
                    ownedIdentity!!,
                    contactIdentity!!,
                    null
                )
            } else {
                contactGroupV2.triggerUpdateNotification()
                val pendingMember: ContactGroupV2PendingMember? =
                    ContactGroupV2PendingMember.get(
                        wrapSession(session),
                        ownedIdentity,
                        groupIdentifier,
                        contactIdentity
                    )
                if (pendingMember != null) {
                    pendingMember.delete()
                }
                val member: ContactGroupV2Member? = ContactGroupV2Member.get(
                    wrapSession(session),
                    ownedIdentity,
                    groupIdentifier,
                    contactIdentity
                )
                if (member != null) {
                    member.delete()
                }
            }
        }
    }

    @Throws(SQLException::class)
    override fun getGroupV2LastModificationTimestamp(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Long? {
        if ((ownedIdentity == null) || (groupIdentifier == null)) {
            return null
        }
        return ContactGroupV2.getLastModificationTimestamp(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier
        )
    }

    override fun createKeycloakGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        keycloakGroupBlob: KeycloakGroupBlob?
    ): ByteArray? {
        if (ownedIdentity == null || groupIdentifier == null || groupIdentifier.category != GroupV2.Identifier.CATEGORY_KEYCLOAK || keycloakGroupBlob == null) {
            return null
        }

        try {
            val identityManagerSession = wrapSession(session)

            // first, find my own permissions and invitation nonce in the groupMembersAndPermissions set
            var ownInvitationNonce: ByteArray? = null
            var ownPermissions: MutableList<String?>? = null
            val otherMembers: MutableList<KeycloakGroupMemberAndPermissions> =
                ArrayList<KeycloakGroupMemberAndPermissions>()

            for (groupMemberAndPermissions in keycloakGroupBlob.groupMembersAndPermissions!!) {
                if (ownedIdentity.getBytes().contentEquals(groupMemberAndPermissions!!.identity)) {
                    ownInvitationNonce = groupMemberAndPermissions.groupInvitationNonce
                    ownPermissions = groupMemberAndPermissions.permissions
                } else {
                    otherMembers.add(groupMemberAndPermissions)
                }
            }


            var serverPhotoInfo: ServerPhotoInfo? = null
            val blobPhotoUid = keycloakGroupBlob.photoUid
            val blobEncodedPhotoKey = keycloakGroupBlob.encodedPhotoKey
            if (blobPhotoUid != null && blobEncodedPhotoKey != null) {
                try {
                    val photoUid = UID(blobPhotoUid)
                    val photoKey =
                        Encoded(blobEncodedPhotoKey).decodeSymmetricKey() as AuthEncKey?
                    serverPhotoInfo = ServerPhotoInfo(null, photoUid, photoKey!!)
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            val groupV2: ContactGroupV2? = ContactGroupV2.createKeycloak(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                jsonObjectMapper.writeValueAsString(keycloakGroupBlob.groupDetails),
                serverPhotoInfo,
                ownInvitationNonce,
                ownPermissions,
                keycloakGroupBlob.pushTopic,
                keycloakGroupBlob.serializedSharedSettings,
                keycloakGroupBlob.timestamp
            )

            if (groupV2 == null) {
                throw Exception("Called createKeycloakGroupV2 and group already exists")
            }

            val noVerificationConsumer = JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build()

            for (groupMemberAndPermissions in otherMembers) {
                try {
                    // the signedUserDetails contained in the KeycloakGroupMemberAndPermissions are a JWT, containing the "raw" details
                    // we deserialize these raw details and enrich them with the signed details
                    val serializedUnsignedDetails =
                        noVerificationConsumer.processToClaims(groupMemberAndPermissions.signedUserDetails)
                            .getRawJson()
                    val jsonKeycloakUserDetails =
                        jsonObjectMapper.readValue<JsonKeycloakUserDetails>(
                            serializedUnsignedDetails,
                            JsonKeycloakUserDetails::class.java
                        )
                    val jsonIdentityDetails =
                        jsonKeycloakUserDetails.getIdentityDetails(groupMemberAndPermissions.signedUserDetails)
                    val serializedIdentityDetails =
                        jsonObjectMapper.writeValueAsString(jsonIdentityDetails)

                    val groupMemberIdentity = Identity.of(groupMemberAndPermissions.identity!!)

                    val pendingMember: ContactGroupV2PendingMember? =
                        ContactGroupV2PendingMember.create(
                            identityManagerSession,
                            ownedIdentity,
                            groupIdentifier,
                            groupMemberIdentity,
                            serializedIdentityDetails,
                            @Suppress("UNCHECKED_CAST")
                            (groupMemberAndPermissions.permissions as MutableCollection<String>?),
                            groupMemberAndPermissions.groupInvitationNonce
                        )

                    if (pendingMember == null) {
                        throw Exception("Unable to create ContactGroupV2PendingMember")
                    }
                } catch (e: InvalidJwtException) {
                    Logger.w("Unable to process one keycloak group member --> skipping them")
                    Logger.x(e)
                } catch (e: JsonProcessingException) {
                    Logger.w("Unable to process one keycloak group member --> skipping them")
                    Logger.x(e)
                }
            }

            val capturedSerializedSharedSettings = keycloakGroupBlob.serializedSharedSettings
            if (capturedSerializedSharedSettings != null) {
                session.addSessionCommitListener {
                    val userInfo = HashMap<String, Any>()
                    userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_OWNED_IDENTITY_KEY] =
                        ownedIdentity
                    userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_GROUP_IDENTIFIER_KEY] =
                        groupIdentifier
                    userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SERIALIZED_SHARED_SETTINGS_KEY] =
                        capturedSerializedSharedSettings
                    userInfo[IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY] =
                        keycloakGroupBlob.timestamp
                    notificationPostingDelegate?.postNotification(
                        IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS,
                        userInfo
                    )
                }
            }

            session.addSessionCommitListener(backupNeededSessionCommitListener)
            session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
            return ownInvitationNonce
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    override fun updateKeycloakGroupV2WithNewBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        keycloakGroupBlob: KeycloakGroupBlob?
    ): KeycloakGroupV2UpdateOutput? {
        if ((ownedIdentity == null) || (groupIdentifier == null) || (groupIdentifier.category != GroupV2.Identifier.CATEGORY_KEYCLOAK) || (keycloakGroupBlob == null)) {
            return null
        }

        if (!session.isInTransaction) {
            throw SQLException("Calling updateKeycloakGroupV2WithNewBlob outside a transaction!")
        }

        val groupV2: ContactGroupV2? =
            ContactGroupV2.get(wrapSession(session), ownedIdentity, groupIdentifier)
        if (groupV2 == null) {
            return null
        }

        session.addSessionCommitListener(backupNeededSessionCommitListener)
        session.addSessionCommitListener(getSessionCommitListenerForProfileBackup(ownedIdentity))
        return groupV2.updateWithNewKeycloakBlob(keycloakGroupBlob, jsonObjectMapper)
    }

    @Throws(SQLException::class)
    override fun rePingOrDemoteContactFromAllKeycloakGroups(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        certifiedByOwnKeycloak: Boolean,
        lastKnownSerializedCertifiedDetails: String?
    ) {
        if ((ownedIdentity == null) || (contactIdentity == null)) {
            return
        }
        val identityManagerSession = wrapSession(session)

        if (certifiedByOwnKeycloak) {
            val groupIdentifiers: MutableList<GroupV2.Identifier?>? =
                ContactGroupV2PendingMember.getKeycloakGroupV2IdentifiersWhereContactIsPending(
                    identityManagerSession,
                    ownedIdentity,
                    contactIdentity
                )
            if (groupIdentifiers != null) {
                for (groupIdentifier in groupIdentifiers) {
                    try {
                        protocolStarterDelegate!!.initiateKeycloakGroupV2TargetedPing(
                            session,
                            ownedIdentity,
                            groupIdentifier,
                            contactIdentity
                        )
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            }
        } else {
            val groupIdentifiers: MutableList<GroupV2.Identifier?>? =
                ContactGroupV2Member.getKeycloakGroupV2IdentifiersWhereContactIsMember(
                    identityManagerSession,
                    ownedIdentity,
                    contactIdentity
                )
            if (groupIdentifiers != null) {
                for (groupIdentifier in groupIdentifiers) {
                    try {
                        moveKeycloakMemberToPendingMember(
                            identityManagerSession,
                            groupIdentifier!!,
                            ownedIdentity,
                            contactIdentity,
                            lastKnownSerializedCertifiedDetails
                        )
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }
            }
        }
    }

    @Throws(SQLException::class)
    private fun moveKeycloakMemberToPendingMember(
        identityManagerSession: IdentityManagerSession,
        groupIdentifier: GroupV2.Identifier,
        ownedIdentity: Identity,
        groupMemberIdentity: Identity,
        lastKnownSerializedCertifiedDetails: String?
    ) {
        if (groupIdentifier.category != GroupV2.Identifier.CATEGORY_KEYCLOAK) {
            return
        }

        val member: ContactGroupV2Member? = ContactGroupV2Member.get(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            groupMemberIdentity
        )
        val serializedPublishedDetails: String? =
            if (lastKnownSerializedCertifiedDetails == null) ContactIdentity.getSerializedPublishedDetails(
                identityManagerSession,
                ownedIdentity,
                groupMemberIdentity
            ) else lastKnownSerializedCertifiedDetails
        if (member == null || serializedPublishedDetails == null) {
            return
        }

        var pendingMember: ContactGroupV2PendingMember? = ContactGroupV2PendingMember.get(
            identityManagerSession,
            ownedIdentity,
            groupIdentifier,
            groupMemberIdentity
        )
        if (pendingMember == null) { // this should always be the case
            // crate the ContactGroupV2PendingMember
            pendingMember = ContactGroupV2PendingMember.create(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                groupMemberIdentity,
                serializedPublishedDetails,
                @Suppress("UNCHECKED_CAST")
                (deserializePermissions(member.serializedPermissions) as MutableCollection<String>?),
                member.getGroupInvitationNonce()
            )

            if (pendingMember == null) {
                throw SQLException("In IdentityManager.moveKeycloakMemberToPendingMember, failed to create ContactGroupV2PendingMember")
            }
        }

        // delete the member
        member.delete()

        identityManagerSession.session.addSessionCommitListener(SessionCommitListener {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_GROUP_IDENTIFIER_KEY,
                groupIdentifier
            )
            userInfo.put(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_BY_ME_KEY, false)
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED,
                userInfo
            )
        })
    }

    // return true only if the identity is a PendingMember: if it is a GroupMember, it returns false
    @Throws(SQLException::class)
    override fun isIdentityAPendingGroupV2Member(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        identity: Identity?
    ): Boolean {
        if (ownedIdentity == null || groupIdentifier == null || identity == null) {
            return false
        }

        return ContactGroupV2PendingMember.get(
            wrapSession(session),
            ownedIdentity,
            groupIdentifier,
            identity
        ) != null
    }


    // endregion
    // region backup
    override fun initiateBackup(
        backupDelegate: BackupDelegate?,
        tag: String?,
        backupKeyUid: UID?,
        version: Int
    ) {
        Thread(Runnable {
            try {
                getSession().use { identityManagerSession ->
                    val ownedIdentityPojos: Array<OwnedIdentity.Pojo_0?> =
                        OwnedIdentity.backupAll(identityManagerSession)
                    if (ownedIdentityPojos.size == 0) {
                        // no active identity --> abort backup
                        backupDelegate!!.backupFailed(tag, backupKeyUid!!, version)
                        return@Runnable
                    }
                    val jsonString = jsonObjectMapper.writeValueAsString(ownedIdentityPojos)
                    backupDelegate!!.backupSuccess(tag, backupKeyUid!!, version, jsonString)
                }
            } catch (e: SQLException) {
                Logger.x(e)
                backupDelegate!!.backupFailed(tag, backupKeyUid!!, version)
            } catch (e: JsonProcessingException) {
                Logger.x(e)
                backupDelegate!!.backupFailed(tag, backupKeyUid!!, version)
            }
        }, "Identity Backup").start()
    }

    override fun restoreOwnedIdentitiesFromBackup(
        serializedJsonPojo: String?,
        deviceDisplayName: String?,
        prng: PRNGService?
    ): Array<ObvIdentity?>? {
        try {
            getSession().use { identityManagerSession ->
                /**///////////// */
                // If an ownedIdentity already exists, we abort
                /**///////////// */
                val ownedIdentities: Array<OwnedIdentity> = OwnedIdentity.getAll(identityManagerSession)
                if (ownedIdentities.isNotEmpty()) {
                    Logger.e("Trying to restore a backup while an OwnedIdentity already exists. Aborting.")
                    return arrayOfNulls(0)
                }

                /**////////////// */
                val restoredIdentities: MutableList<ObvIdentity?> = ArrayList()
                val ownedIdentityPojos: Array<OwnedIdentity.Pojo_0?>? =
                    jsonObjectMapper.readValue<Array<OwnedIdentity.Pojo_0?>?>(
                        serializedJsonPojo,
                        object : TypeReference<Array<OwnedIdentity.Pojo_0?>?>() {})

                identityManagerSession.session.startTransaction()
                for (ownedIdentityPojo in ownedIdentityPojos!!) {
                    restoredIdentities.add(
                        OwnedIdentity.restore(
                            identityManagerSession,
                            ownedIdentityPojo!!,
                            deviceDisplayName,
                            prng
                        )
                    )
                }
                identityManagerSession.session.commit()
                return restoredIdentities.toTypedArray<ObvIdentity?>()
            }
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun restoreContactsAndGroupsFromBackup(
        serializedJsonPojo: String?,
        restoredOwnedIdentities: Array<ObvIdentity?>?,
        backupTimestamp: Long
    ) {
        val restoredIdentities: MutableSet<Identity?> = HashSet()
        for (obvOwnedIdentity in restoredOwnedIdentities!!) {
            restoredIdentities.add(obvOwnedIdentity!!.getIdentity())
        }

        try {
            getSession().use { identityManagerSession ->
                val ownedIdentityPojos: Array<OwnedIdentity.Pojo_0?>? =
                    jsonObjectMapper.readValue<Array<OwnedIdentity.Pojo_0?>?>(
                        serializedJsonPojo,
                        object : TypeReference<Array<OwnedIdentity.Pojo_0?>?>() {})
                for (ownedIdentityPojo in ownedIdentityPojos!!) {
                    val ownedIdentity = Identity.of(ownedIdentityPojo!!.owned_identity!!)
                    if (!restoredIdentities.contains(ownedIdentity)) {
                        continue
                    }

                    @Suppress("UNCHECKED_CAST")
                    ContactIdentity.restoreAll(
                        identityManagerSession,
                        ownedIdentity,
                        ownedIdentityPojo.contact_identities as Array<ContactIdentity.Pojo_0>?,
                        backupTimestamp
                    )
                    @Suppress("UNCHECKED_CAST")
                    ContactGroup.restoreAllForOwner(
                        identityManagerSession,
                        ownedIdentity,
                        ownedIdentity,
                        ownedIdentityPojo.owned_groups as Array<ContactGroup.Pojo_0>?,
                        backupTimestamp
                    )
                    @Suppress("UNCHECKED_CAST")
                    ContactGroupV2.restoreAll(
                        identityManagerSession,
                        protocolStarterDelegate!!,
                        ownedIdentity,
                        ownedIdentityPojo.groups_v2 as Array<ContactGroupV2.Pojo_0>?
                    )
                }
                for (obvOwnedIdentity in restoredOwnedIdentities) {
                    if (obvOwnedIdentity!!.isActive()) {
                        reactivateOwnedIdentityIfNeeded(
                            identityManagerSession.session,
                            obvOwnedIdentity.getIdentity()
                        )
                    }
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    // endregion
    // region userData
    @Throws(Exception::class)
    override fun getAllUserData(session: Session): Array<UserData?> {
        val serverUserData: Array<ServerUserData?> =
            ServerUserData.getAll(wrapSession(session))
        val userData = arrayOfNulls<UserData>(serverUserData.size)
        for (i in serverUserData.indices) {
            userData[i] = serverUserData[i]!!.userData
        }
        return userData
    }

    @Throws(Exception::class)
    override fun getUserData(session: Session, ownedIdentity: Identity?, label: UID?): UserData? {
        val serverUserData: ServerUserData? =
            ServerUserData.get(wrapSession(session), ownedIdentity!!, label!!)
        if (serverUserData != null) {
            return serverUserData.userData
        }
        return null
    }

    @Throws(Exception::class)
    override fun deleteUserData(session: Session, ownedIdentity: Identity?, label: UID?) {
        val serverUserData: ServerUserData? =
            ServerUserData.get(wrapSession(session), ownedIdentity!!, label!!)
        serverUserData?.delete()
    }

    @Throws(Exception::class)
    override fun updateUserDataNextRefreshTimestamp(
        session: Session,
        ownedIdentity: Identity?,
        label: UID?
    ) {
        val serverUserData: ServerUserData? =
            ServerUserData.get(wrapSession(session), ownedIdentity!!, label!!)
        serverUserData?.updateNextRefreshTimestamp()
    }

    // endregion
    // region Device sync
    @Throws(Exception::class)
    override fun processSyncItem(
        session: Session,
        ownedIdentity: Identity?,
        obvSyncAtom: ObvSyncAtom?
    ) {
        when (obvSyncAtom!!.syncType) {
            ObvSyncAtom.TYPE_TRUST_CONTACT_DETAILS -> {
                try {
                    val atomDetails =
                        jsonObjectMapper.readValue<JsonIdentityDetailsWithVersionAndPhoto>(
                            obvSyncAtom.getStringValue(),
                            JsonIdentityDetailsWithVersionAndPhoto::class.java
                        )
                    val dbDetails = getContactPublishedAndTrustedDetails(
                        session,
                        ownedIdentity,
                        obvSyncAtom.contactIdentity
                    )
                    // check if there are indeed details to trust
                    if (dbDetails != null && dbDetails.size == 2) {
                        // check that the published details actually match those we received
                        val dbPhotoKey: SymmetricKey? = if (dbDetails[0]!!.getPhotoServerKey() == null) null else Encoded(dbDetails[0]!!.getPhotoServerKey()!!).decodeSymmetricKey()
                        val atomPhotoKey: SymmetricKey? = if (atomDetails.getPhotoServerKey() == null) null else Encoded(atomDetails.getPhotoServerKey()!!).decodeSymmetricKey()
                        if (dbPhotoKey == atomPhotoKey
                                && dbDetails[0]!!.getPhotoServerLabel()
                                .contentEquals(atomDetails.getPhotoServerLabel()) && dbDetails[0]!!.getIdentityDetails() == atomDetails.getIdentityDetails()
                        ) {
                            trustPublishedContactDetails(
                                session,
                                obvSyncAtom.contactIdentity,
                                ownedIdentity
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            ObvSyncAtom.TYPE_TRUST_GROUP_V1_DETAILS -> {
                try {
                    val atomDetails =
                        jsonObjectMapper.readValue<JsonGroupDetailsWithVersionAndPhoto>(
                            obvSyncAtom.getStringValue(),
                            JsonGroupDetailsWithVersionAndPhoto::class.java
                        )
                    val dbDetails = getGroupPublishedAndLatestOrTrustedDetails(
                        session,
                        ownedIdentity,
                        obvSyncAtom.bytesGroupOwnerAndUid
                    )
                    // check if there are indeed details to trust
                    if (dbDetails != null && dbDetails.size == 2) {
                        // check that the published details actually match those we received
                        val dbGroupPhotoKey: SymmetricKey? = if (dbDetails[0]!!.getPhotoServerKey() == null) null else Encoded(dbDetails[0]!!.getPhotoServerKey()!!).decodeSymmetricKey()
                        val atomGroupPhotoKey: SymmetricKey? = if (atomDetails.getPhotoServerKey() == null) null else Encoded(atomDetails.getPhotoServerKey()!!).decodeSymmetricKey()
                        if (dbGroupPhotoKey == atomGroupPhotoKey
                                && dbDetails[0]!!.getPhotoServerLabel()
                                .contentEquals(atomDetails.getPhotoServerLabel()) && dbDetails[0]!!.getGroupDetails() == atomDetails.getGroupDetails()
                        ) {
                            trustPublishedGroupDetails(
                                session,
                                ownedIdentity,
                                obvSyncAtom.bytesGroupOwnerAndUid
                            )
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            ObvSyncAtom.TYPE_TRUST_GROUP_V2_DETAILS -> {
                try {
                    val version = obvSyncAtom.integerValue!!
                    val groupIdentifier = obvSyncAtom.groupIdentifier
                    val groupV2: ContactGroupV2? = ContactGroupV2.get(
                        wrapSession(session),
                        ownedIdentity,
                        groupIdentifier
                    )
                    // check if there are indeed details to trust matching the version
                    if (groupV2 != null && (groupV2.version != groupV2.getTrustedDetailsVersion() || groupV2.version < version)) {
                        if (groupV2.version == version) {
                            trustGroupV2PublishedDetails(session, ownedIdentity, groupIdentifier)
                        } else if (groupV2.version < version) {
                            if (groupV2.getAlreadyTrustedDetailsVersion() == null || groupV2.getAlreadyTrustedDetailsVersion()!! < version) {
                                groupV2.setAlreadyTrustedDetailsVersion(version)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            else -> {
                throw Exception("Unknown Identity Manager sync atom type")
            }
        }
    }

    @Throws(Exception::class)
    override fun downloadAllUserData(session: Session) {
        val ownedIdentityDetailsList: MutableList<OwnedIdentityDetails?> =
            OwnedIdentityDetails.getAllWithMissingPhotoUrl(wrapSession(session))
        for (ownedIdentityDetails in ownedIdentityDetailsList) {
            protocolStarterDelegate!!.startDownloadIdentityPhotoProtocolWithinTransaction(
                session,
                ownedIdentityDetails!!.getOwnedIdentity(),
                ownedIdentityDetails.getOwnedIdentity(),
                ownedIdentityDetails.jsonIdentityDetailsWithVersionAndPhoto
            )
        }

        val contactIdentityDetailsList: MutableList<ContactIdentityDetails?> =
            ContactIdentityDetails.getAllWithMissingPhotoUrl(wrapSession(session))
        for (contactIdentityDetails in contactIdentityDetailsList) {
            protocolStarterDelegate!!.startDownloadIdentityPhotoProtocolWithinTransaction(
                session,
                contactIdentityDetails!!.getOwnedIdentity(),
                contactIdentityDetails.getContactIdentity(),
                contactIdentityDetails.jsonIdentityDetailsWithVersionAndPhoto
            )
        }

        val contactGroupDetailsList: MutableList<ContactGroupDetails?> =
            ContactGroupDetails.getAllWithMissingPhotoUrl(wrapSession(session))
        for (contactGroupDetails in contactGroupDetailsList) {
            protocolStarterDelegate!!.startDownloadGroupPhotoProtocolWithinTransaction(
                session,
                contactGroupDetails!!.getOwnedIdentity(),
                contactGroupDetails.groupOwnerAndUid,
                contactGroupDetails.jsonGroupDetailsWithVersionAndPhoto
            )
        }

        val contactGroupV2DetailsList: MutableList<ContactGroupV2Details?> =
            ContactGroupV2Details.getAllWithMissingPhotoUrl(wrapSession(session))
        for (contactGroupV2Details in contactGroupV2DetailsList) {
            protocolStarterDelegate!!.startDownloadGroupV2PhotoProtocolWithinTransaction(
                session,
                contactGroupV2Details!!.ownedIdentity,
                contactGroupV2Details.groupIdentifier,
                contactGroupV2Details.serverPhotoInfo
            )
        }
    }


    // endregion
    // endregion
    // region Implement EncryptionForIdentityDelegate
    override fun wrap(
        messageKey: AuthEncKey?,
        toIdentity: Identity?,
        prng: PRNGService?
    ): EncryptedBytes? {
        try {
            val pubEnc = Suite.getPublicKeyEncryption(toIdentity!!.encryptionPublicKey)!!
            return pubEnc.encrypt(toIdentity.encryptionPublicKey, Encoded.of(messageKey!!).bytes, prng)
        } catch (_: InvalidKeyException) {
            return null
        }
    }

    @Throws(SQLException::class)
    override fun unwrap(
        session: Session,
        wrappedKey: EncryptedBytes?,
        toIdentity: Identity?
    ): AuthEncKey? {
        try {
            val ownedIdentity: OwnedIdentity =
                OwnedIdentity.get(wrapSession(session), toIdentity) ?: return null
            val privateIdentity = ownedIdentity.getPrivateIdentity()
            val pubEnc = Suite.getPublicKeyEncryption(privateIdentity!!.getEncryptionPublicKey())!!
            val unwrappedBytes = pubEnc.decrypt(privateIdentity.encryptionPrivateKey, wrappedKey)!!
            return Encoded(unwrappedBytes).decodeSymmetricKey() as AuthEncKey?
        } catch (_: DecryptionException) {
            return null
        } catch (_: InvalidKeyException) {
            return null
        } catch (_: DecodingException) {
            return null
        }
    }

    @Throws(SQLException::class)
    override fun decrypt(
        session: Session,
        ciphertext: EncryptedBytes?,
        toIdentity: Identity?
    ): ByteArray? {
        try {
            val ownedIdentity: OwnedIdentity =
                OwnedIdentity.get(wrapSession(session), toIdentity) ?: return null
            val privateIdentity = ownedIdentity.getPrivateIdentity()
            val pubEnc = Suite.getPublicKeyEncryption(privateIdentity!!.getEncryptionPublicKey())!!
            return pubEnc.decrypt(privateIdentity.encryptionPrivateKey, ciphertext)
        } catch (_: DecryptionException) {
            return null
        } catch (_: InvalidKeyException) {
            return null
        }
    }

    // very risky method, only called from the engine, but this is kind of a bad idea...
    @Throws(SQLException::class)
    fun getOwnedIdentityEncryptionPrivateKey(
        session: Session,
        toIdentity: Identity?
    ): EncryptionPrivateKey? {
        val ownedIdentity: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), toIdentity)
        if (ownedIdentity == null) {
            return null
        }
        val privateIdentity = ownedIdentity.getPrivateIdentity()
        return privateIdentity!!.encryptionPrivateKey
    }


    // endregion
    // region implement PreKeyEncryptionDelegate
    override fun wrapWithPreKey(
        session: Session,
        messageKey: AuthEncKey?,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?,
        remoteDeviceUid: UID?,
        prng: PRNGService?
    ): EncryptedBytes? {
        try {
            val ownedIdentityObject: OwnedIdentity? =
                OwnedIdentity.get(wrapSession(session), ownedIdentity)
            if (ownedIdentityObject == null) {
                Logger.w("In wrapWithPreKey(), unknown OwnedIdentity")
                return null
            }

            // find the PreKey to use for encryption
            val preKey: PreKey?
            if (ownedIdentity!!.equals(remoteIdentity)) {
                val ownedDevice: OwnedDevice? =
                    OwnedDevice.get(wrapSession(session), remoteDeviceUid!!)
                if (ownedDevice == null || ownedDevice.getOwnedIdentity() != ownedIdentity) {
                    Logger.w("In wrapWithPreKey(), unable to find the correct ownedDevice")
                    return null
                }
                preKey = ownedDevice.preKey
            } else {
                val contactDevice: ContactDevice? = ContactDevice.get(
                    wrapSession(session),
                    remoteDeviceUid!!,
                    remoteIdentity!!,
                    ownedIdentity
                )
                if (contactDevice == null) {
                    Logger.w("In wrapWithPreKey(), unable to find the correct contactDevice")
                    return null
                }
                preKey = contactDevice.preKey
            }

            if (preKey == null) {
                Logger.w("In wrapWithPreKey(), remote device does not have a preKey")
                return null
            }

            // build the message payload
            val currentDeviceUid = getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
            val encodedPayload = Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(messageKey!!),
                    Encoded.of(currentDeviceUid!!),
                    Encoded.of(ownedIdentity),
                )
            )


            // compute the signature
            val signaturePayload = Encoded.of(
                arrayOf<Encoded>(
                    encodedPayload,
                    Encoded.of(remoteIdentity!!),
                    Encoded.of(remoteDeviceUid),
                    Encoded.of(preKey.keyId!!.bytes),
                )
            )


            val signature = Signature.sign(
                SignatureContext.ENCRYPTION_WITH_PRE_KEY,
                signaturePayload.bytes,
                ownedIdentityObject.getPrivateIdentity()!!.serverAuthenticationPrivateKey.signaturePrivateKey,
                prng!!
            )
            if (signature == null) {
                Logger.w("In wrapWithPreKey(), unable to compute signature?!")
                return null
            }

            // encrypt the signed payload
            val encodedPlaintext = Encoded.of(
                arrayOf(
                    encodedPayload,
                    Encoded.of(signature),
                )
            )
            val encryptedBytes = Suite.getPublicKeyEncryption(preKey.encryptionPublicKey)!!
                .encrypt(preKey.encryptionPublicKey, encodedPlaintext.bytes, prng)!!
            val outputBytes = ByteArray(KeyId.KEYID_LENGTH + encryptedBytes.length)
            System.arraycopy(preKey.keyId.bytes, 0, outputBytes, 0, KeyId.KEYID_LENGTH)
            System.arraycopy(
                encryptedBytes.getBytes(),
                0,
                outputBytes,
                KeyId.KEYID_LENGTH,
                encryptedBytes.length
            )

            return EncryptedBytes(outputBytes)
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun unwrapWithPreKey(
        session: Session,
        wrappedKey: EncryptedBytes?,
        ownedIdentity: Identity?
    ): AuthEncKeyAndChannelInfo? {
        try {
            if (wrappedKey!!.length < KeyId.KEYID_LENGTH) {
                return null
            }
            val keyId = KeyId(Arrays.copyOfRange(wrappedKey.getBytes(), 0, KeyId.KEYID_LENGTH))
            val ownedPreKey: OwnedPreKey? =
                OwnedPreKey.get(wrapSession(session), ownedIdentity!!, keyId)
            if (ownedPreKey == null) {
                return null
            }

            val plaintextBytes: ByteArray
            try {
                plaintextBytes =
                    Suite.getPublicKeyEncryption(ownedPreKey.encryptionPrivateKey)!!.decrypt(
                        ownedPreKey.encryptionPrivateKey, EncryptedBytes(
                            Arrays.copyOfRange(
                                wrappedKey.getBytes(),
                                KeyId.KEYID_LENGTH,
                                wrappedKey.length
                            )
                        )
                    )!!
            } catch (_: InvalidKeyException) {
                return null
            } catch (_: DecryptionException) {
                return null
            }
            val encodeds: Array<Encoded> = Encoded(plaintextBytes).decodeList()

            val payloadEncodeds: Array<Encoded> = encodeds[0].decodeList()
            val signature = encodeds[1].decodeBytes()

            val messageKey = payloadEncodeds[0].decodeSymmetricKey() as AuthEncKey?
            val remoteDeviceUid = payloadEncodeds[1].decodeUid()
            val remoteIdentity = payloadEncodeds[2].decodeIdentity()

            val currentDeviceUid = getCurrentDeviceUidOfOwnedIdentity(session, ownedIdentity)
            val signatureEncoded: Encoded = Encoded.of(
                arrayOf(
                    encodeds[0],
                    Encoded.of(ownedIdentity),
                    Encoded.of(currentDeviceUid!!),
                    Encoded.of(keyId.bytes),
                )
            )

            if (!Signature.verify(
                    SignatureContext.ENCRYPTION_WITH_PRE_KEY,
                    signatureEncoded.bytes,
                    remoteIdentity,
                    signature
                )
            ) {
                Logger.w("PreKey wrapped messageKey signature verification failed!")
                return null
            }
            return AuthEncKeyAndChannelInfo(
                messageKey,
                createPreKeyChannelInfo(remoteDeviceUid, remoteIdentity)
            )
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }


    // endregion
    // region implement ObvBackupAndSyncDelegate
    override val tag: String
        get() = "identity"

    override fun getSyncSnapshot(ownedIdentity: Identity?): ObvSyncSnapshotNode? {
        try {
            getSession().use { identityManagerSession ->
                try {
                    // start a transaction to be sure the db is not modified while the snapshot is being computed!
                    identityManagerSession.session.startTransaction()
                    return getSyncSnapshotWithinTransaction(identityManagerSession, ownedIdentity!!)
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                } finally {
                    // always rollback as the snapshot creation should never modify the DB.
                    identityManagerSession.session.rollback()
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    private fun getSyncSnapshotWithinTransaction(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity
    ): ObvSyncSnapshotNode {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("ERROR: called IdentityManager.getSyncSnapshot outside a transaction!")
            throw Exception()
        }
        return IdentityManagerSyncSnapshot.of(identityManagerSession, ownedIdentity)
    }


    @Throws(Exception::class)
    override fun restoreOwnedIdentity(
        ownedIdentity: ObvIdentity?,
        node: ObvSyncSnapshotNode?
    ): RestoreFinishedCallback? {
        // this method does not do anything for the IdentityManager: the ownedIdentity has already been restored before calling this
        return null
    }

    override fun restoreSyncSnapshot(node: ObvSyncSnapshotNode?): RestoreFinishedCallback? {
        try {
            getSession().use { identityManagerSession ->
                var transactionSuccessful = false
                try {
                    // start a transaction to be sure the db is not modified while the snapshot is being computed!
                    identityManagerSession.session.startTransaction()
                    val callback =
                        restoreSyncSnapshotWithinTransaction(identityManagerSession, node)
                    transactionSuccessful = true
                    return callback
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (transactionSuccessful) {
                        identityManagerSession.session.commit()
                    } else {
                        identityManagerSession.session.rollback()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
        return null
    }

    @Throws(Exception::class)
    private fun restoreSyncSnapshotWithinTransaction(
        identityManagerSession: IdentityManagerSession?,
        node: ObvSyncSnapshotNode?
    ): RestoreFinishedCallback? {
        if (node !is IdentityManagerSyncSnapshot) {
            throw Exception()
        }
        node.restore(identityManagerSession!!, protocolStarterDelegate)
        return null
    }

    @Throws(Exception::class)
    override fun serialize(
        serializationContext: SerializationContext?,
        snapshotNode: ObvSyncSnapshotNode?
    ): ByteArray? {
        when (serializationContext) {
            SerializationContext.DEVICE -> if (snapshotNode !is IdentityManagerDeviceSnapshot) {
                throw Exception("IdentityBackupDelegate can only serialize IdentityManagerDeviceSnapshot")
            }

            SerializationContext.PROFILE -> if (snapshotNode !is IdentityManagerSyncSnapshot) {
                throw Exception("IdentityBackupDelegate can only serialize IdentityManagerSyncSnapshot")
            }

            null -> {}
        }
        return jsonObjectMapper.writeValueAsBytes(snapshotNode)
    }

    @Throws(Exception::class)
    override fun deserialize(
        serializationContext: SerializationContext?,
        serializedSnapshotNode: ByteArray?
    ): ObvSyncSnapshotNode? {
        when (serializationContext) {
            SerializationContext.DEVICE -> return jsonObjectMapper.readValue<IdentityManagerDeviceSnapshot?>(
                serializedSnapshotNode,
                IdentityManagerDeviceSnapshot::class.java
            )

            SerializationContext.PROFILE -> return jsonObjectMapper.readValue<IdentityManagerSyncSnapshot?>(
                serializedSnapshotNode,
                IdentityManagerSyncSnapshot::class.java
            )

            else -> return jsonObjectMapper.readValue<IdentityManagerSyncSnapshot?>(
                serializedSnapshotNode,
                IdentityManagerSyncSnapshot::class.java
            )
        }
    }

    override fun getDeviceSnapshot(): ObvSyncSnapshotNode? {
        try {
            getSession().use { identityManagerSession ->
                try {
                    // start a transaction to be sure the db is not modified while the snapshot is being computed!
                    identityManagerSession.session.startTransaction()
                    return getDeviceSnapshotWithinTransaction(identityManagerSession)
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                } finally {
                    // always rollback as the snapshot creation should never modify the DB.
                    identityManagerSession.session.rollback()
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    fun getDeviceSnapshotWithinTransaction(identityManagerSession: IdentityManagerSession): ObvSyncSnapshotNode {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("ERROR: called IdentityManager.getDeviceSnapshotWithinTransaction outside a transaction!")
            throw Exception()
        }
        return IdentityManagerDeviceSnapshot.of(identityManagerSession)
    }

    override fun getAdditionalProfileInfo(ownedIdentity: Identity?): MutableMap<String?, String?>? {
        try {
            getSession().use { identityManagerSession ->
                try {
                    // start a transaction to be sure the db is not modified while the snapshot is being computed!
                    identityManagerSession.session.startTransaction()
                    return getAdditionalProfileInfoWithinTransaction(
                        identityManagerSession,
                        ownedIdentity
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                } finally {
                    // always rollback as the snapshot creation should never modify the DB.
                    identityManagerSession.session.rollback()
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            return null
        }
    }

    @Throws(Exception::class)
    private fun getAdditionalProfileInfoWithinTransaction(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity?
    ): MutableMap<String?, String?> {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("ERROR: called IdentityManager.getAdditionalProfileInfoWithinTransaction outside a transaction!")
            throw Exception()
        }
        val displayName = getCurrentDeviceDisplayName(identityManagerSession.session, ownedIdentity)
        if (displayName != null) {
            return Map.of<String?, String?>(ObvProfileBackupSnapshot.INFO_DEVICE_NAME, displayName)
        } else {
            return mutableMapOf<String?, String?>()
        }
    }

    override val syncDelegate: ObvBackupAndSyncDelegate?
        get() = this

    override fun getSyncDelegateWithinTransaction(session: Session): ObvBackupAndSyncDelegate {
        return object : ObvBackupAndSyncDelegate {
            private val identityManagerSession: IdentityManagerSession = wrapSession(session)
            override val tag: String
                get() = this@IdentityManager.tag

            override fun getSyncSnapshot(ownedIdentity: Identity?): ObvSyncSnapshotNode? {
                try {
                    return this@IdentityManager.getSyncSnapshotWithinTransaction(
                        identityManagerSession,
                        ownedIdentity!!
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                }
            }

            @Throws(Exception::class)
            override fun restoreOwnedIdentity(
                ownedIdentity: ObvIdentity?,
                node: ObvSyncSnapshotNode?
            ): RestoreFinishedCallback? {
                return this@IdentityManager.restoreOwnedIdentity(ownedIdentity, node)
            }

            @Throws(Exception::class)
            override fun restoreSyncSnapshot(node: ObvSyncSnapshotNode?): RestoreFinishedCallback? {
                return this@IdentityManager.restoreSyncSnapshotWithinTransaction(
                    identityManagerSession,
                    node
                )
            }

            @Throws(Exception::class)
            override fun serialize(
                serializationContext: SerializationContext?,
                snapshotNode: ObvSyncSnapshotNode?
            ): ByteArray? {
                return this@IdentityManager.serialize(serializationContext, snapshotNode)
            }

            @Throws(Exception::class)
            override fun deserialize(
                serializationContext: SerializationContext?,
                serializedSnapshotNode: ByteArray?
            ): ObvSyncSnapshotNode? {
                return this@IdentityManager.deserialize(
                    serializationContext,
                    serializedSnapshotNode
                )
            }

            override fun getDeviceSnapshot(): ObvSyncSnapshotNode? {
                try {
                    return this@IdentityManager.getDeviceSnapshotWithinTransaction(
                        identityManagerSession
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                }
            }

            override fun getAdditionalProfileInfo(ownedIdentity: Identity?): MutableMap<String?, String?>? {
                try {
                    return this@IdentityManager.getAdditionalProfileInfoWithinTransaction(
                        identityManagerSession,
                        ownedIdentity
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                    return null
                }
            }
        }
    }

    @Throws(Exception::class)
    override fun restoreTransferredOwnedIdentity(
        session: Session,
        deviceName: String?,
        node: IdentityManagerSyncSnapshot?
    ): ObvIdentity {
        val ownedIdentity = Identity.of(node!!.owned_identity!!)
        return node.owned_identity_node!!.restoreOwnedIdentity(
            wrapSession(session),
            deviceName,
            ownedIdentity
        )
    }

    @Throws(SQLException::class)
    override fun getOwnedIdentityBackupSeed(
        session: Session,
        ownedIdentity: Identity?
    ): BackupSeed? {
        val ownedIdentityObject: OwnedIdentity? =
            OwnedIdentity.get(wrapSession(session), ownedIdentity)
        if (ownedIdentityObject != null) {
            return ownedIdentityObject.getBackupSeed()
        }
        return null
    }

    @Throws(Exception::class)
    override fun getDeviceBackupProfileListFromDeviceBackup(
        session: Session,
        snapshotNode: ObvSyncSnapshotNode?
    ): MutableList<ObvDeviceBackupProfile?> {
        if (snapshotNode !is IdentityManagerDeviceSnapshot) {
            throw Exception("Bad snapshot type")
        }
        val list: MutableList<ObvDeviceBackupProfile?> = ArrayList<ObvDeviceBackupProfile?>()
        val identityManagerDeviceSnapshot = snapshotNode

        if (!identityManagerDeviceSnapshot.validate()) {
            throw Exception("Invalid IdentityManagerDeviceSnapshot")
        }

        val identityManagerSession = wrapSession(session)
        for (owned_identity in identityManagerDeviceSnapshot.owned_identities!!.entries) {
            if (!owned_identity.value!!.validate()) {
                continue
            }

            val profile = ObvDeviceBackupProfile()
            profile.bytesProfileIdentity = owned_identity.key!!.getBytes()
            val published_details = owned_identity.value!!.published_details
            val detailsAndPhoto = JsonIdentityDetailsWithVersionAndPhoto()
            detailsAndPhoto.setVersion(published_details!!.version!!)
            detailsAndPhoto.setIdentityDetails(
                jsonObjectMapper.readValue<JsonIdentityDetails?>(
                    published_details.serialized_details,
                    JsonIdentityDetails::class.java
                )
            )

            // check if this identity is known and has a local published photo
            val detailsPhotoServerLabel = published_details.photo_server_label
            val detailsPhotoServerKey = published_details.photo_server_key
            if (detailsPhotoServerLabel != null && detailsPhotoServerKey != null) {
                detailsAndPhoto.setPhotoServerLabel(detailsPhotoServerLabel)
                detailsAndPhoto.setPhotoServerKey(detailsPhotoServerKey)

                try {
                    val label = UID(detailsPhotoServerLabel)
                    val key =
                        Encoded(detailsPhotoServerKey).decodeSymmetricKey() as AuthEncKey?
                    val ownedIdentityDetailsList: MutableList<OwnedIdentityDetails?> =
                        OwnedIdentityDetails.getAllForOwnedIdentity(
                            identityManagerSession,
                            Identity.of(profile.bytesProfileIdentity!!)
                        )
                    for (ownedIdentityDetails in ownedIdentityDetailsList) {
                        if (label.equals(ownedIdentityDetails!!.photoServerLabel)
                            && key == ownedIdentityDetails.photoServerKey
                        ) {
                            detailsAndPhoto.setPhotoUrl(ownedIdentityDetails.photoUrl)
                            break
                        }
                    }
                } catch (_: Exception) {
                }
            }

            profile.identityDetails = detailsAndPhoto
            profile.keycloakManaged = owned_identity.value!!.keycloak_managed!!
            profile.profileBackupSeed = BackupSeed(owned_identity.value!!.backup_seed!!).toString()

            list.add(profile)
        }

        return list
    } // endregion

    companion object {
        @JvmStatic
        @Throws(SQLException::class)
        fun upgradeTables(session: Session, oldVersion: Int, newVersion: Int) {
            OwnedIdentityDetails.upgradeTable(session, oldVersion, newVersion)
            KeycloakServer.upgradeTable(session, oldVersion, newVersion)
            KeycloakRevokedIdentity.upgradeTable(session, oldVersion, newVersion)
            OwnedIdentity.upgradeTable(session, oldVersion, newVersion)
            OwnedDevice.upgradeTable(session, oldVersion, newVersion)
            if (oldVersion < 14 && newVersion >= 14) {
                // Drop the OwnedEphemeralIdentity table
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE IF EXISTS owned_ephemeral_identity")
                }
            }
            OwnedPreKey.upgradeTable(session, oldVersion, newVersion)
            ContactIdentityDetails.upgradeTable(session, oldVersion, newVersion)
            ContactIdentity.upgradeTable(session, oldVersion, newVersion)
            ContactTrustOrigin.upgradeTable(session, oldVersion, newVersion)
            ContactDevice.upgradeTable(session, oldVersion, newVersion)
            ContactGroupDetails.upgradeTable(session, oldVersion, newVersion)
            ContactGroup.upgradeTable(session, oldVersion, newVersion)
            ContactGroupMembersJoin.upgradeTable(session, oldVersion, newVersion)
            PendingGroupMember.upgradeTable(session, oldVersion, newVersion)
            ServerUserData.upgradeTable(session, oldVersion, newVersion)
            ContactGroupV2Details.upgradeTable(session, oldVersion, newVersion)
            ContactGroupV2.upgradeTable(session, oldVersion, newVersion)
            ContactGroupV2Member.upgradeTable(session, oldVersion, newVersion)
            ContactGroupV2PendingMember.upgradeTable(session, oldVersion, newVersion)
        }

        @Throws(Exception::class)
        private fun groupV2toObvGroupV2(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            groupV2: ContactGroupV2
        ): ObvGroupV2? {
            val otherGroupMembers = HashSet<ObvGroupV2Member>()
            val members: MutableList<ContactGroupV2Member?>? = ContactGroupV2Member.getAll(
                identityManagerSession!!,
                ownedIdentity,
                groupIdentifier
            )
            for (member in members!!) {
                otherGroupMembers.add(
                    ObvGroupV2Member(
                        member!!.contactIdentity.getBytes(),
                        deserializeKnownPermissions(member.serializedPermissions)
                    )
                )
            }

            val pendingGroupMembers = HashSet<ObvGroupV2PendingMember>()
            val pendingMembers: MutableList<ContactGroupV2PendingMember?>? =
                ContactGroupV2PendingMember.getAll(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier
                )
            for (pendingMember in pendingMembers!!) {
                pendingGroupMembers.add(
                    ObvGroupV2PendingMember(
                        pendingMember!!.contactIdentity.getBytes(),
                        deserializeKnownPermissions(pendingMember.serializedPermissions),
                        pendingMember.getSerializedContactDetails()
                    )
                )
            }

            val trustedDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                identityManagerSession,
                ownedIdentity,
                groupIdentifier,
                groupV2.getTrustedDetailsVersion()
            )
            if (trustedDetails == null) {
                return null
            }

            val serializedGroupDetails = trustedDetails.serializedJsonDetails
            var photoUrl = trustedDetails.getPhotoUrl()
            if (photoUrl == null && trustedDetails.serverPhotoInfo != null) { // photo not downloaded yet
                photoUrl = ""
            }

            val serializedPublishedDetails: String?
            var publishedPhotoUrl: String? = null
            if (groupV2.version != groupV2.getTrustedDetailsVersion()) {
                val publishedDetails: ContactGroupV2Details? = ContactGroupV2Details.get(
                    identityManagerSession,
                    ownedIdentity,
                    groupIdentifier,
                    groupV2.version
                )
                if (publishedDetails == null) {
                    return null
                }
                serializedPublishedDetails = publishedDetails.serializedJsonDetails
                publishedPhotoUrl = publishedDetails.getPhotoUrl()
                if (publishedPhotoUrl == null && publishedDetails.serverPhotoInfo != null) { // photo not downloaded yet
                    publishedPhotoUrl = ""
                }
            } else {
                serializedPublishedDetails = null
                publishedPhotoUrl = null
            }


            return ObvGroupV2(
                ownedIdentity!!.getBytes(),
                groupIdentifier!!,
                fromStrings(groupV2.ownPermissionStrings),
                otherGroupMembers,
                pendingGroupMembers,
                serializedGroupDetails!!,
                photoUrl,
                serializedPublishedDetails,
                publishedPhotoUrl,
                groupV2.lastModificationTimestamp
            )
        }
    }
}
