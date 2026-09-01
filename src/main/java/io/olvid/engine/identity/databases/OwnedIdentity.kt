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
package io.olvid.engine.identity.databases

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.PrivateIdentity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.datatypes.notifications.BackupNotifications
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.IdBased
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.storage.EngineFile
import java.io.File
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Arrays
import java.util.Map
import java.util.Random
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet

class OwnedIdentity : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val ownedIdentity: Identity
    private val privateIdentityBytes: ByteArray
    var publishedDetailsVersion: Int
        private set
    var latestDetailsVersion: Int
        private set
    private var active: Boolean
    private var keycloakServerUrl: String?
    var isMarkedForDeletion: Boolean
        private set
    private var backupSeed: ByteArray?

    // keep the deserialized version in cache locally
    private var privateIdentity: PrivateIdentity? = null


    fun getPrivateIdentity(): PrivateIdentity? {
        if (privateIdentity == null) {
            privateIdentity = PrivateIdentity.of(privateIdentityBytes)
        }
        return privateIdentity
    }

    fun isActive(): Boolean {
        return active
    }

    fun getKeycloakServerUrl(): String? {
        return keycloakServerUrl
    }

    val isKeycloakManaged: Boolean
        get() = keycloakServerUrl != null

    fun getBackupSeed(): BackupSeed? {
        if (backupSeed != null) {
            try {
                return BackupSeed(backupSeed!!)
            } catch (e: Exception) {
                Logger.x(e)
            }
        }
        return null
    }

    val contactIdentities: Array<ContactIdentity>
        // region computed properties
        get() = ContactIdentity.getAll(identityManagerSession, ownedIdentity)

    @get:Throws(SQLException::class)
    val otherDeviceUids: Array<UID?>
        get() {
            val ownedDevices: Array<OwnedDevice> =
                OwnedDevice.getOtherDevicesOfOwnedIdentity(
                    identityManagerSession,
                    ownedIdentity
                )
            val uids =
                arrayOfNulls<UID>(ownedDevices.size)
            for (i in ownedDevices.indices) {
                uids[i] = ownedDevices[i].uid
            }
            return uids
        }

    @get:Throws(SQLException::class)
    val allDeviceUids: Array<UID?>
        get() = OwnedDevice.getAllDeviceUidsOfIdentity(
            identityManagerSession,
            ownedIdentity
        )

    @get:Throws(SQLException::class)
    val currentDeviceUid: UID?
        get() = OwnedDevice.getCurrentDeviceOfOwnedIdentity(
            identityManagerSession,
            ownedIdentity
        )?.uid

    @get:Throws(SQLException::class)
    val publishedDetails: OwnedIdentityDetails?
        get() = OwnedIdentityDetails.get(
            identityManagerSession,
            ownedIdentity,
            publishedDetailsVersion
        )

    @get:Throws(SQLException::class)
    val latestDetails: OwnedIdentityDetails?
        get() = OwnedIdentityDetails.get(
            identityManagerSession,
            ownedIdentity,
            latestDetailsVersion
        )

    @get:Throws(SQLException::class)
    val keycloakServer: KeycloakServer?
        get() {
            if (keycloakServerUrl != null) {
                return KeycloakServer.get(
                    identityManagerSession,
                    keycloakServerUrl,
                    ownedIdentity
                )
            }
            return null
        }


    @get:Throws(SQLException::class)
    val keycloakState: ObvKeycloakState?
        get() {
            if (keycloakServerUrl != null) {
                val keycloakServer: KeycloakServer? = KeycloakServer.get(
                    identityManagerSession,
                    keycloakServerUrl,
                    ownedIdentity
                )
                if (keycloakServer != null) {
                    var jwks: JsonWebKeySet? = null
                    try {
                        jwks = keycloakServer.jwks
                    } catch (_: Exception) {
                        jwks = null
                    }
                    var signatureKey: JsonWebKey? = null
                    try {
                        signatureKey = keycloakServer.signatureKey
                    } catch (_: Exception) {
                        signatureKey = null
                    }

                    val supportedAuthTypes: MutableList<ObvKeycloakAuthType?> =
                        ArrayList<ObvKeycloakAuthType?>()
                    if (keycloakServer.clientId != null) {
                        supportedAuthTypes.add(
                            OpenIdConnect(
                                keycloakServer.clientId,
                                keycloakServer.clientSecret
                            )
                        )
                    }
                    if (keycloakServer.isIdBasedAuthSupported) {
                        supportedAuthTypes.add(IdBased())
                    }
                    return ObvKeycloakState(
                        keycloakServer.serverUrl,
                        supportedAuthTypes,
                        jwks,
                        signatureKey,
                        keycloakServer.serializedAuthState,
                        keycloakServer.isTransferRestricted(),
                        keycloakServer.ownApiKey,
                        keycloakServer.latestRevocationListTimestamp,
                        keycloakServer.getLatestGroupUpdateTimestamp()
                    )
                }
            }
            return null
        }

    @get:Throws(SQLException::class)
    val keycloakSignatureKey: JsonWebKey?
        get() {
            if (keycloakServerUrl != null) {
                val keycloakServer: KeycloakServer? = KeycloakServer.get(
                    identityManagerSession,
                    keycloakServerUrl,
                    ownedIdentity
                )
                if (keycloakServer != null) {
                    try {
                        return keycloakServer.signatureKey
                    } catch (_: Exception) {
                        // nothing
                    }
                }
            }
            return null
        }


    @get:Throws(SQLException::class)
    val keycloakUserId: String?
        get() {
            if (keycloakServerUrl != null) {
                val keycloakServer: KeycloakServer? = KeycloakServer.get(
                    identityManagerSession,
                    keycloakServerUrl,
                    ownedIdentity
                )
                if (keycloakServer != null) {
                    return keycloakServer.getKeycloakUserId()
                }
            }
            return null
        }


    // endregion
    // region setters
    @Throws(Exception::class)
    fun setLatestDetails(identityDetails: JsonIdentityDetails?) {
        if (identityDetails == null || identityDetails.isEmpty()) {
            return
        }

        // We no longer check if details changed: if we were instructed to update the details, we do so
        // checks that more than the signature has changed were already made
        if (publishedDetailsVersion != latestDetailsVersion) {
            val publishedDetails = this.publishedDetails!!.jsonIdentityDetails
            if (publishedDetails == identityDetails) {
                // changes were reverted --> we discard
                discardLatestDetails()
                return
            }
        }
        // we indeed have a proper update to save
        val ownedIdentityDetails: OwnedIdentityDetails?
        if (publishedDetailsVersion == latestDetailsVersion) {
            ownedIdentityDetails = OwnedIdentityDetails.copy(
                identityManagerSession,
                ownedIdentity,
                publishedDetailsVersion
            )
            identityManagerSession.session.prepareStatement(
                "OwnedIdentity.setLatestDetails",
                "UPDATE " + TABLE_NAME + " SET " +
                        LATEST_DETAILS_VERSION + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, ownedIdentityDetails!!.version)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.latestDetailsVersion = ownedIdentityDetails.version
                commitHookBits = commitHookBits or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED
                identityManagerSession.session.addSessionCommitListener(this)
            }
        } else {
            ownedIdentityDetails = OwnedIdentityDetails.get(
                identityManagerSession,
                ownedIdentity,
                latestDetailsVersion
            )
        }
        ownedIdentityDetails!!.setJsonDetails(identityDetails)
    }

    @Throws(Exception::class)
    fun setPhoto(srcAbsolutePhotoUrl: String?) {
        if (srcAbsolutePhotoUrl == null) {
            // we were requested to remove a photo, just create a new details without it
            val ownedIdentityDetails: OwnedIdentityDetails?
            if (publishedDetailsVersion == latestDetailsVersion) {
                ownedIdentityDetails = OwnedIdentityDetails.copy(
                    identityManagerSession,
                    ownedIdentity,
                    publishedDetailsVersion
                )
                identityManagerSession.session.prepareStatement(
                    "OwnedIdentity.setPhoto",
                    "UPDATE " + TABLE_NAME + " SET " +
                            LATEST_DETAILS_VERSION + " = ? " +
                            " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, ownedIdentityDetails!!.version)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.latestDetailsVersion = ownedIdentityDetails.version
                    commitHookBits =
                        commitHookBits or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED
                    identityManagerSession.session.addSessionCommitListener(this)
                }
            } else {
                ownedIdentityDetails = OwnedIdentityDetails.get(
                    identityManagerSession,
                    ownedIdentity,
                    latestDetailsVersion
                )
            }
            ownedIdentityDetails!!.setPhotoUrl(null, true)
        } else {
            val srcPhotoFile = identityManagerSession.fileIo.file(srcAbsolutePhotoUrl)
            if (!srcPhotoFile.canRead()) {
                return
            }
            val ownedIdentityDetails: OwnedIdentityDetails?
            if (publishedDetailsVersion == latestDetailsVersion) {
                ownedIdentityDetails = OwnedIdentityDetails.copy(
                    identityManagerSession,
                    ownedIdentity,
                    publishedDetailsVersion
                )
                identityManagerSession.session.prepareStatement(
                    "OwnedIdentity.setPhoto",
                    "UPDATE " + TABLE_NAME + " SET " +
                            LATEST_DETAILS_VERSION + " = ? " +
                            " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, ownedIdentityDetails!!.version)
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.latestDetailsVersion = ownedIdentityDetails.version
                    commitHookBits =
                        commitHookBits or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED
                    identityManagerSession.session.addSessionCommitListener(this)
                }
            } else {
                ownedIdentityDetails = OwnedIdentityDetails.get(
                    identityManagerSession,
                    ownedIdentity,
                    latestDetailsVersion
                )
            }
            // find a non-existing fileName
            val fileName = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
                Arrays.copyOfRange(
                    ownedIdentity.getBytes(),
                    ownedIdentity.getBytes().size - 32,
                    ownedIdentity.getBytes().size
                )
            )
            var randFileName: String? = null
            val random = Random()
            var dstPhotoFile: EngineFile? = null
            do {
                randFileName = fileName + "_" + random.nextInt(65536)
                dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
            } while (dstPhotoFile.exists())

            srcPhotoFile.openInput().use { `is` ->
                dstPhotoFile.openOutput().use { os ->
                    val buffer = ByteArray(4096)
                    var length: Int
                    while ((`is`.read(buffer).also { length = it }) > 0) {
                        os.write(buffer, 0, length)
                    }
                }
            }
            // update the details
            ownedIdentityDetails!!.setPhotoUrl(randFileName, true)
        }
    }

    @Throws(SQLException::class)
    fun setOwnedIdentityDetailsFromOtherDevice(ownDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto): Boolean {
        val newDetailsVersion = ownDetailsWithVersionAndPhoto.getVersion()

        // first, check the received details are newer than our own details:
        val currentPublishedDetails = this.publishedDetails
        if (currentPublishedDetails == null) {
            Logger.e("In setOwnedIdentityDetailsFromOtherDevice: unable to read current published details!")
            throw SQLException()
        }

        if (currentPublishedDetails.version >= newDetailsVersion) {
            // if the current version is greater or equal, do nothing
            return false
        }


        // now, create the new OwnedIdentityDetails
        val newPublishedDetails: OwnedIdentityDetails? = OwnedIdentityDetails.create(
            identityManagerSession,
            ownedIdentity,
            ownDetailsWithVersionAndPhoto
        )
        if (newPublishedDetails == null) {
            Logger.e("In setOwnedIdentityDetailsFromOtherDevice: unable to create new details!")
            throw SQLException()
        }

        // copy the existing photoUrl if it is the same
        if (newPublishedDetails.photoServerKey == currentPublishedDetails.photoServerKey
            && newPublishedDetails.photoServerLabel == currentPublishedDetails.photoServerLabel
        ) {
            newPublishedDetails.setPhotoUrl(currentPublishedDetails.photoUrl, false)
        }

        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.setOwnedIdentityDetailsFromOtherDevice",
            "UPDATE " + TABLE_NAME + " SET " +
                    PUBLISHED_DETAILS_VERSION + " = ?, " +
                    LATEST_DETAILS_VERSION + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, newDetailsVersion)
            statement.setInt(2, newDetailsVersion)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.publishedDetailsVersion = newDetailsVersion
        }
        OwnedIdentityDetails.cleanup(
            identityManagerSession,
            ownedIdentity,
            newDetailsVersion,
            newDetailsVersion
        )

        hookDetails = newPublishedDetails.jsonIdentityDetailsWithVersionAndPhoto
        commitHookBits =
            commitHookBits or (HOOK_BIT_IDENTITY_DETAILS_PUBLISHED or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED)
        identityManagerSession.session.addSessionCommitListener(this)

        return newPublishedDetails.photoUrl == null && newPublishedDetails.photoServerKey != null && newPublishedDetails.photoServerLabel != null
    }


    @Throws(Exception::class)
    fun setDetailsDownloadedPhotoUrl(version: Int, photo: ByteArray) {
        val ownedIdentityDetails: OwnedIdentityDetails? =
            OwnedIdentityDetails.get(identityManagerSession, ownedIdentity, version)

        if (ownedIdentityDetails == null) {
            return
        }

        // find a non-existing fileName
        val fileName = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
            Arrays.copyOfRange(
                ownedIdentity.getBytes(),
                ownedIdentity.getBytes().size - 32,
                ownedIdentity.getBytes().size
            )
        )
        var randFileName: String? = null
        val random = Random()
        var dstPhotoFile: EngineFile? = null
        do {
            randFileName = fileName + "_" + random.nextInt(65536)
            dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
        } while (dstPhotoFile.exists())

        dstPhotoFile.openOutput().use { os ->
            os.write(photo, 0, photo.size)
        }
        // update the details
        ownedIdentityDetails.setPhotoUrl(randFileName, false)

        hookDetails = ownedIdentityDetails.jsonIdentityDetailsWithVersionAndPhoto
        commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_DETAILS_PUBLISHED
        identityManagerSession.session.addSessionCommitListener(this)
    }


    @Throws(SQLException::class)
    fun setPhotoLabelAndKey(version: Int, photoServerLabel: UID, photoServerKey: AuthEncKey?) {
        val ownedIdentityDetails: OwnedIdentityDetails? =
            OwnedIdentityDetails.get(identityManagerSession, ownedIdentity, version)
        if (ownedIdentityDetails != null) {
            ownedIdentityDetails.setPhotoServerLabelAndKey(photoServerLabel, photoServerKey!!)
        }
    }

    @Throws(SQLException::class)
    fun publishLatestDetails(): Int {
        if (latestDetailsVersion == publishedDetailsVersion) {
            return -1
        }
        val publishedDetails = this.publishedDetails
        val latestDetails = this.latestDetails
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.publishLatestDetails",
            "UPDATE " + TABLE_NAME + " SET " +
                    PUBLISHED_DETAILS_VERSION + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, latestDetailsVersion)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.publishedDetailsVersion = latestDetailsVersion
            commitHookBits = commitHookBits or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
        if (publishedDetails!!.photoUrl != null && (latestDetails!!.photoUrl == null || latestDetails.photoUrl != publishedDetails.photoUrl)) {
            if (publishedDetails.photoServerLabel != null) {
                labelToDelete = publishedDetails.photoServerLabel
                commitHookBits = commitHookBits or HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED
            }
        }
        hookDetails = latestDetails!!.jsonIdentityDetailsWithVersionAndPhoto
        commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_DETAILS_PUBLISHED
        identityManagerSession.session.addSessionCommitListener(this)
        return latestDetailsVersion
    }

    @Throws(SQLException::class)
    fun discardLatestDetails() {
        if (latestDetailsVersion == publishedDetailsVersion) {
            return
        }
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.discardLatestDetails",
            "UPDATE " + TABLE_NAME + " SET " +
                    LATEST_DETAILS_VERSION + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, publishedDetailsVersion)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.latestDetailsVersion = publishedDetailsVersion
            commitHookBits = commitHookBits or HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setActive(active: Boolean) {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.setActive",
            "UPDATE " + TABLE_NAME +
                    " SET " + ACTIVE + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, active)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.active = active
            commitHookBits = commitHookBits or HOOK_BIT_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setKeycloakServerUrl(keycloakServerUrl: String?) {
        val deleteAllKeycloakGroups = keycloakServerUrl != this.keycloakServerUrl

        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.setKeycloakServerUrl",
            "UPDATE " + TABLE_NAME +
                    " SET " + KEYCLOAK_SERVER_URL + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, keycloakServerUrl)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.keycloakServerUrl = keycloakServerUrl
            commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_LIST_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
            if (deleteAllKeycloakGroups) {
                ContactGroupV2.deleteAllKeycloakGroupsForOwnedIdentity(
                    identityManagerSession,
                    ownedIdentity
                )
            }
        }
    }

    @Throws(SQLException::class)
    fun markForDeletion() {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.markedForDeletion",
            "UPDATE " + TABLE_NAME +
                    " SET " + MARKED_FOR_DELETION + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, true)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.isMarkedForDeletion = true
            commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_LIST_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setBackupSeed(backupSeed: BackupSeed) {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.setBackupSeed",
            "UPDATE " + TABLE_NAME +
                    " SET " + BACKUP_SEED + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, backupSeed.backupSeedBytes)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.backupSeed = backupSeed.backupSeedBytes
        }
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        privateIdentity: PrivateIdentity,
        backupSeed: BackupSeed?,
        detailsVersion: Int
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = privateIdentity.publicIdentity
        this.privateIdentity = privateIdentity
        this.privateIdentityBytes = privateIdentity.serialize()
        this.publishedDetailsVersion = detailsVersion
        this.latestDetailsVersion = detailsVersion
        this.active = true
        this.keycloakServerUrl = null
        this.isMarkedForDeletion = false
        this.backupSeed = if (backupSeed == null) null else backupSeed.backupSeedBytes
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.privateIdentityBytes = res.getBytes(PRIVATE_IDENTITY)
        this.publishedDetailsVersion = res.getInt(PUBLISHED_DETAILS_VERSION)
        this.latestDetailsVersion = res.getInt(LATEST_DETAILS_VERSION)
        this.active = res.getBoolean(ACTIVE)
        this.keycloakServerUrl = res.getString(KEYCLOAK_SERVER_URL)
        this.isMarkedForDeletion = res.getBoolean(MARKED_FOR_DELETION)
        this.backupSeed = res.getBytes(BACKUP_SEED)
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setBytes(2, privateIdentityBytes)
            statement.setInt(3, publishedDetailsVersion)
            statement.setInt(4, latestDetailsVersion)
            statement.setBoolean(5, active)
            statement.setString(6, keycloakServerUrl)
            statement.setBoolean(7, this.isMarkedForDeletion)
            statement.setBytes(8, backupSeed)
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_LIST_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Running OwnedIdentity delete outside a transaction")
            throw SQLException()
        }
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_IDENTITY_LIST_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
        identityManagerSession.session.prepareStatement(
            "OwnedIdentity.delete",
            "DELETE FROM " + OwnedIdentityDetails.TABLE_NAME +
                    " WHERE " + OwnedIdentityDetails.OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    // endregion
    // region hooks
    private var labelToDelete: UID? = null
    private var hookDetails: JsonIdentityDetailsWithVersionAndPhoto? = null

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_IDENTITY_LIST_CHANGED) != 0L) {
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_LIST_UPDATED,
                HashMap<String, Any>()
            )
        }
        if ((commitHookBits and HOOK_BIT_IDENTITY_DETAILS_PUBLISHED) != 0L) {
            // trigger an update of the App ownedIdentity
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED_IDENTITY_DETAILS_KEY,
                hookDetails!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY,
                labelToDelete!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED_HAS_UNPUBLISHED_KEY,
                latestDetailsVersion != publishedDetailsVersion
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY,
                active
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
                userInfo
            )
            if (active) {
                identityManagerSession.notificationPostingDelegate?.postNotification(
                    BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED,
                    Map.of<String, Any>(
                        BackupNotifications.NOTIFICATION_PROFILE_BACKUP_NEEDED_OWNED_IDENTITY,
                        ownedIdentity
                    )
                )
            }
        }
        commitHookBits = 0
    }

    @Throws(SQLException::class)
    private fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.owned_identity = ownedIdentity.getBytes()
        pojo.private_identity = backupPrivateIdentity()
        pojo.published_details = this.publishedDetails!!.backup()
        if (latestDetailsVersion != publishedDetailsVersion) {
            pojo.latest_details = this.latestDetails!!.backup()
        }
        pojo.active = active
        if (keycloakServerUrl != null) {
            pojo.keycloak = this.keycloakServer!!.backup()
        }
        pojo.contact_identities =
            ContactIdentity.backupAll(identityManagerSession, ownedIdentity)
        pojo.owned_groups = ContactGroup.backupAllForOwner(
            identityManagerSession,
            ownedIdentity,
            ownedIdentity
        )
        pojo.groups_v2 = ContactGroupV2.backupAll(identityManagerSession, ownedIdentity)
        return pojo
    }

    private fun backupPrivateIdentity(): PrivateIdentityPojo_0 {
        val privateId = getPrivateIdentity()
        val privateIdentityPojo = PrivateIdentityPojo_0()
        privateIdentityPojo.server_authentication_private_key =
            Encoded.of(privateId!!.serverAuthenticationPrivateKey).bytes
        privateIdentityPojo.encryption_private_key = Encoded.of(privateId.encryptionPrivateKey).bytes
        privateIdentityPojo.mac_key = Encoded.of(privateId.macKey).bytes
        return privateIdentityPojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var owned_identity: ByteArray? = null
        var private_identity: PrivateIdentityPojo_0? = null
        var published_details: OwnedIdentityDetails.Pojo_0? = null
        var latest_details: OwnedIdentityDetails.Pojo_0? = null
        var active: Boolean? = null
        var keycloak: KeycloakServer.Pojo_0? = null
        var contact_identities: Array<ContactIdentity.Pojo_0?>? = null
        var owned_groups: Array<ContactGroup.Pojo_0?>? = null
        var groups_v2: Array<ContactGroupV2.Pojo_0?>? = null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class PrivateIdentityPojo_0 {
        var server_authentication_private_key: ByteArray? = null
        var encryption_private_key: ByteArray? = null
        var mac_key: ByteArray? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "owned_identity"

        const val OWNED_IDENTITY: String = "identity"
        const val PRIVATE_IDENTITY: String = "private_identity"
        const val PUBLISHED_DETAILS_VERSION: String = "published_details_version"
        const val LATEST_DETAILS_VERSION: String = "latest_details_version"
        const val ACTIVE: String = "active"
        const val KEYCLOAK_SERVER_URL: String = "keycloak_server_url"
        const val MARKED_FOR_DELETION: String = "marked_for_deletion"
        const val BACKUP_SEED: String = "backup_seed"

        // endregion
        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            server: String,
            serverAuthenticationAlgoImplByte: Byte?,
            encryptionAlgoImplByte: Byte?,
            identityDetails: JsonIdentityDetails?,
            deviceDisplayName: String?,
            prng: PRNGService
        ): OwnedIdentity? {
            if (identityDetails == null || identityDetails.isEmpty()) {
                return null
            }
            val serverAuthKeyPair =
                Suite.generateServerAuthenticationKeyPair(serverAuthenticationAlgoImplByte, prng)
            val encryptionKeyPair = Suite.generateEncryptionKeyPair(encryptionAlgoImplByte, prng)
            if (serverAuthKeyPair == null || encryptionKeyPair == null) {
                return null
            }
            val macKey = Suite.getDefaultMAC(0).generateKey(prng)!!
            val backupSeed = BackupSeed.generate(prng)
            try {
                val identity = Identity(
                    server,
                    serverAuthKeyPair.getPublicKey() as ServerAuthenticationPublicKey,
                    encryptionKeyPair.getPublicKey() as EncryptionPublicKey
                )
                val privateIdentity = PrivateIdentity(
                    identity,
                    serverAuthKeyPair.getPrivateKey() as ServerAuthenticationPrivateKey,
                    encryptionKeyPair.getPrivateKey() as EncryptionPrivateKey,
                    macKey
                )
                val ownedIdentityDetails: OwnedIdentityDetails =
                    OwnedIdentityDetails.create(
                        identityManagerSession,
                        identity,
                        identityManagerSession.jsonObjectMapper!!.writeValueAsString(identityDetails)
                    ) ?: return null
                val ownedIdentity = OwnedIdentity(
                    identityManagerSession,
                    privateIdentity,
                    backupSeed,
                    ownedIdentityDetails.version
                )
                ownedIdentity.insert()
                OwnedDevice.createCurrentDevice(
                    identityManagerSession,
                    identity,
                    deviceDisplayName,
                    prng
                )
                return ownedIdentity
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB PRIMARY KEY, " +
                            PRIVATE_IDENTITY + " BLOB NOT NULL, " +
                            PUBLISHED_DETAILS_VERSION + " INT NOT NULL, " +
                            LATEST_DETAILS_VERSION + " INT NOT NULL, " +
                            ACTIVE + " BIT NOT NULL, " +
                            KEYCLOAK_SERVER_URL + " TEXT, " +
                            MARKED_FOR_DELETION + " BIT NOT NULL, " +
                            BACKUP_SEED + " BLOB, " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + PUBLISHED_DETAILS_VERSION + ") REFERENCES " + OwnedIdentityDetails.TABLE_NAME + "(" + OwnedIdentityDetails.OWNED_IDENTITY + ", " + OwnedIdentityDetails.VERSION + ")," +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + LATEST_DETAILS_VERSION + ") REFERENCES " + OwnedIdentityDetails.TABLE_NAME + "(" + OwnedIdentityDetails.OWNED_IDENTITY + ", " + OwnedIdentityDetails.VERSION + ")," +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + KEYCLOAK_SERVER_URL + ") REFERENCES " + KeycloakServer.TABLE_NAME + "(" + KeycloakServer.OWNED_IDENTITY + ", " + KeycloakServer.SERVER_URL + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 5 && newVersion >= 5) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE owned_identity RENAME TO old_owned_identities")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS owned_identity_details (" +
                                " owned_identity BLOB NOT NULL, " +
                                " version INT NOT NULL, " +
                                " serialized_json_details TEXT NOT NULL, " +
                                " photo_url TEXT, " +
                                " photo_server_label BLOB, " +
                                " photo_server_key BLOB, " +
                                " CONSTRAINT PK_owned_identity_details PRIMARY KEY(owned_identity, version));"
                    )
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS owned_identity (" +
                                " identity BLOB PRIMARY KEY, " +
                                " private_identity BLOB NOT NULL, " +
                                " published_details_version INT NOT NULL, " +
                                " latest_details_version INT NOT NULL, " +
                                " single_use BIT NOT NULL, " +
                                " api_key VARCHAR NOT NULL, " +
                                " FOREIGN KEY (identity, published_details_version) REFERENCES owned_identity_details(owned_identity, version)," +
                                " FOREIGN KEY (identity, latest_details_version) REFERENCES owned_identity_details(owned_identity, version));"
                    )
                    val objectMapper = ObjectMapper()
                    statement.executeQuery("SELECT * FROM old_owned_identities").use { res ->
                        while (res.next()) {
                            session.prepareStatement("INSERT INTO owned_identity VALUES (?,?,?,?,?, ?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setBytes(2, res.getBytes(2))
                                    preparedStatement.setInt(3, 1)
                                    preparedStatement.setInt(4, 1)
                                    preparedStatement.setBoolean(5, res.getBoolean(4))
                                    preparedStatement.setString(6, res.getString(5))
                                    preparedStatement.executeUpdate()
                                }
                            session.prepareStatement("INSERT INTO owned_identity_details VALUES (?,?,?,?,?, ?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setInt(2, 1)
                                    val map = HashMap<String?, String?>()
                                    map.put("first_name", res.getString(3))
                                    try {
                                        preparedStatement.setString(
                                            3,
                                            objectMapper.writeValueAsString(map)
                                        )
                                    } catch (e: Exception) {
                                        Logger.x(e)
                                        // skip the owned identity!
                                        continue
                                    }
                                    preparedStatement.setString(4, null)
                                    preparedStatement.setBytes(5, null)
                                    preparedStatement.setBytes(6, null)
                                    preparedStatement.executeUpdate()
                                }
                        }
                    }
                    statement.execute("DROP TABLE old_owned_identities")
                }
                oldVersion = 5
            }
            if (oldVersion < 15 && newVersion >= 15) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `owned_identity` DATABASE FROM VERSION " + oldVersion + " TO 15")
                    statement.execute("ALTER TABLE owned_identity RENAME TO old_owned_identity")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS owned_identity (" +
                                " identity BLOB PRIMARY KEY, " +
                                " private_identity BLOB NOT NULL, " +
                                " published_details_version INT NOT NULL, " +
                                " latest_details_version INT NOT NULL, " +
                                " api_key VARCHAR NOT NULL, " +
                                " active BIT NOT NULL, " +
                                " FOREIGN KEY (identity, published_details_version) REFERENCES owned_identity_details(owned_identity, version)," +
                                " FOREIGN KEY (identity, latest_details_version) REFERENCES owned_identity_details(owned_identity, version));"
                    )
                    statement.execute("INSERT INTO owned_identity SELECT identity, private_identity, published_details_version, latest_details_version, api_key, 1 FROM old_owned_identity")
                    statement.execute("DROP TABLE old_owned_identity")
                }
                oldVersion = 15
            }
            if (oldVersion < 20 && newVersion >= 20) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `owned_identity` DATABASE FROM VERSION " + oldVersion + " TO 20")
                    statement.execute("ALTER TABLE owned_identity RENAME TO old_owned_identity")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS owned_identity (" +
                                " identity BLOB PRIMARY KEY, " +
                                " private_identity BLOB NOT NULL, " +
                                " published_details_version INT NOT NULL, " +
                                " latest_details_version INT NOT NULL, " +
                                " api_key VARCHAR NOT NULL, " +
                                " active BIT NOT NULL, " +
                                " keycloak_server_url TEXT, " +
                                " FOREIGN KEY (identity, published_details_version) REFERENCES owned_identity_details(owned_identity, version)," +
                                " FOREIGN KEY (identity, latest_details_version) REFERENCES owned_identity_details(owned_identity, version)," +
                                " FOREIGN KEY (identity, keycloak_server_url) REFERENCES keycloak_server(owned_identity, server_url) ON DELETE SET NULL);"
                    )
                    statement.execute("INSERT INTO owned_identity SELECT identity, private_identity, published_details_version, latest_details_version, api_key, active, NULL FROM old_owned_identity")
                    statement.execute("DROP TABLE old_owned_identity")
                }
                oldVersion = 20
            }
            if (oldVersion < 35 && newVersion >= 35) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `owned_identity` DATABASE FROM VERSION " + oldVersion + " TO 35")
                    // No need to save the api_key, it has already been saved on server side
                    statement.execute("ALTER TABLE owned_identity DROP COLUMN api_key")
                    statement.execute("ALTER TABLE owned_identity ADD COLUMN marked_for_deletion BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 35
            }
            if (oldVersion < 44 && newVersion >= 44) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `owned_identity` DATABASE FROM VERSION " + oldVersion + " TO 44")
                    // No need to save the api_key, it has already been saved on server side
                    statement.execute("ALTER TABLE owned_identity ADD COLUMN backup_seed BLOB")
                }
                oldVersion = 44
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?
        ): OwnedIdentity? {
            if ((ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "OwnedIdentity.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedIdentity(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun isActive(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?
        ): Boolean {
            if ((ownedIdentity == null)) {
                return false
            }
            identityManagerSession.session.prepareStatement(
                "OwnedIdentity.isActive",
                "SELECT " + ACTIVE + " FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return res.getBoolean(ACTIVE)
                    } else {
                        return false
                    }
                }
            }
        }

        // only returns owned identities that have not been marked for deletion
        @Throws(SQLException::class)
        fun getAll(identityManagerSession: IdentityManagerSession): Array<OwnedIdentity> {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentity.getAll",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + MARKED_FOR_DELETION + " == 0;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedIdentity> = ArrayList()
                    while (res.next()) {
                        list.add(OwnedIdentity(identityManagerSession, res))
                    }
                    return list.toTypedArray<OwnedIdentity>()
                }
            }
        }

        fun getSerializedPublishedDetails(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): String? {
            try {
                identityManagerSession.session.prepareStatement(
                    "OwnedIdentity.getSerializedPublishedDetails",
                    "SELECT details." + OwnedIdentityDetails.SERIALIZED_JSON_DETAILS +
                            " FROM " + TABLE_NAME + " AS identity " +
                            " INNER JOIN " + OwnedIdentityDetails.TABLE_NAME + " AS details " +
                            " ON identity." + OWNED_IDENTITY + " = details." + OwnedIdentityDetails.OWNED_IDENTITY +
                            " AND identity." + PUBLISHED_DETAILS_VERSION + " = details." + OwnedIdentityDetails.VERSION +
                            " WHERE identity." + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return res.getString(1)
                        }
                        return null
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }


        private const val HOOK_BIT_IDENTITY_LIST_CHANGED: Long = 0x1
        private const val HOOK_BIT_IDENTITY_DETAILS_PUBLISHED: Long = 0x2
        private const val HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED: Long = 0x4
        private const val HOOK_BIT_LATEST_IDENTITY_DETAILS_VERSION_CHANGED: Long = 0x8
        private const val HOOK_BIT_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS: Long = 0x10

        // endregion
        // region backup
        @Throws(SQLException::class)
        fun backupAll(identityManagerSession: IdentityManagerSession): Array<Pojo_0?> {
            val ownedIdentities: Array<OwnedIdentity> = getAll(identityManagerSession)
            val pojos = arrayOfNulls<Pojo_0>(ownedIdentities.size)
            for (i in ownedIdentities.indices) {
                pojos[i] = ownedIdentities[i].backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            pojo: Pojo_0,
            deviceDisplayName: String?,
            prng: PRNGService?
        ): ObvIdentity? {
            var ownedIdentity: Identity? = null
            try {
                ownedIdentity = Identity.of(pojo.owned_identity!!)
            } catch (e: DecodingException) {
                Logger.e("Error recreating OwnedIdentity from backup!")
                Logger.x(e)
            }
            if (ownedIdentity == null) {
                return null
            }
            val privateIdentity: PrivateIdentity? =
                Companion.restorePrivateIdentity(ownedIdentity, pojo.private_identity!!)
            if (privateIdentity == null) {
                return null
            }

            val published_details: OwnedIdentityDetails = OwnedIdentityDetails.restore(
                identityManagerSession,
                ownedIdentity,
                pojo.published_details!!
            )
            var latest_details: OwnedIdentityDetails? = null
            val latestDetailsPojo = pojo.latest_details
            if (latestDetailsPojo != null && latestDetailsPojo.version != pojo.published_details!!.version) {
                latest_details = OwnedIdentityDetails.restore(
                    identityManagerSession,
                    ownedIdentity,
                    latestDetailsPojo
                )
            }
            var backupSeed: BackupSeed? = null
            try {
                backupSeed = privateIdentity.getDeterministicBackupSeedForLegacyIdentity()
            } catch (_: Exception) {
                backupSeed = null
            }
            val ownedIdentityObject = OwnedIdentity(
                identityManagerSession,
                privateIdentity,
                backupSeed,
                published_details.version
            )
            if (latest_details != null) {
                ownedIdentityObject.latestDetailsVersion = latest_details.version
            }
            ownedIdentityObject.active = pojo.active!!
            ownedIdentityObject.insert()

            val keycloakPojo = pojo.keycloak
            if (keycloakPojo != null) {
                val keycloakServer: KeycloakServer? = KeycloakServer.restore(
                    identityManagerSession,
                    ownedIdentity,
                    keycloakPojo
                )
                if (keycloakServer != null) {
                    ownedIdentityObject.setKeycloakServerUrl(keycloakServer.serverUrl)
                }
            }

            val currentOwnedDevice: OwnedDevice = OwnedDevice.createCurrentDevice(
                identityManagerSession,
                ownedIdentity,
                deviceDisplayName,
                prng!!
            ) ?: return null
            // when restoring a backup, directly set all currentDevices to the most up to data capabilities
            // rationale: all channels will be recreated and contact devices will be notified properly.
            currentOwnedDevice.rawDeviceCapabilities = ObvCapability.capabilityListToStringArray(
                ObvCapability.currentCapabilities
            )


            // The ObvIdentity returned here contains the active status of the OwnedIdentity when it was backup
            // --> this will let the app determine if push notification registration is required
            return ObvIdentity(
                ownedIdentity, published_details.jsonIdentityDetails,
                ownedIdentityObject.isKeycloakManaged, pojo.active == null || pojo.active == true
            )
        }

        private fun restorePrivateIdentity(
            publicIdentity: Identity,
            pojo: PrivateIdentityPojo_0
        ): PrivateIdentity? {
            try {
                val serverAuthenticationPrivateKey =
                    Encoded(pojo.server_authentication_private_key!!).decodePrivateKey() as ServerAuthenticationPrivateKey?
                val encryptionPrivateKey =
                    Encoded(pojo.encryption_private_key!!).decodePrivateKey() as EncryptionPrivateKey?
                val macKey = Encoded(pojo.mac_key!!).decodeSymmetricKey() as MACKey?
                return PrivateIdentity(
                    publicIdentity,
                    serverAuthenticationPrivateKey!!,
                    encryptionPrivateKey!!,
                    macKey!!
                )
            } catch (_: DecodingException) {
                return null
            } catch (_: ClassCastException) {
                return null
            }
        }
    }
}
