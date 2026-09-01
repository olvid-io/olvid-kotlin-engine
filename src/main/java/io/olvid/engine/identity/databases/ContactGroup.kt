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
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.storage.EngineFile
import java.io.File
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Random

class ContactGroup : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val groupOwnerAndUid: ByteArray
    private var ownedIdentity: Identity
    @JvmField var groupOwner: Identity? = null // NULL for groups where you are the owner
    var publishedDetailsVersion: Int
        private set
    @JvmField var latestOrTrustedDetailsVersion: Int
    @JvmField var groupMembersVersion: Long

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    fun getGroupMembersVersion(): Long {
        return groupMembersVersion
    }

    @get:Throws(SQLException::class)
    val publishedDetails: ContactGroupDetails?
        get() = ContactGroupDetails.get(
            identityManagerSession,
            groupOwnerAndUid,
            ownedIdentity,
            publishedDetailsVersion
        )

    @get:Throws(SQLException::class)
    val latestOrTrustedDetails: ContactGroupDetails?
        get() = ContactGroupDetails.get(
            identityManagerSession,
            groupOwnerAndUid,
            ownedIdentity,
            latestOrTrustedDetailsVersion
        )

    val groupInformation: GroupInformation?
        get() {
            val serializedGroupDetailsWithVersionAndPhoto: String
            try {
                val jsonGroupDetailsWithVersionAndPhoto =
                    this.publishedDetails!!.jsonGroupDetailsWithVersionAndPhoto
                serializedGroupDetailsWithVersionAndPhoto =
                    identityManagerSession.jsonObjectMapper!!.writeValueAsString(
                        jsonGroupDetailsWithVersionAndPhoto
                    )
            } catch (_: Exception) {
                return null
            }
            val groupUid = UID(
                this.groupOwnerAndUid.copyOfRange(
                    this.groupOwnerAndUid.size - UID.UID_LENGTH,
                    this.groupOwnerAndUid.size
                )
            )
            return GroupInformation(
                (if (groupOwner == null) ownedIdentity else groupOwner)!!,
                groupUid,
                serializedGroupDetailsWithVersionAndPhoto
            )
        }


    // region setters
    // update details of a group you do not own. Returns true if details were indeed updated
    @Throws(Exception::class)
    fun updatePublishedDetails(
        jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?,
        allowDowngrade: Boolean
    ): Boolean {
        if (jsonGroupDetailsWithVersionAndPhoto == null) {
            return false
        }
        val newDetailsVersion = jsonGroupDetailsWithVersionAndPhoto.getVersion()
        if (!allowDowngrade && newDetailsVersion <= publishedDetailsVersion) {
            return false
        }

        if (allowDowngrade && newDetailsVersion <= publishedDetailsVersion) {
            // check whether anything changed
            val publishedDetails = this.publishedDetails
            if (newDetailsVersion == publishedDetailsVersion) {
                if (publishedDetails!!.jsonGroupDetails == jsonGroupDetailsWithVersionAndPhoto.getGroupDetails()) {
                    // details are the same, check photo labels
                    val newPhotoServerLabel =
                        if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel() == null) null else UID(
                            jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()!!
                        )
                    if ((newPhotoServerLabel == null && publishedDetails.photoServerLabel == null) ||
                        (newPhotoServerLabel != null && newPhotoServerLabel == publishedDetails.photoServerLabel)
                    ) {
                        // photo labels are the same, check keys
                        val newPhotoServerKey =
                            if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() == null) null else Encoded(
                                jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                            ).decodeSymmetricKey() as AuthEncKey?
                        if ((newPhotoServerKey == null && publishedDetails.photoServerKey == null) ||
                            (newPhotoServerKey != null && newPhotoServerKey == publishedDetails.photoServerKey)
                        ) {
                            // nothing changed, do nothing!
                            return false
                        }
                    }
                }
            }
            // something changed and we actually need to downgrade!
            // first, cleanup
            ContactGroupDetails.cleanup(
                identityManagerSession,
                ownedIdentity,
                groupOwnerAndUid,
                publishedDetailsVersion,
                latestOrTrustedDetailsVersion
            )
            // then move trusted details to number 0 if needed, and set trusted And published to 0 --> clean published details
            val trustedDetails = this.latestOrTrustedDetails
            if (latestOrTrustedDetailsVersion != -1) {
                val zeroedDetails: ContactGroupDetails? = ContactGroupDetails.copy(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerAndUid,
                    latestOrTrustedDetailsVersion,
                    -1
                )
                if (zeroedDetails == null) {
                    throw Exception("Failed to copy contact groupd details to version 0")
                }
                identityManagerSession.session.prepareStatement(
                    "ContactGroup.updatePublishedDetails",
                    "UPDATE " + TABLE_NAME +
                            " SET " + LATEST_OR_TRUSTED_DETAILS_VERSION + " = ?, " +
                            PUBLISHED_DETAILS_VERSION + " = ? " +
                            " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, -1)
                    statement.setInt(2, -1)
                    statement.setBytes(3, groupOwnerAndUid)
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.latestOrTrustedDetailsVersion = -1
                    this.publishedDetailsVersion = -1
                }
                trustedDetails!!.delete()
            } else {
                identityManagerSession.session.prepareStatement(
                    "ContactGroup.updatePublishedDetails",
                    "UPDATE " + TABLE_NAME +
                            " SET " + LATEST_OR_TRUSTED_DETAILS_VERSION + " = ?, " +
                            PUBLISHED_DETAILS_VERSION + " = ? " +
                            " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, -1)
                    statement.setInt(2, -1)
                    statement.setBytes(3, groupOwnerAndUid)
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.latestOrTrustedDetailsVersion = -1
                    this.publishedDetailsVersion = -1
                }
            }
            // now that the published details are no longer linked, remove them from DB
            if (publishedDetails!!.version != trustedDetails!!.version) {
                publishedDetails.delete()
            }
            // insert the new details
            val newPublishedDetails: ContactGroupDetails = ContactGroupDetails.create(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                jsonGroupDetailsWithVersionAndPhoto
            ) ?: return false
            if (newPublishedDetails.photoServerLabel != null &&
                newPublishedDetails.photoServerKey != null
            ) {
                val npsl = newPublishedDetails.photoServerLabel!!
                if (npsl == publishedDetails.photoServerLabel &&
                    newPublishedDetails.photoServerKey == publishedDetails.photoServerKey && publishedDetails.photoUrl != null
                ) {
                    // photo is the same, copy the photoUrl
                    newPublishedDetails.setPhotoUrl(publishedDetails.photoUrl, false)
                }
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroup.updatePublishedDetails",
                "UPDATE " + TABLE_NAME +
                        " SET " + PUBLISHED_DETAILS_VERSION + " = ? " +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, newPublishedDetails.version)
                statement.setBytes(2, groupOwnerAndUid)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.publishedDetailsVersion = newPublishedDetails.version
            }
        } else {
            val newPublishedDetails: ContactGroupDetails = ContactGroupDetails.create(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                jsonGroupDetailsWithVersionAndPhoto
            ) ?: return false
            val publishedDetails = this.publishedDetails
            if (newPublishedDetails.photoServerLabel != null &&
                newPublishedDetails.photoServerKey != null
            ) {
                val npsl2 = newPublishedDetails.photoServerLabel!!
                if (npsl2 == publishedDetails!!.photoServerLabel &&
                    newPublishedDetails.photoServerKey == publishedDetails.photoServerKey && publishedDetails.photoUrl != null
                ) {
                    // photo is the same, copy the photoUrl
                    newPublishedDetails.setPhotoUrl(publishedDetails.photoUrl, false)
                }
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroup.updatePublishedDetails",
                "UPDATE " + TABLE_NAME +
                        " SET " + PUBLISHED_DETAILS_VERSION + " = ? " +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, newPublishedDetails.version)
                statement.setBytes(2, groupOwnerAndUid)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.publishedDetailsVersion = newPublishedDetails.version
            }
        }
        // no need to notify if I am the group owner processing a propagated message
        if (groupOwner != null) {
            commitHookBits = commitHookBits or HOOK_BIT_NEW_PUBLISHED_DETAILS
            identityManagerSession.session.addSessionCommitListener(this)
        }
        return true
    }

    // trust the details of a group you do not own
    @Throws(SQLException::class)
    fun trustPublishedDetails(): JsonGroupDetailsWithVersionAndPhoto? {
        if (latestOrTrustedDetailsVersion == publishedDetailsVersion) {
            return null
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroup.trustPublishedDetails",
            "UPDATE " + TABLE_NAME +
                    " SET " + LATEST_OR_TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, publishedDetailsVersion)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.latestOrTrustedDetailsVersion = publishedDetailsVersion
        }
        hookDetails = this.latestOrTrustedDetails!!.jsonGroupDetailsWithVersionAndPhoto
        commitHookBits = commitHookBits or HOOK_BIT_PUBLISHED_DETAILS_TRUSTED
        identityManagerSession.session.addSessionCommitListener(this)
        return hookDetails
    }

    // set details of a group you own
    @Throws(Exception::class)
    fun setLatestDetails(groupDetails: JsonGroupDetails?) {
        if (groupOwner != null || groupDetails == null || groupDetails.isEmpty()) {
            return
        }
        val latestDetails = this.latestOrTrustedDetails!!.jsonGroupDetails
        if (latestDetails == groupDetails) {
            // nothing changed, so nothing to do
            return
        }
        if (publishedDetailsVersion != latestOrTrustedDetailsVersion) {
            val publishedDetails = this.publishedDetails!!.jsonGroupDetails
            if (publishedDetails == groupDetails) {
                // changes were reverted --> we discard
                discardLatestDetails()
                return
            }
        }
        // we indeed have a proper update to save
        val contactGroupDetails: ContactGroupDetails
        if (publishedDetailsVersion == latestOrTrustedDetailsVersion) {
            contactGroupDetails = ContactGroupDetails.copy(
                identityManagerSession,
                ownedIdentity,
                groupOwnerAndUid,
                publishedDetailsVersion,
                null
            )!!
            identityManagerSession.session.prepareStatement(
                "ContactGroup.setLatestDetails",
                "UPDATE " + TABLE_NAME + " SET " +
                        LATEST_OR_TRUSTED_DETAILS_VERSION + " = ? " +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ?" +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, contactGroupDetails.version)
                statement.setBytes(2, groupOwnerAndUid)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.latestOrTrustedDetailsVersion = contactGroupDetails.version
            }
        } else {
            contactGroupDetails = ContactGroupDetails.get(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                latestOrTrustedDetailsVersion
            )!!
        }
        contactGroupDetails.setJsonDetails(groupDetails)
    }

    // set the photo of a group you own
    @Throws(Exception::class)
    fun setOwnedGroupPhoto(srcAbsolutePhotoUrl: String?, partOfGroupCreation: Boolean) {
        if (groupOwner != null) {
            return
        }
        if (srcAbsolutePhotoUrl == null) {
            val contactGroupDetails: ContactGroupDetails
            if (publishedDetailsVersion == latestOrTrustedDetailsVersion) {
                contactGroupDetails = ContactGroupDetails.copy(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerAndUid,
                    publishedDetailsVersion,
                    null
                )!!
                identityManagerSession.session.prepareStatement(
                    "ContactGroup.setOwnedGroupPhoto",
                    "UPDATE " + TABLE_NAME + " SET " +
                            LATEST_OR_TRUSTED_DETAILS_VERSION + " = ? " +
                            " WHERE " + GROUP_OWNER_AND_UID + " = ?" +
                            " AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, contactGroupDetails.version)
                    statement.setBytes(2, groupOwnerAndUid)
                    statement.setBytes(3, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.latestOrTrustedDetailsVersion = contactGroupDetails.version
                }
            } else {
                contactGroupDetails = ContactGroupDetails.get(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    latestOrTrustedDetailsVersion
                )!!
            }
            contactGroupDetails.setPhotoUrl(null, true)
        } else {
            val srcPhotoFile = identityManagerSession.fileIo.file(srcAbsolutePhotoUrl)
            if (!srcPhotoFile.canRead()) {
                return
            }
            val contactGroupDetails: ContactGroupDetails
            if (partOfGroupCreation) {
                contactGroupDetails = ContactGroupDetails.get(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    publishedDetailsVersion
                )!!
            } else {
                if (publishedDetailsVersion == latestOrTrustedDetailsVersion) {
                    contactGroupDetails = ContactGroupDetails.copy(
                        identityManagerSession,
                        ownedIdentity,
                        groupOwnerAndUid,
                        publishedDetailsVersion,
                        null
                    )!!
                    identityManagerSession.session.prepareStatement(
                        "ContactGroup.setOwnedGroupPhoto",
                        "UPDATE " + TABLE_NAME + " SET " +
                                LATEST_OR_TRUSTED_DETAILS_VERSION + " = ? " +
                                " WHERE " + GROUP_OWNER_AND_UID + " = ?" +
                                " AND " + OWNED_IDENTITY + " = ?;"
                    ).use { statement ->
                        statement.setInt(1, contactGroupDetails.version)
                        statement.setBytes(2, groupOwnerAndUid)
                        statement.setBytes(3, ownedIdentity.getBytes())
                        statement.executeUpdate()
                        this.latestOrTrustedDetailsVersion = contactGroupDetails.version
                    }
                } else {
                    contactGroupDetails = ContactGroupDetails.get(
                        identityManagerSession,
                        groupOwnerAndUid,
                        ownedIdentity,
                        latestOrTrustedDetailsVersion
                    )!!
                }
            }

            // find a non-existing fileName
            val fileName = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
                groupOwnerAndUid.copyOfRange(groupOwnerAndUid.size - 32, groupOwnerAndUid.size)
            )
            var randFileName: String?
            val random = Random()
            var dstPhotoFile: EngineFile?
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
            contactGroupDetails.setPhotoUrl(randFileName, true)
        }
    }

    @Throws(SQLException::class)
    fun setPhotoLabelAndKey(version: Int, photoServerLabel: UID, photoServerKey: AuthEncKey?) {
        val contactGroupDetails: ContactGroupDetails? = ContactGroupDetails.get(
            identityManagerSession,
            groupOwnerAndUid,
            ownedIdentity,
            version
        )
        contactGroupDetails?.setPhotoServerLabelAndKey(photoServerLabel, photoServerKey!!)
    }

    // publish details of a group you own
    @Throws(SQLException::class)
    fun publishLatestDetails(): Int {
        if (latestOrTrustedDetailsVersion == publishedDetailsVersion) {
            return -1
        }
        val publishedDetails = this.publishedDetails
        val latestDetails = this.latestOrTrustedDetails
        identityManagerSession.session.prepareStatement(
            "ContactGroup.publishLatestDetails",
            "UPDATE " + TABLE_NAME + " SET " +
                    PUBLISHED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, latestOrTrustedDetailsVersion)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.publishedDetailsVersion = latestOrTrustedDetailsVersion
        }
        if (publishedDetails!!.photoUrl != null && (latestDetails!!.photoUrl == null || latestDetails.photoUrl != publishedDetails.photoUrl)) {
            if (publishedDetails.photoServerLabel != null) {
                labelToDelete = publishedDetails.photoServerLabel
                commitHookBits = commitHookBits or HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED
            }
        }
        commitHookBits = commitHookBits or HOOK_BIT_DETAILS_PUBLISHED
        hookDetails = latestDetails!!.jsonGroupDetailsWithVersionAndPhoto
        identityManagerSession.session.addSessionCommitListener(this)
        return latestOrTrustedDetailsVersion
    }

    @Throws(SQLException::class)
    fun discardLatestDetails() {
        if (latestOrTrustedDetailsVersion == publishedDetailsVersion) {
            return
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroup.discardLatestDetails",
            "UPDATE " + TABLE_NAME + " SET " +
                    LATEST_OR_TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, publishedDetailsVersion)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.latestOrTrustedDetailsVersion = publishedDetailsVersion
        }
    }

    // usually for group you do not own, but can be for owned groups after a backup restore or in multi-device
    @Throws(Exception::class)
    fun setDetailsDownloadedPhotoUrl(version: Int, photo: ByteArray) {
        val contactGroupDetails: ContactGroupDetails? = ContactGroupDetails.get(
            identityManagerSession,
            groupOwnerAndUid,
            ownedIdentity,
            version
        )

        if (contactGroupDetails == null) {
            return
        }

        // find a non-existing fileName
        val fileName = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
            groupOwnerAndUid.copyOfRange(groupOwnerAndUid.size - 32, groupOwnerAndUid.size)
        )
        var randFileName: String?
        val random = Random()
        var dstPhotoFile: EngineFile?
        do {
            randFileName = fileName + "_" + random.nextInt(65536)
            dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
        } while (dstPhotoFile.exists())

        dstPhotoFile.openOutput().use { os ->
            os.write(photo, 0, photo.size)
        }
        // update the details
        contactGroupDetails.setPhotoUrl(randFileName, false)
        if (groupOwner == null) {
            // groups you own
            hookDetails = contactGroupDetails.jsonGroupDetailsWithVersionAndPhoto
            commitHookBits = commitHookBits or HOOK_BIT_PUBLISHED_DETAILS_TRUSTED
        } else {
            // groups you do not own
            hookPhotoSetVersion = version
            commitHookBits = commitHookBits or HOOK_BIT_PHOTO_SET
        }
        identityManagerSession.session.addSessionCommitListener(this)
    }

    // for groups you own
    @Throws(Exception::class)
    fun incrementGroupMembersVersion() {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Called incrementGroupMembersVersion outside a transaction")
            throw Exception()
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroup.incrementGroupMembersVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + GROUP_MEMBERS_VERSION + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, groupMembersVersion + 1)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.groupMembersVersion += 1
        }
    }

    // for groups you do not own
    @Throws(Exception::class)
    fun setGroupMembersVersion(groupMembersVersion: Long) {
        identityManagerSession.session.prepareStatement(
            "ContactGroup.setGroupMembersVersion",
            "UPDATE " + TABLE_NAME +
                    " SET " + GROUP_MEMBERS_VERSION + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, groupMembersVersion)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.groupMembersVersion = groupMembersVersion
        }
    }


    constructor(
        identityManagerSession: IdentityManagerSession,
        groupOwnerAndUid: ByteArray,
        ownedIdentity: Identity,
        groupOwner: Identity?,
        version: Int
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = groupOwnerAndUid
        this.ownedIdentity = ownedIdentity
        this.groupOwner = groupOwner
        this.publishedDetailsVersion = version
        this.latestOrTrustedDetailsVersion = version
        this.groupMembersVersion = 0
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = res.getBytes(GROUP_OWNER_AND_UID)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            val bytes: ByteArray? = res.getBytes(GROUP_OWNER)
            this.groupOwner = if (bytes == null) null else Identity.of(bytes)
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.publishedDetailsVersion = res.getInt(PUBLISHED_DETAILS_VERSION)
        this.latestOrTrustedDetailsVersion = res.getInt(LATEST_OR_TRUSTED_DETAILS_VERSION)
        this.groupMembersVersion = res.getLong(GROUP_MEMBERS_VERSION)
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroup.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?);"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setBytes(3, groupOwner?.getBytes())
            statement.setInt(4, publishedDetailsVersion)
            statement.setInt(5, latestOrTrustedDetailsVersion)
            statement.setLong(6, groupMembersVersion)
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Running ContactGroup.delete() outside a transaction")
            throw SQLException()
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroup.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_DELETED
            identityManagerSession.session.addSessionCommitListener(this)
        }
        identityManagerSession.session.prepareStatement(
            "ContactGroup.delete",
            "DELETE FROM " + ContactGroupDetails.TABLE_NAME +
                    " WHERE " + ContactGroupDetails.GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + ContactGroupDetails.OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }


    // endregion
    // region hooks
    private var labelToDelete: UID? = null
    private var hookDetails: JsonGroupDetailsWithVersionAndPhoto? = null
    private var hookPhotoSetVersion = 0

    private var commitHookBits: Long = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_CREATED_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_CREATED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_CREATED_ON_OTHER_DEVICE_KEY] = (commitHookBits and HOOK_BIT_CREATED_ON_OTHER_DEVICE) != 0L
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_CREATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_DELETED_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_DELETED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DETAILS_PUBLISHED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_DETAILS_KEY] =
                hookDetails!!
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_NEW_PUBLISHED_DETAILS) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS_OWNED_IDENTITY_KEY] =
                ownedIdentity
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_PUBLISHED_DETAILS_TRUSTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_DETAILS_KEY] =
                hookDetails!!
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_PHOTO_SET) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_GROUP_OWNER_AND_UID_KEY] =
                groupOwnerAndUid
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_VERSION_KEY] =
                hookPhotoSetVersion
            userInfo[IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_IS_TRUSTED_KEY] =
                hookPhotoSetVersion == latestOrTrustedDetailsVersion
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY] =
                labelToDelete!!
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    @Throws(SQLException::class)
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.group_uid = this.groupOwnerAndUid.copyOfRange(
            this.groupOwnerAndUid.size - UID.UID_LENGTH,
            this.groupOwnerAndUid.size
        )
        if (groupOwner == null) {
            pojo.published_details = this.publishedDetails!!.backup()
            if (latestOrTrustedDetailsVersion != publishedDetailsVersion) {
                pojo.latest_details = this.latestOrTrustedDetails!!.backup()
            }
        } else {
            pojo.trusted_details = this.latestOrTrustedDetails!!.backup()
            if (publishedDetailsVersion != latestOrTrustedDetailsVersion) {
                pojo.published_details = this.publishedDetails!!.backup()
            }
        }
        pojo.group_members_version = groupMembersVersion
        pojo.members = ContactGroupMembersJoin.backupAll(
            identityManagerSession,
            ownedIdentity,
            groupOwnerAndUid
        )
        pojo.pending_members = PendingGroupMember.backupAll(
            identityManagerSession,
            ownedIdentity,
            groupOwnerAndUid
        )
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var group_uid: ByteArray? = null // only the uid, not the owner
        var published_details: ContactGroupDetails.Pojo_0? = null
        var latest_details: ContactGroupDetails.Pojo_0? = null
        var trusted_details: ContactGroupDetails.Pojo_0? = null
        var group_members_version: Long = 0
        var members: Array<ContactGroupMembersJoin.Pojo_0?>? = null
        var pending_members: Array<PendingGroupMember.Pojo_0?>? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group"

        const val GROUP_OWNER_AND_UID: String = "group_owner_and_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val GROUP_OWNER: String = "group_owner"
        const val PUBLISHED_DETAILS_VERSION: String = "published_details_version"
        const val LATEST_OR_TRUSTED_DETAILS_VERSION: String = "latest_or_trusted_details_version"
        const val GROUP_MEMBERS_VERSION: String = "group_members_version"

        // endregion
        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            groupUid: ByteArray?,
            ownedIdentity: Identity?,
            serializedGroupDetailsWithVersionAndPhoto: String?,
            groupOwner: Identity?,
            createdByMeOnOtherDevice: Boolean
        ): ContactGroup? {
            if ((groupUid == null) || (serializedGroupDetailsWithVersionAndPhoto == null) || (ownedIdentity == null)) {
                return null
            }
            val jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?
            try {
                jsonGroupDetailsWithVersionAndPhoto =
                    identityManagerSession.jsonObjectMapper!!.readValue(
                        serializedGroupDetailsWithVersionAndPhoto,
                        JsonGroupDetailsWithVersionAndPhoto::class.java
                    )
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }

            try {
                if (!identityManagerSession.session.isInTransaction) {
                    Logger.e("Calling ContactGroup.create() outside a transaction")
                    throw SQLException()
                }
                val contactGroupDetails: ContactGroupDetails? =
                    ContactGroupDetails.create(
                        identityManagerSession,
                        groupUid,
                        ownedIdentity,
                        jsonGroupDetailsWithVersionAndPhoto
                    )
                if (contactGroupDetails == null) {
                    Logger.e("Error create contactGroupDetails in ContactGroup.create()")
                    throw SQLException()
                }
                val contactGroup = ContactGroup(
                    identityManagerSession,
                    groupUid,
                    ownedIdentity,
                    groupOwner,
                    contactGroupDetails.version
                )
                contactGroup.insert()
                if (createdByMeOnOtherDevice) {
                    contactGroup.commitHookBits =
                        contactGroup.commitHookBits or HOOK_BIT_CREATED_ON_OTHER_DEVICE
                }
                return contactGroup
            } catch (e: SQLException) {
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
                            GROUP_OWNER_AND_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            GROUP_OWNER + " BLOB, " +  // NULL for groups you own
                            PUBLISHED_DETAILS_VERSION + " INT NOT NULL, " +
                            LATEST_OR_TRUSTED_DETAILS_VERSION + " INT NOT NULL, " +
                            GROUP_MEMBERS_VERSION + " BIGINT NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_OWNER_AND_UID + ", " + OWNED_IDENTITY + "), " +
                            " FOREIGN KEY (" + GROUP_OWNER + "," + OWNED_IDENTITY + ") REFERENCES " + ContactIdentity.TABLE_NAME + "(" + ContactIdentity.CONTACT_IDENTITY + "," + ContactIdentity.OWNED_IDENTITY + "), " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + "(" + OwnedIdentity.OWNED_IDENTITY + ")," +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + GROUP_OWNER_AND_UID + ", " + PUBLISHED_DETAILS_VERSION + ") REFERENCES " + ContactGroupDetails.TABLE_NAME + "(" + ContactGroupDetails.OWNED_IDENTITY + ", " + ContactGroupDetails.GROUP_OWNER_AND_UID + ", " + ContactGroupDetails.VERSION + ")," +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + GROUP_OWNER_AND_UID + ", " + LATEST_OR_TRUSTED_DETAILS_VERSION + ") REFERENCES " + ContactGroupDetails.TABLE_NAME + "(" + ContactGroupDetails.OWNED_IDENTITY + ", " + ContactGroupDetails.GROUP_OWNER_AND_UID + ", " + ContactGroupDetails.VERSION + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 11 && newVersion >= 11) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING contact_group DATABASE FROM VERSION " + oldVersion + " TO 11")
                    statement.execute("ALTER TABLE contact_group RENAME TO old_contact_group")
                    statement.execute(
                        "CREATE TABLE contact_group_details (" +
                                " group_owner_and_uid BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " version INT NOT NULL, " +
                                " serialized_json_details TEXT NOT NULL, " +
                                " photo_url TEXT, " +
                                " photo_server_label BLOB, " +
                                " photo_server_key BLOB, " +
                                " CONSTRAINT PK_contact_group_details PRIMARY KEY(group_owner_and_uid, owned_identity, version));"
                    )
                    statement.execute(
                        "CREATE TABLE contact_group (" +
                                " group_owner_and_uid BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " group_owner BLOB, " +
                                " published_details_version INT NOT NULL, " +
                                " latest_or_trusted_details_version INT NOT NULL, " +
                                " group_members_version BIGINT NOT NULL, " +
                                " CONSTRAINT PK_contact_group PRIMARY KEY(group_owner_and_uid, owned_identity), " +
                                " FOREIGN KEY (group_owner,owned_identity) REFERENCES contact_identity(identity,owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity(identity), " +
                                " FOREIGN KEY (owned_identity, group_owner_and_uid, published_details_version) REFERENCES contact_group_details(owned_identity, group_owner_and_uid, version), " +
                                " FOREIGN KEY (owned_identity, group_owner_and_uid, latest_or_trusted_details_version) REFERENCES contact_group_details(owned_identity, group_owner_and_uid, version));"
                    )
                    val objectMapper = ObjectMapper()
                    statement.executeQuery("SELECT * FROM old_contact_group").use { res ->
                        while (res.next()) {
                            session.prepareStatement("INSERT INTO contact_group VALUES (?,?,?,?,?, ?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setBytes(2, res.getBytes(2))
                                    preparedStatement.setBytes(3, res.getBytes(4))
                                    preparedStatement.setInt(4, 0)
                                    preparedStatement.setInt(5, 0)
                                    preparedStatement.setInt(6, 0)
                                    preparedStatement.executeUpdate()
                                }
                            session.prepareStatement("INSERT INTO contact_group_details VALUES (?,?,?,?,?, ?,?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setBytes(2, res.getBytes(2))
                                    preparedStatement.setInt(3, 0)
                                    val map = HashMap<String?, String?>()
                                    map["name"] = res.getString(3)
                                    try {
                                        preparedStatement.setString(
                                            4,
                                            objectMapper.writeValueAsString(map)
                                        )
                                    } catch (_: Exception) {
                                        Logger.e("\n\n\n\nMIGRATION ERROR!!!\n\n\n")
                                        throw SQLException()
                                    }
                                    preparedStatement.setString(5, null)
                                    preparedStatement.setBytes(6, null)
                                    preparedStatement.setBytes(7, null)
                                    preparedStatement.executeUpdate()
                                }
                        }
                    }
                    statement.execute("DROP TABLE old_contact_group")
                }
                oldVersion = 11
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            groupOwnerAndUid: ByteArray?,
            ownedIdentity: Identity
        ): ContactGroup? {
            identityManagerSession.session.prepareStatement(
                "ContactGroup.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + GROUP_OWNER_AND_UID + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupOwnerAndUid)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    return if (res.next()) {
                        ContactGroup(identityManagerSession, res)
                    } else {
                        null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAll(identityManagerSession: IdentityManagerSession): Array<ContactGroup?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroup.getAll",
                "SELECT * FROM " + TABLE_NAME + ";"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroup?> = ArrayList()
                    while (res.next()) {
                        val contactGroup = ContactGroup(identityManagerSession, res)
                        list.add(contactGroup)
                    }
                    return list.toTypedArray<ContactGroup?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllForIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): Array<ContactGroup> {
            identityManagerSession.session.prepareStatement(
                "ContactGroup.getAllForIdentity",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroup> = ArrayList()
                    while (res.next()) {
                        val contactGroup = ContactGroup(identityManagerSession, res)
                        list.add(contactGroup)
                    }
                    return list.toTypedArray<ContactGroup>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllForOwnedIdentityAndOwner(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwner: Identity
        ): Array<ContactGroup?> {
            if (ownedIdentity == groupOwner) {
                identityManagerSession.session.prepareStatement(
                    "ContactGroup.getAllForOwnedIdentityAndOwner",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + GROUP_OWNER + " IS NULL;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactGroup?> = ArrayList()
                        while (res.next()) {
                            val contactGroup = ContactGroup(identityManagerSession, res)
                            list.add(contactGroup)
                        }
                        return list.toTypedArray<ContactGroup?>()
                    }
                }
            } else {
                identityManagerSession.session.prepareStatement(
                    "ContactGroup.getAllForOwnedIdentityAndOwner",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + GROUP_OWNER + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, groupOwner.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactGroup?> = ArrayList()
                        while (res.next()) {
                            val contactGroup = ContactGroup(identityManagerSession, res)
                            list.add(contactGroup)
                        }
                        return list.toTypedArray<ContactGroup?>()
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getGroupOwnerAndUidsOfGroupsOwnedByContact(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): Array<ByteArray?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroup.getGroupOwnerAndUidsOfOwnedGroupsWithContact",
                "SELECT " + GROUP_OWNER_AND_UID + " FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + GROUP_OWNER + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ByteArray?> = ArrayList()
                    while (res.next()) {
                        list.add(res.getBytes(GROUP_OWNER_AND_UID))
                    }
                    return list.toTypedArray<ByteArray?>()
                }
            }
        }

        @Throws(SQLException::class)
        fun getGroupOwnerAndUidsOfOwnedGroupsWithContact(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): Array<ByteArray?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroup.getGroupOwnerAndUidsOfOwnedGroupsWithContact",
                "SELECT g." + GROUP_OWNER_AND_UID +
                        " FROM " + TABLE_NAME + " AS g " +
                        " INNER JOIN " + ContactGroupMembersJoin.TABLE_NAME + " AS j " +
                        " ON g." + GROUP_OWNER_AND_UID + " = j." + ContactGroupMembersJoin.GROUP_OWNER_AND_UID +
                        " AND g." + OWNED_IDENTITY + " = j." + ContactGroupMembersJoin.OWNED_IDENTITY +
                        " WHERE g." + OWNED_IDENTITY + " = ? " +
                        " AND g." + GROUP_OWNER + " IS NULL " +
                        " AND j." + ContactGroupMembersJoin.CONTACT_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ByteArray?> = ArrayList()
                    while (res.next()) {
                        list.add(res.getBytes(GROUP_OWNER_AND_UID))
                    }
                    return list.toTypedArray<ByteArray?>()
                }
            }
        }


        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_DELETED: Long = 0x2
        private const val HOOK_BIT_PUBLISHED_DETAILS_TRUSTED: Long = 0x4
        private const val HOOK_BIT_NEW_PUBLISHED_DETAILS: Long = 0x8
        private const val HOOK_BIT_PHOTO_SET: Long = 0x10
        private const val HOOK_BIT_DETAILS_PUBLISHED: Long = 0x20
        private const val HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED: Long = 0x40
        private const val HOOK_BIT_CREATED_ON_OTHER_DEVICE: Long = 0x80

        // endregion
        // region backup
        @Throws(SQLException::class)
        fun backupAllForOwner(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerIdentity: Identity
        ): Array<Pojo_0?> {
            val contactGroups: Array<ContactGroup?> = getAllForOwnedIdentityAndOwner(
                identityManagerSession,
                ownedIdentity,
                groupOwnerIdentity
            )
            val pojos = arrayOfNulls<Pojo_0>(contactGroups.size)
            for (i in contactGroups.indices) {
                pojos[i] = contactGroups[i]!!.backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restoreAllForOwner(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwner: Identity,
            pojos: Array<Pojo_0>?,
            backupTimestamp: Long
        ) {
            if (pojos == null) {
                return
            }
            for (pojo in pojos) {
                restoreForOwner(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwner,
                    pojo,
                    backupTimestamp
                )
            }
        }

        @Throws(SQLException::class)
        fun restoreForOwner(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwner: Identity,
            pojo: Pojo_0,
            @Suppress("unused") backupTimestamp: Long
        ) {
            val groupOwnerAndUid = ByteArray(groupOwner.getBytes().size + UID.UID_LENGTH)
            System.arraycopy(
                groupOwner.getBytes(),
                0,
                groupOwnerAndUid,
                0,
                groupOwner.getBytes().size
            )
            System.arraycopy(
                pojo.group_uid!!,
                0,
                groupOwnerAndUid,
                groupOwner.getBytes().size,
                UID.UID_LENGTH
            )

            identityManagerSession.session.startTransaction()
            if (groupOwner == ownedIdentity) {
                // owned group
                val publishedDetails: ContactGroupDetails = ContactGroupDetails.restore(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerAndUid,
                    pojo.published_details!!,
                    true
                )
                var latestDetails: ContactGroupDetails? = null
                val latestDetailsPojo = pojo.latest_details
                if (latestDetailsPojo != null && latestDetailsPojo.version != pojo.published_details!!.version) {
                    latestDetails = ContactGroupDetails.restore(
                        identityManagerSession,
                        ownedIdentity,
                        groupOwnerAndUid,
                        latestDetailsPojo,
                        true
                    )
                }
                val contactGroup = ContactGroup(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    null,
                    publishedDetails.version
                )
                if (latestDetails != null) {
                    contactGroup.latestOrTrustedDetailsVersion = latestDetails.version
                }
                contactGroup.insert()
            } else {
                // joined group
                val trustedDetails: ContactGroupDetails = ContactGroupDetails.restore(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerAndUid,
                    pojo.trusted_details!!,
                    false
                )
                var publishDetails: ContactGroupDetails? = null
                val publishedDetailsPojo = pojo.published_details
                if (publishedDetailsPojo != null && pojo.trusted_details!!.version != publishedDetailsPojo.version) {
                    publishDetails = ContactGroupDetails.restore(
                        identityManagerSession,
                        ownedIdentity,
                        groupOwnerAndUid,
                        publishedDetailsPojo,
                        false
                    )
                }
                val contactGroup = ContactGroup(
                    identityManagerSession,
                    groupOwnerAndUid,
                    ownedIdentity,
                    groupOwner,
                    trustedDetails.version
                )
                if (publishDetails != null) {
                    contactGroup.publishedDetailsVersion = publishDetails.version
                }
                contactGroup.groupMembersVersion = pojo.group_members_version
                contactGroup.insert()
            }

            // now add members and pending
            @Suppress("UNCHECKED_CAST")
            ContactGroupMembersJoin.restoreAll(
                identityManagerSession,
                ownedIdentity,
                groupOwnerAndUid,
                pojo.members as Array<ContactGroupMembersJoin.Pojo_0>?
            )
            @Suppress("UNCHECKED_CAST")
            PendingGroupMember.restoreAll(
                identityManagerSession,
                ownedIdentity,
                groupOwnerAndUid,
                pojo.pending_members as Array<PendingGroupMember.Pojo_0>?
            )
            identityManagerSession.session.commit()
        }
    }
}
