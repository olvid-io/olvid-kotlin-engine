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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncAtom.DiscussionIdentifier
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.io.File
import java.sql.ResultSet
import java.sql.SQLException

// A photo the user set on a contact or group for themselves only, or the published photo they chose to hide.
// A photo is uploaded as owned user data so that other owned devices, transfers and backups can download it with
// the label and key. A hidden photo has no label nor key.
class CustomPhoto : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    val ownedIdentity: Identity
    val target: DiscussionIdentifier
    val serverPhotoInfo: GroupV2.ServerPhotoInfo? // null when hidden
    var photoUrl: String? // relative to the engine base directory, null until downloaded
        private set

    private var commitHookBits = 0L

    val isHidden: Boolean
        get() = serverPhotoInfo == null

    private constructor(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity,
        target: DiscussionIdentifier,
        serverPhotoInfo: GroupV2.ServerPhotoInfo?,
        photoUrl: String?,
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = ownedIdentity
        this.target = target
        this.serverPhotoInfo = serverPhotoInfo
        this.photoUrl = photoUrl
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            this.target = DiscussionIdentifier(res.getInt(TARGET_TYPE), res.getBytes(TARGET))
            val label = res.getBytes(LABEL)
            val key = res.getBytes(KEY)
            this.serverPhotoInfo = if (label != null && key != null) GroupV2.ServerPhotoInfo(ownedIdentity, UID(label), Encoded(key).decodeSymmetricKey() as AuthEncKey) else null
            this.photoUrl = res.getString(PHOTO_URL)
        } catch (_: DecodingException) {
            throw SQLException()
        }
    }

    @Throws(Exception::class)
    fun setDownloadedPhoto(photo: ByteArray) {
        val relativePhotoUrl = newPhotoUrl(identityManagerSession, serverPhotoInfo!!.serverPhotoLabel)
        identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, relativePhotoUrl).openOutput().use { os ->
            os.write(photo, 0, photo.size)
        }
        identityManagerSession.session.prepareStatement(
            "CustomPhoto.setDownloadedPhoto",
            "UPDATE " + TABLE_NAME + " SET " + PHOTO_URL + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ? AND " + TARGET_TYPE + " = ? AND " + TARGET + " = ?;"
        ).use { statement ->
            statement.setString(1, relativePhotoUrl)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, target.type)
            statement.setBytes(4, target.bytesDiscussionIdentifier)
            statement.executeUpdate()
        }
        this.photoUrl = relativePhotoUrl
        commitHookBits = commitHookBits or HOOK_BIT_NOTIFY_APP
        identityManagerSession.session.addSessionCommitListener(this)
    }

    // the server copy is deleted after commit, the local file by the next photo cleanup
    @Throws(SQLException::class)
    fun deleteAndReleaseServerCopy(notifyApp: Boolean) {
        delete()
        if (serverPhotoInfo != null) {
            ServerUserData.get(identityManagerSession, ownedIdentity, serverPhotoInfo.serverPhotoLabel)?.delete()
            commitHookBits = commitHookBits or HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED
        }
        if (notifyApp) {
            commitHookBits = commitHookBits or HOOK_BIT_NOTIFY_APP
        }
        identityManagerSession.session.addSessionCommitListener(this)
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "CustomPhoto.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setInt(2, target.type)
            statement.setBytes(3, target.bytesDiscussionIdentifier)
            statement.setBytes(4, serverPhotoInfo?.serverPhotoLabel?.bytes)
            statement.setBytes(5, serverPhotoInfo?.let { Encoded.of(it.serverPhotoKey).bytes })
            statement.setString(6, photoUrl)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "CustomPhoto.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? AND " + TARGET_TYPE + " = ? AND " + TARGET + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity.getBytes())
            statement.setInt(2, target.type)
            statement.setBytes(3, target.bytesDiscussionIdentifier)
            statement.executeUpdate()
        }
    }

    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_OWNED_IDENTITY_KEY] = ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY] = serverPhotoInfo!!.serverPhotoLabel
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_NOTIFY_APP) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED_OWNED_IDENTITY_KEY] = ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED_TARGET_KEY] = target
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED,
                userInfo
            )
        }
        commitHookBits = 0
    }

    companion object {
        const val TABLE_NAME: String = "custom_photo"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val TARGET_TYPE: String = "target_type" // a DiscussionIdentifier type
        const val TARGET: String = "target"
        const val LABEL: String = "label"
        const val KEY: String = "key"
        const val PHOTO_URL: String = "photo_url"

        private const val HOOK_BIT_SERVER_USER_DATA_CAN_BE_DELETED: Long = 0x1
        private const val HOOK_BIT_NOTIFY_APP: Long = 0x2

        private fun newPhotoUrl(identityManagerSession: IdentityManagerSession, label: UID): String {
            var photoUrl: String
            var i = 0
            do {
                photoUrl = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + "custom_" + Logger.toHexString(label.bytes) + "_" + i
                i++
            } while (identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, photoUrl).exists())
            return photoUrl
        }

        // region constructors

        // copies the photo, the caller uploads it
        @Throws(Exception::class)
        fun createFromLocalPhoto(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            target: DiscussionIdentifier,
            serverPhotoInfo: GroupV2.ServerPhotoInfo,
            absolutePhotoUrl: String,
        ): CustomPhoto {
            val photoUrl = newPhotoUrl(identityManagerSession, serverPhotoInfo.serverPhotoLabel)
            identityManagerSession.fileIo.file(absolutePhotoUrl).openInput().use { inputStream ->
                identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, photoUrl).openOutput().use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
            val customPhoto = CustomPhoto(identityManagerSession, ownedIdentity, target, serverPhotoInfo, photoUrl)
            customPhoto.insertWithServerUserData()
            return customPhoto
        }

        // from another device or a snapshot: the photo is downloaded later
        @Throws(SQLException::class)
        fun createToDownload(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            target: DiscussionIdentifier,
            serverPhotoInfo: GroupV2.ServerPhotoInfo,
        ): CustomPhoto {
            val customPhoto = CustomPhoto(identityManagerSession, ownedIdentity, target, serverPhotoInfo, null)
            customPhoto.insertWithServerUserData()
            return customPhoto
        }

        @Throws(SQLException::class)
        fun createHidden(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            target: DiscussionIdentifier,
            notifyApp: Boolean,
        ): CustomPhoto {
            val customPhoto = CustomPhoto(identityManagerSession, ownedIdentity, target, null, null)
            customPhoto.insert()
            if (notifyApp) {
                customPhoto.commitHookBits = HOOK_BIT_NOTIFY_APP
                identityManagerSession.session.addSessionCommitListener(customPhoto)
            }
            return customPhoto
        }

        @Throws(SQLException::class)
        private fun CustomPhoto.insertWithServerUserData() {
            insert()
            val label = serverPhotoInfo!!.serverPhotoLabel
            if (ServerUserData.get(identityManagerSession, ownedIdentity, label) == null) {
                ServerUserData.createForCustomPhoto(identityManagerSession, ownedIdentity, label)
            }
        }

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            TARGET_TYPE + " INT NOT NULL, " +
                            TARGET + " BLOB NOT NULL, " +
                            LABEL + " BLOB, " +
                            KEY + " BLOB, " +
                            PHOTO_URL + " TEXT, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + TARGET_TYPE + ", " + TARGET + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 54 && newVersion >= 54) {
                Logger.d("CREATING `custom_photo` TABLE AS PART OF VERSION 54")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS custom_photo (" +
                                " owned_identity BLOB NOT NULL, " +
                                " target_type INT NOT NULL, " +
                                " target BLOB NOT NULL, " +
                                " label BLOB, " +
                                " key BLOB, " +
                                " photo_url TEXT, " +
                                " CONSTRAINT PK_custom_photo PRIMARY KEY(owned_identity, target_type, target));"
                    )
                }
                oldVersion = 54
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            target: DiscussionIdentifier,
        ): CustomPhoto? {
            identityManagerSession.session.prepareStatement(
                "CustomPhoto.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? AND " + TARGET_TYPE + " = ? AND " + TARGET + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setInt(2, target.type)
                statement.setBytes(3, target.bytesDiscussionIdentifier)
                statement.executeQuery().use { res ->
                    return if (res.next()) CustomPhoto(identityManagerSession, res) else null
                }
            }
        }

        @Throws(SQLException::class)
        fun getByLabel(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            label: UID,
        ): CustomPhoto? {
            identityManagerSession.session.prepareStatement(
                "CustomPhoto.getByLabel",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + LABEL + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, label.bytes)
                statement.executeQuery().use { res ->
                    return if (res.next()) CustomPhoto(identityManagerSession, res) else null
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithMissingPhotoUrl(identityManagerSession: IdentityManagerSession): List<CustomPhoto> {
            identityManagerSession.session.prepareStatement(
                "CustomPhoto.getAllWithMissingPhotoUrl",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + PHOTO_URL + " IS NULL AND " + LABEL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list = ArrayList<CustomPhoto>()
                    while (res.next()) {
                        list.add(CustomPhoto(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllPhotoUrl(identityManagerSession: IdentityManagerSession): List<String> {
            identityManagerSession.session.prepareStatement(
                "CustomPhoto.getAllPhotoUrl",
                "SELECT " + PHOTO_URL + " FROM " + TABLE_NAME + " WHERE " + PHOTO_URL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list = ArrayList<String>()
                    while (res.next()) {
                        list.add(res.getString(1))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteAllForOwnedIdentity(identityManagerSession: IdentityManagerSession, ownedIdentity: Identity) {
            identityManagerSession.session.prepareStatement(
                "CustomPhoto.deleteAllForOwnedIdentity",
                "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }
        // endregion
    }
}
