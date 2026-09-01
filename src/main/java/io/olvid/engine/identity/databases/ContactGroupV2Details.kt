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
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.storage.EngineFile
import java.io.File
import java.io.IOException
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Random

class ContactGroupV2Details : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession


    @JvmField val groupUid: UID
    private val serverUrl: String
    private val category: Int
    @JvmField val ownedIdentity: Identity
    @JvmField val version: Int
    var serializedJsonDetails: String?
        private set
    private var photoUrl: String?
    var photoServerIdentity: Identity? = null // this is null for Keycloak groups with a photo
        private set
    var photoServerLabel: UID? = null
        private set
    var photoServerKey: AuthEncKey? = null
        private set

    fun getPhotoUrl(): String? {
        return photoUrl
    }

    val serverPhotoInfo: ServerPhotoInfo?
        get() {
            if ((photoServerLabel == null) || (photoServerKey == null)) {
                return null
            }
            return ServerPhotoInfo(photoServerIdentity, photoServerLabel!!, photoServerKey!!)
        }

    val groupIdentifier: GroupV2.Identifier
        get() = GroupV2.Identifier(
            groupUid,
            serverUrl,
            category
        )

    constructor(
        identityManagerSession: IdentityManagerSession,
        groupUid: UID,
        serverUrl: String,
        category: Int,
        ownedIdentity: Identity,
        version: Int,
        serializedJsonDetails: String?,
        photoUrl: String?,
        photoServerIdentity: Identity?,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = groupUid
        this.serverUrl = serverUrl
        this.category = category
        this.ownedIdentity = ownedIdentity
        this.version = version
        this.serializedJsonDetails = serializedJsonDetails
        this.photoUrl = photoUrl
        this.photoServerIdentity = photoServerIdentity
        this.photoServerLabel = photoServerLabel
        this.photoServerKey = photoServerKey
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupUid = UID(res.getBytes(GROUP_UID))
        this.serverUrl = res.getString(SERVER_URL)
        this.category = res.getInt(CATEGORY)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.version = res.getInt(VERSION)
        this.serializedJsonDetails = res.getString(SERIALIZED_JSON_DETAILS)
        this.photoUrl = res.getString(PHOTO_URL)
        var bytes: ByteArray? = res.getBytes(PHOTO_SERVER_IDENTITY)
        if (bytes == null) {
            this.photoServerIdentity = null
        } else {
            try {
                this.photoServerIdentity = Identity.of(bytes)
            } catch (_: DecodingException) {
                this.photoServerIdentity = null
            }
        }
        bytes = res.getBytes(PHOTO_SERVER_LABEL)
        if (bytes == null) {
            this.photoServerLabel = null
        } else {
            this.photoServerLabel = UID(bytes)
        }
        bytes = res.getBytes(PHOTO_SERVER_KEY)
        if (bytes == null) {
            this.photoServerKey = null
        } else {
            try {
                this.photoServerKey = Encoded(bytes).decodeSymmetricKey() as AuthEncKey?
            } catch (_: DecodingException) {
                this.photoServerKey = null
            }
        }
    }


    @Throws(SQLException::class)
    fun setPhotoUrl(photoUrl: String?) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2Details.setPhotoUrl",
            "UPDATE " + TABLE_NAME +
                    " SET " + PHOTO_URL + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, photoUrl)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.setInt(6, version)
            statement.executeUpdate()
            this.photoUrl = photoUrl
        }
    }

    @Throws(Exception::class)
    fun setAbsolutePhotoUrl(absolutePhotoUrl: String) {
        // copy the photo
        val fileName =
            Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(groupUid.bytes)
        var randFileName: String? = null
        val random = Random()
        var dstPhotoFile: EngineFile? = null
        do {
            randFileName = fileName + "_" + random.nextInt(65536)
            dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
        } while (dstPhotoFile.exists())

        // copy the file
        val srcPhotoFile = identityManagerSession.fileIo.file(absolutePhotoUrl)
        srcPhotoFile.openInput().use { `is` ->
            dstPhotoFile.openOutput().use { os ->
                val buffer = ByteArray(4096)
                var length: Int
                while ((`is`.read(buffer).also { length = it }) > 0) {
                    os.write(buffer, 0, length)
                }
            }
        }
        photoUrl = randFileName

        identityManagerSession.session.prepareStatement(
            "ContactGroupV2Details.setAbsolutePhotoUrl",
            "UPDATE " + TABLE_NAME +
                    " SET " + PHOTO_URL + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, photoUrl)
            statement.setBytes(2, groupUid.bytes)
            statement.setString(3, serverUrl)
            statement.setInt(4, category)
            statement.setBytes(5, ownedIdentity.getBytes())
            statement.setInt(6, version)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2Details.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setInt(5, version)

            statement.setString(6, serializedJsonDetails)
            statement.setString(7, photoUrl)
            statement.setBytes(
                8,
                if (photoServerIdentity == null) null else photoServerIdentity!!.getBytes()
            )
            statement.setBytes(9, if (photoServerLabel == null) null else photoServerLabel!!.bytes)
            statement.setBytes(
                10,
                if (photoServerKey == null) null else Encoded.of(photoServerKey!!).bytes
            )
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun update() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2Details.update",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_JSON_DETAILS + " = ?, " +
                    PHOTO_URL + " = ?, " +
                    PHOTO_SERVER_IDENTITY + " = ?, " +
                    PHOTO_SERVER_LABEL + " = ?, " +
                    PHOTO_SERVER_KEY + " = ? " +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, serializedJsonDetails)
            statement.setString(2, photoUrl)
            statement.setBytes(
                3,
                if (photoServerIdentity == null) null else photoServerIdentity!!.getBytes()
            )
            statement.setBytes(4, if (photoServerLabel == null) null else photoServerLabel!!.bytes)
            statement.setBytes(
                5,
                if (photoServerKey == null) null else Encoded.of(photoServerKey!!).bytes
            )

            statement.setBytes(6, groupUid.bytes)
            statement.setString(7, serverUrl)
            statement.setInt(8, category)
            statement.setBytes(9, ownedIdentity.getBytes())
            statement.setInt(10, version)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupV2Details.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + GROUP_UID + " = ? " +
                    " AND " + SERVER_URL + " = ? " +
                    " AND " + CATEGORY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupUid.bytes)
            statement.setString(2, serverUrl)
            statement.setInt(3, category)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setInt(5, version)
            statement.executeUpdate()
        }
    }

    // endregion
    override fun wasCommitted() {
    }


    // region backup
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.serialized_details = serializedJsonDetails
        if (photoServerLabel != null && photoServerKey != null) {
            pojo.photo_server_identity =
                if (photoServerIdentity == null) null else photoServerIdentity!!.getBytes()
            pojo.photo_server_label = photoServerLabel!!.bytes
            pojo.photo_server_key = Encoded.of(photoServerKey!!).bytes
        }
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var serialized_details: String? = null
        var photo_server_identity: ByteArray? = null
        var photo_server_label: ByteArray? = null
        var photo_server_key: ByteArray? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group_v2_details"

        const val GROUP_UID: String = "group_uid"
        const val SERVER_URL: String = "server_url"
        const val CATEGORY: String = "category"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val VERSION: String = "version"
        const val SERIALIZED_JSON_DETAILS: String = "serialized_json_details"
        const val PHOTO_URL: String = "photo_url"
        const val PHOTO_SERVER_IDENTITY: String = "photo_server_identity"
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"

        // region Constructor
        fun createNew(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            serializedGroupDetails: String?,
            absolutePhotoUrl: String?,
            serverPhotoInfo: ServerPhotoInfo?
        ): ContactGroupV2Details? {
            if ((groupIdentifier == null) || (ownedIdentity == null) || (serializedGroupDetails == null)) {
                return null
            }

            try {
                var photoUrl: String? = null

                if (absolutePhotoUrl != null) {
                    if ((serverPhotoInfo == null)) {
                        Logger.e("Calling ContactGroupV2Details.createNew with a photoUrl and no label or key")
                        return null
                    }

                    try {
                        // copy the file to the appropriate place
                        val fileName =
                            Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
                                groupIdentifier.groupUid.bytes
                            )
                        var randFileName: String? = null
                        val random = Random()
                        var dstPhotoFile: EngineFile? = null
                        do {
                            randFileName = fileName + "_" + random.nextInt(65536)
                            dstPhotoFile =
                                identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
                        } while (dstPhotoFile.exists())

                        // copy the file
                        val srcPhotoFile = identityManagerSession.fileIo.file(absolutePhotoUrl)
                        srcPhotoFile.openInput().use { `is` ->
                            dstPhotoFile.openOutput().use { os ->
                                val buffer = ByteArray(4096)
                                var length: Int
                                while ((`is`.read(buffer).also { length = it }) > 0) {
                                    os.write(buffer, 0, length)
                                }
                            }
                        }
                        photoUrl = randFileName
                    } catch (e: IOException) {
                        Logger.x(e)
                        Logger.w("Error copying the photo for the groupV2 --> creating a group without photo")
                    }
                }

                val version = 0
                val contactGroupDetails: ContactGroupV2Details?
                if (photoUrl == null) {
                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        null,
                        null,
                        null,
                        null
                    )
                } else {
                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        photoUrl,
                        serverPhotoInfo!!.serverPhotoIdentity,
                        serverPhotoInfo.serverPhotoLabel,
                        serverPhotoInfo.serverPhotoKey
                    )
                }
                contactGroupDetails.insert()
                return contactGroupDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }


        fun createJoined(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier,
            version: Int,
            serializedGroupDetails: String?,
            serverPhotoInfo: ServerPhotoInfo?
        ): ContactGroupV2Details? {
            try {
                val contactGroupDetails: ContactGroupV2Details?
                if (serverPhotoInfo == null) {
                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        null,
                        null,
                        null,
                        null
                    )
                } else {
                    // check if we have a photoUrl to copy from previous versions
                    var photoUrl: String? = null
                    for (otherDetails in getAll(
                        identityManagerSession,
                        ownedIdentity,
                        groupIdentifier
                    )!!) {
                        if (otherDetails.photoUrl != null && otherDetails.serverPhotoInfo == serverPhotoInfo) {
                            photoUrl = otherDetails.photoUrl
                            break
                        }
                    }

                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        photoUrl,
                        serverPhotoInfo.serverPhotoIdentity,
                        serverPhotoInfo.serverPhotoLabel,
                        serverPhotoInfo.serverPhotoKey
                    )
                }
                contactGroupDetails.insert()
                return contactGroupDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }


        fun create(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            version: Int,
            serializedGroupDetails: String?,
            serverPhotoInfo: ServerPhotoInfo?
        ): ContactGroupV2Details? {
            if ((groupIdentifier == null) || (ownedIdentity == null) || (serializedGroupDetails == null)) {
                return null
            }

            try {
                val contactGroupDetails: ContactGroupV2Details?
                if (serverPhotoInfo == null) {
                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        null,
                        null,
                        null,
                        null
                    )
                } else {
                    contactGroupDetails = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        serializedGroupDetails,
                        null,
                        serverPhotoInfo.serverPhotoIdentity,
                        serverPhotoInfo.serverPhotoLabel,
                        serverPhotoInfo.serverPhotoKey
                    )
                }
                contactGroupDetails.insert()
                return contactGroupDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun createOrUpdateKeycloak(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier,
            serializedGroupDetails: String?,
            serverPhotoInfo: ServerPhotoInfo?
        ): ContactGroupV2Details? {
            try {
                // first check if we already have some details
                var contactGroupDetails: ContactGroupV2Details? =
                    get(identityManagerSession, ownedIdentity, groupIdentifier, 0)
                if (contactGroupDetails == null) {
                    if (serverPhotoInfo == null) {
                        contactGroupDetails = ContactGroupV2Details(
                            identityManagerSession,
                            groupIdentifier.groupUid,
                            groupIdentifier.serverUrl,
                            groupIdentifier.category,
                            ownedIdentity,
                            0,
                            serializedGroupDetails,
                            null,
                            null,
                            null,
                            null
                        )
                    } else {
                        contactGroupDetails = ContactGroupV2Details(
                            identityManagerSession,
                            groupIdentifier.groupUid,
                            groupIdentifier.serverUrl,
                            groupIdentifier.category,
                            ownedIdentity,
                            0,
                            serializedGroupDetails,
                            null,
                            serverPhotoInfo.serverPhotoIdentity,
                            serverPhotoInfo.serverPhotoLabel,
                            serverPhotoInfo.serverPhotoKey
                        )
                    }
                    contactGroupDetails.insert()
                } else {
                    contactGroupDetails.serializedJsonDetails = serializedGroupDetails
                    if (serverPhotoInfo != null) {
                        // we already have some details, simply update them
                        if (contactGroupDetails.photoUrl != null) {
                            // we already have a photo, check if it changed or not
                            val oldServerPhotoInfo = ServerPhotoInfo(
                                contactGroupDetails.photoServerIdentity,
                                contactGroupDetails.photoServerLabel!!,
                                contactGroupDetails.photoServerKey!!
                            )
                            if (oldServerPhotoInfo != serverPhotoInfo) {
                                contactGroupDetails.photoUrl = null
                            }
                        }
                        contactGroupDetails.photoServerIdentity =
                            serverPhotoInfo.serverPhotoIdentity
                        contactGroupDetails.photoServerLabel = serverPhotoInfo.serverPhotoLabel
                        contactGroupDetails.photoServerKey = serverPhotoInfo.serverPhotoKey
                    } else {
                        contactGroupDetails.photoUrl = null
                        contactGroupDetails.photoServerIdentity = null
                        contactGroupDetails.photoServerLabel = null
                        contactGroupDetails.photoServerKey = null
                    }
                    contactGroupDetails.update()
                }

                return contactGroupDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region Get and Set
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            version: Int
        ): ContactGroupV2Details? {
            if ((groupIdentifier == null) || (ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2Details.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_UID + " = ? " +
                        " AND " + SERVER_URL + " = ? " +
                        " AND " + CATEGORY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.setInt(5, version)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ContactGroupV2Details(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }


        @Throws(SQLException::class)
        fun getAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?
        ): MutableList<ContactGroupV2Details>? {
            if ((groupIdentifier == null) || (ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2Details.getAll",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_UID + " = ? " +
                        " AND " + SERVER_URL + " = ? " +
                        " AND " + CATEGORY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2Details> =
                        ArrayList<ContactGroupV2Details>()
                    while (res.next()) {
                        list.add(ContactGroupV2Details(identityManagerSession, res))
                    }
                    return list
                }
            }
        }


        @Throws(SQLException::class)
        fun cleanup(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier,
            version: Int,
            trustedVersion: Int
        ) {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2Details.cleanup",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + GROUP_UID + " = ? " +
                        " AND " + SERVER_URL + " = ? " +
                        " AND " + CATEGORY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " NOT IN (?,?);"
            ).use { statement ->
                statement.setBytes(1, groupIdentifier.groupUid.bytes)
                statement.setString(2, groupIdentifier.serverUrl)
                statement.setInt(3, groupIdentifier.category)
                statement.setBytes(4, ownedIdentity.getBytes())
                statement.setInt(5, version)
                statement.setInt(6, trustedVersion)
                statement.executeUpdate()
            }
        }


        @Throws(SQLException::class)
        fun getByGroupIdentifierAndServerPhotoInfo(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupIdentifier: GroupV2.Identifier?,
            serverPhotoInfo: ServerPhotoInfo?
        ): MutableList<ContactGroupV2Details?>? {
            if ((ownedIdentity == null) || (groupIdentifier == null) || (serverPhotoInfo == null)) {
                return null
            }
            if (groupIdentifier.category == GroupV2.Identifier.CATEGORY_KEYCLOAK) {
                identityManagerSession.session.prepareStatement(
                    "ContactGroupV2Details.getByGroupIdentifierAndServerPhotoInfo",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + GROUP_UID + " = ? " +
                            " AND " + SERVER_URL + " = ? " +
                            " AND " + CATEGORY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ? " +
                            " AND " + PHOTO_SERVER_IDENTITY + " IS NULL " +
                            " AND " + PHOTO_SERVER_LABEL + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupIdentifier.groupUid.bytes)
                    statement.setString(2, groupIdentifier.serverUrl)
                    statement.setInt(3, groupIdentifier.category)
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.setBytes(5, serverPhotoInfo.serverPhotoLabel.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactGroupV2Details?> =
                            ArrayList<ContactGroupV2Details?>()
                        while (res.next()) {
                            val contactGroupV2Details =
                                ContactGroupV2Details(identityManagerSession, res)
                            if (contactGroupV2Details.photoServerKey == serverPhotoInfo.serverPhotoKey) {
                                list.add(contactGroupV2Details)
                            }
                        }
                        return list
                    }
                }
            } else {
                identityManagerSession.session.prepareStatement(
                    "ContactGroupV2Details.getByGroupIdentifierAndServerPhotoInfo",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + GROUP_UID + " = ? " +
                            " AND " + SERVER_URL + " = ? " +
                            " AND " + CATEGORY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ? " +
                            " AND " + PHOTO_SERVER_IDENTITY + " = ? " +
                            " AND " + PHOTO_SERVER_LABEL + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, groupIdentifier.groupUid.bytes)
                    statement.setString(2, groupIdentifier.serverUrl)
                    statement.setInt(3, groupIdentifier.category)
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.setBytes(5, serverPhotoInfo.serverPhotoIdentity!!.getBytes())
                    statement.setBytes(6, serverPhotoInfo.serverPhotoLabel.bytes)
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactGroupV2Details?> =
                            ArrayList<ContactGroupV2Details?>()
                        while (res.next()) {
                            val contactGroupV2Details =
                                ContactGroupV2Details(identityManagerSession, res)
                            if (contactGroupV2Details.photoServerKey == serverPhotoInfo.serverPhotoKey) {
                                list.add(contactGroupV2Details)
                            }
                        }
                        return list
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<String> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2Details.getAllPhotoUrl",
                "SELECT " + PHOTO_URL + " FROM " + TABLE_NAME +
                        " WHERE " + PHOTO_URL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<String> = ArrayList()
                    while (res.next()) {
                        list.add(res.getString(PHOTO_URL))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithMissingPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<ContactGroupV2Details?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupV2Details.getAllWithMissingPhotoUrl",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + PHOTO_URL + " IS NULL " +
                        " AND (" + PHOTO_SERVER_IDENTITY + " IS NOT NULL" +
                        " OR " + CATEGORY + " = " + GroupV2.Identifier.CATEGORY_KEYCLOAK + ") " +
                        " AND " + PHOTO_SERVER_KEY + " IS NOT NULL " +
                        " AND " + PHOTO_SERVER_LABEL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupV2Details?> =
                        ArrayList<ContactGroupV2Details?>()
                    while (res.next()) {
                        list.add(ContactGroupV2Details(identityManagerSession, res))
                    }
                    return list
                }
            }
        }


        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            GROUP_UID + " BLOB NOT NULL, " +
                            SERVER_URL + " TEXT NOT NULL, " +
                            CATEGORY + " INT NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            VERSION + " INT NOT NULL, " +
                            SERIALIZED_JSON_DETAILS + " TEXT NOT NULL, " +
                            PHOTO_URL + " TEXT, " +
                            PHOTO_SERVER_IDENTITY + " BLOB, " +
                            PHOTO_SERVER_LABEL + " BLOB, " +
                            PHOTO_SERVER_KEY + " BLOB, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_UID + ", " + SERVER_URL + ", " + CATEGORY + ", " + OWNED_IDENTITY + ", " + VERSION + ") );"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    Logger.d("CREATING contact_group_v2_details DATABASE FOR VERSION 32")
                    statement.execute(
                        "CREATE TABLE contact_group_v2_details (" +
                                "group_uid BLOB NOT NULL, " +
                                "server_url TEXT NOT NULL, " +
                                "category INT NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "version INT NOT NULL, " +
                                "serialized_json_details TEXT NOT NULL, " +
                                "photo_url TEXT, " +
                                "photo_server_identity BLOB, " +
                                "photo_server_label BLOB, " +
                                "photo_server_key BLOB, " +
                                " CONSTRAINT PK_contact_group_v2_details PRIMARY KEY(group_uid, server_url, category, owned_identity, version) );"
                    )
                }
                oldVersion = 32
            }
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupIdentifier: GroupV2.Identifier,
            version: Int,
            pojo: Pojo_0
        ) {
            var contactGroupV2Details: ContactGroupV2Details? = null
            if (pojo.photo_server_label != null && pojo.photo_server_key != null) {
                try {
                    val photoServerIdentity =
                        if (pojo.photo_server_identity == null) null else Identity.of(pojo.photo_server_identity!!)
                    val photoServerLabel = UID(pojo.photo_server_label!!)
                    val photoServerKey =
                        Encoded(pojo.photo_server_key!!).decodeSymmetricKey() as AuthEncKey?

                    contactGroupV2Details = ContactGroupV2Details(
                        identityManagerSession,
                        groupIdentifier.groupUid,
                        groupIdentifier.serverUrl,
                        groupIdentifier.category,
                        ownedIdentity,
                        version,
                        pojo.serialized_details,
                        null,
                        photoServerIdentity,
                        photoServerLabel,
                        photoServerKey
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            if (contactGroupV2Details == null) {
                contactGroupV2Details = ContactGroupV2Details(
                    identityManagerSession,
                    groupIdentifier.groupUid,
                    groupIdentifier.serverUrl,
                    groupIdentifier.category,
                    ownedIdentity,
                    version,
                    pojo.serialized_details,
                    null,
                    null,
                    null,
                    null
                )
            }
            contactGroupV2Details.insert()
        }
    }
}
