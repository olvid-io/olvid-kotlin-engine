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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class ContactGroupDetails : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val groupOwnerAndUid: ByteArray
    private var ownedIdentity: Identity
    @JvmField val version: Int
    var serializedJsonDetails: String?
        private set
    var photoUrl: String?
        private set
    var photoServerLabel: UID? = null
        private set
    var photoServerKey: AuthEncKey? = null
        private set

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    val jsonGroupDetails: JsonGroupDetails?
        get() {
            return runCatching {
                identityManagerSession.jsonObjectMapper!!.readValue(
                    serializedJsonDetails,
                    JsonGroupDetails::class.java
                )
            }.getOrNull()
        }

    val jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?
        get() {
            try {
                val json =
                    JsonGroupDetailsWithVersionAndPhoto()
                json.setGroupDetails(
                    identityManagerSession.jsonObjectMapper!!.readValue(
                        serializedJsonDetails,
                        JsonGroupDetails::class.java
                    )
                )
                json.setVersion(version)
                json.setPhotoUrl(photoUrl)
                if (photoServerLabel != null && photoServerKey != null) {
                    json.setPhotoServerLabel(photoServerLabel!!.bytes)
                    json.setPhotoServerKey(Encoded.of(photoServerKey!!).bytes)
                }
                return json
            } catch (_: Exception) {
                return null
            }
        }

    @Throws(Exception::class)
    fun setJsonDetails(jsonGroupDetails: JsonGroupDetails) {
        val serializedJsonDetails =
            identityManagerSession.jsonObjectMapper!!.writeValueAsString(jsonGroupDetails)
        identityManagerSession.session.prepareStatement(
            "ContactGroupDetails.setJsonDetails",
            "UPDATE " + TABLE_NAME + " SET " +
                    SERIALIZED_JSON_DETAILS + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, serializedJsonDetails)
            statement.setBytes(2, groupOwnerAndUid)
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.setInt(4, version)
            statement.executeUpdate()
            this.serializedJsonDetails = serializedJsonDetails
        }
    }

    @Throws(SQLException::class)
    fun setPhotoUrl(photoUrl: String?, clearLabelAndKey: Boolean) {
        if (clearLabelAndKey) {
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.setPhotoUrl",
                "UPDATE " + TABLE_NAME +
                        " SET " + PHOTO_URL + " = ?, " +
                        PHOTO_SERVER_LABEL + " = NULL, " +
                        PHOTO_SERVER_KEY + " = NULL " +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setString(1, photoUrl)
                statement.setBytes(2, groupOwnerAndUid)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.setInt(4, version)
                statement.executeUpdate()
                this.photoUrl = photoUrl
                this.photoServerKey = null
                this.photoServerLabel = null
            }
        } else {
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.setPhotoUrl",
                "UPDATE " + TABLE_NAME +
                        " SET " + PHOTO_URL + " = ? " +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setString(1, photoUrl)
                statement.setBytes(2, groupOwnerAndUid)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.setInt(4, version)
                statement.executeUpdate()
                this.photoUrl = photoUrl
            }
        }
    }

    @Throws(SQLException::class)
    fun setPhotoServerLabelAndKey(photoServerLabel: UID, photoServerKey: AuthEncKey) {
        identityManagerSession.session.prepareStatement(
            "ContactGroupDetails.setPhotoServerLabelAndKey",
            "UPDATE " + TABLE_NAME + " SET " +
                    PHOTO_SERVER_LABEL + " = ?, " +
                    PHOTO_SERVER_KEY + " = ? " +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, photoServerLabel.bytes)
            statement.setBytes(2, Encoded.of(photoServerKey).bytes)
            statement.setBytes(3, groupOwnerAndUid)
            statement.setBytes(4, ownedIdentity.getBytes())
            statement.setInt(5, version)
            statement.executeUpdate()
            this.photoServerLabel = photoServerLabel
            this.photoServerKey = photoServerKey
        }
    }


    constructor(
        identityManagerSession: IdentityManagerSession,
        groupOwnerAndUid: ByteArray,
        ownedIdentity: Identity,
        version: Int,
        serializedJsonDetails: String?,
        photoUrl: String?,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = groupOwnerAndUid
        this.ownedIdentity = ownedIdentity
        this.version = version
        this.serializedJsonDetails = serializedJsonDetails
        this.photoUrl = photoUrl
        this.photoServerLabel = photoServerLabel
        this.photoServerKey = photoServerKey
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.groupOwnerAndUid = res.getBytes(GROUP_OWNER_AND_UID)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.version = res.getInt(VERSION)
        this.serializedJsonDetails = res.getString(SERIALIZED_JSON_DETAILS)
        this.photoUrl = res.getString(PHOTO_URL)
        var bytes: ByteArray? = res.getBytes(PHOTO_SERVER_LABEL)
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
            } catch (e: DecodingException) {
                Logger.x(e)
                this.photoServerKey = null
            }
        }
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupDetails.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, version)
            statement.setString(4, serializedJsonDetails)
            statement.setString(5, photoUrl)
            statement.setBytes(6, if (photoServerLabel == null) null else photoServerLabel!!.bytes)
            statement.setBytes(
                7,
                if (photoServerKey == null) null else Encoded.of(photoServerKey!!).bytes
            )
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactGroupDetails.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, groupOwnerAndUid)
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, version)
            statement.executeUpdate()
        }
    }

    // endregion
    // region hooks
    override fun wasCommitted() {
    }

    // endregion
    // region backup
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.version = version
        pojo.serialized_details = serializedJsonDetails
        if (photoServerLabel != null && photoServerKey != null) {
            pojo.photo_server_label = photoServerLabel!!.bytes
            pojo.photo_server_key = Encoded.of(photoServerKey!!).bytes
        }
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var version: Int = 0
        var serialized_details: String? = null
        var photo_server_label: ByteArray? = null
        var photo_server_key: ByteArray? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_group_details"

        const val GROUP_OWNER_AND_UID: String = "group_owner_and_uid"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val VERSION: String = "version"
        const val SERIALIZED_JSON_DETAILS: String = "serialized_json_details"
        const val PHOTO_URL: String = "photo_url"
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"

        // region setters
        @Throws(SQLException::class)
        fun cleanup(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerAndUid: ByteArray?,
            publishedVersion: Int,
            latestOrTrustedVersion: Int
        ) {
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.cleanup",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + GROUP_OWNER_AND_UID + " = ? " +
                        " AND " + VERSION + " NOT IN (?,?);"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, groupOwnerAndUid)
                statement.setInt(3, publishedVersion)
                statement.setInt(4, latestOrTrustedVersion)
                statement.executeUpdate()
            }
        }


        // endregion
        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            groupUid: ByteArray?,
            ownedIdentity: Identity?,
            jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?
        ): ContactGroupDetails? {
            if (groupUid == null || ownedIdentity == null || jsonGroupDetailsWithVersionAndPhoto == null || jsonGroupDetailsWithVersionAndPhoto.getGroupDetails() == null) {
                return null
            }
            try {
                val version = jsonGroupDetailsWithVersionAndPhoto.getVersion()
                val serializedJsonDetails =
                    identityManagerSession.jsonObjectMapper!!.writeValueAsString(
                        jsonGroupDetailsWithVersionAndPhoto.getGroupDetails()
                    )
                val photoServerLabel =
                    if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel() == null) null else UID(
                        jsonGroupDetailsWithVersionAndPhoto.getPhotoServerLabel()!!
                    )
                val photoServerKey =
                    if (jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey() == null) null else Encoded(
                        jsonGroupDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                    ).decodeSymmetricKey() as AuthEncKey?
                val contactGroupDetails = ContactGroupDetails(
                    identityManagerSession,
                    groupUid,
                    ownedIdentity,
                    version,
                    serializedJsonDetails,
                    null,
                    photoServerLabel,
                    photoServerKey
                )
                contactGroupDetails.insert()
                return contactGroupDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun copy(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            groupUid: ByteArray?,
            version: Int,
            newVersion: Int?
        ): ContactGroupDetails? {
            var newVersion = newVersion
            if (groupUid == null || ownedIdentity == null) {
                return null
            }
            try {
                if (newVersion == null) {
                    newVersion = version + 1
                    identityManagerSession.session.prepareStatement(
                        "ContactGroupDetails.copy",
                        "SELECT * FROM " + TABLE_NAME +
                                " WHERE " + GROUP_OWNER_AND_UID + " = ? " +
                                " AND " + OWNED_IDENTITY + " = ? " +
                                " ORDER BY " + VERSION + " DESC LIMIT 1;"
                    ).use { statement ->
                        statement.setBytes(1, groupUid)
                        statement.setBytes(2, ownedIdentity.getBytes())
                        statement.executeQuery().use { res ->
                            if (res.next()) {
                                newVersion = res.getInt(VERSION) + 1
                            }
                        }
                    }
                }
                val oldDetails: ContactGroupDetails =
                    get(identityManagerSession, groupUid, ownedIdentity, version) ?: return null
                val contactGroupDetails = ContactGroupDetails(
                    identityManagerSession,
                    groupUid,
                    ownedIdentity,
                    newVersion!!,
                    oldDetails.serializedJsonDetails,
                    oldDetails.photoUrl,
                    oldDetails.photoServerLabel,
                    oldDetails.photoServerKey
                )
                contactGroupDetails.insert()
                return contactGroupDetails
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
                            GROUP_OWNER_AND_UID + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            VERSION + " INT NOT NULL, " +
                            SERIALIZED_JSON_DETAILS + " TEXT NOT NULL, " +
                            PHOTO_URL + " TEXT, " +
                            PHOTO_SERVER_LABEL + " BLOB, " +
                            PHOTO_SERVER_KEY + " BLOB, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + GROUP_OWNER_AND_UID + ", " + OWNED_IDENTITY + ", " + VERSION + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            groupUid: ByteArray?,
            ownedIdentity: Identity?,
            version: Int
        ): ContactGroupDetails? {
            if ((ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + GROUP_OWNER_AND_UID + " = ?" +
                        " AND " + OWNED_IDENTITY + " = ?" +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setBytes(1, groupUid)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.setInt(3, version)
                statement.executeQuery().use { res ->
                    return if (res.next()) {
                        ContactGroupDetails(identityManagerSession, res)
                    } else {
                        null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<String> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.getAllPhotoUrl",
                "SELECT " + PHOTO_URL + " FROM " + TABLE_NAME + " WHERE " + PHOTO_URL + " IS NOT NULL;"
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
        fun getAllWithMissingPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<ContactGroupDetails?> {
            identityManagerSession.session.prepareStatement(
                "ContactGroupDetails.getAllWithMissingPhotoUrl",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + PHOTO_URL + " IS NULL " +
                        " AND " + PHOTO_SERVER_KEY + " IS NOT NULL " +
                        " AND " + PHOTO_SERVER_LABEL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactGroupDetails?> = ArrayList()
                    while (res.next()) {
                        list.add(ContactGroupDetails(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            groupOwnerAndUid: ByteArray,
            pojo: Pojo_0,
            ownedGroup: Boolean
        ): ContactGroupDetails {
            var photoServerLabel: UID? = null
            if (pojo.photo_server_label != null) {
                photoServerLabel = UID(pojo.photo_server_label!!)
            }
            var photoServerKey: AuthEncKey? = null
            try {
                if (pojo.photo_server_key != null) {
                    photoServerKey =
                        Encoded(pojo.photo_server_key!!).decodeSymmetricKey() as AuthEncKey?
                }
            } catch (e: DecodingException) {
                Logger.x(e)
            } catch (e: ClassCastException) {
                Logger.x(e)
            }
            val contactGroupDetails = ContactGroupDetails(
                identityManagerSession,
                groupOwnerAndUid,
                ownedIdentity,
                pojo.version,
                pojo.serialized_details,
                null,
                photoServerLabel,
                photoServerKey
            )
            contactGroupDetails.insert()
            if (ownedGroup && photoServerLabel != null && photoServerKey != null) {
                ServerUserData.createForOwnedGroupDetails(
                    identityManagerSession,
                    ownedIdentity,
                    photoServerLabel,
                    groupOwnerAndUid
                )
            }
            return contactGroupDetails
        }
    }
}
