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
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class OwnedIdentityDetails : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var ownedIdentity: Identity? = null
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
        return ownedIdentity!!
    }

    val jsonIdentityDetails: JsonIdentityDetails?
        get() {
            try {
                return identityManagerSession.jsonObjectMapper!!.readValue<JsonIdentityDetails?>(
                    serializedJsonDetails,
                    JsonIdentityDetails::class.java
                )
            } catch (_: Exception) {
                return null
            }
        }

    val jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
        get() {
            try {
                val json =
                    JsonIdentityDetailsWithVersionAndPhoto()
                json.setIdentityDetails(
                    identityManagerSession.jsonObjectMapper!!.readValue<JsonIdentityDetails?>(
                        serializedJsonDetails,
                        JsonIdentityDetails::class.java
                    )
                )
                json.setVersion(version)
                json.setPhotoUrl(photoUrl)
                if (photoServerKey != null && photoServerLabel != null) {
                    json.setPhotoServerLabel(photoServerLabel!!.bytes)
                    json.setPhotoServerKey(Encoded.of(photoServerKey!!).bytes)
                }
                return json
            } catch (_: Exception) {
                return null
            }
        }

    constructor(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity,
        version: Int,
        serializedJsonDetails: String?,
        photoUrl: String?,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = ownedIdentity
        this.version = version
        this.serializedJsonDetails = serializedJsonDetails
        this.photoUrl = photoUrl
        this.photoServerLabel = photoServerLabel
        this.photoServerKey = photoServerKey
    }

    private constructor(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity,
        version: Int,
        serializedJsonDetails: String?
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = ownedIdentity
        this.version = version
        this.serializedJsonDetails = serializedJsonDetails
        this.photoUrl = null
        this.photoServerLabel = null
        this.photoServerKey = null
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
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
            "OwnedIdentityDetails.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setInt(2, version)
            statement.setString(3, serializedJsonDetails)
            statement.setString(4, photoUrl)
            statement.setBytes(5, if (photoServerLabel == null) null else photoServerLabel!!.bytes)
            statement.setBytes(
                6,
                if (photoServerKey == null) null else Encoded.of(photoServerKey!!).bytes
            )
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentityDetails.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setInt(2, version)
            statement.executeUpdate()
        }
    }

    @Throws(Exception::class)
    fun setJsonDetails(jsonIdentityDetails: JsonIdentityDetails) {
        val serializedJsonDetails =
            identityManagerSession.jsonObjectMapper!!.writeValueAsString(jsonIdentityDetails)
        identityManagerSession.session.prepareStatement(
            "OwnedIdentityDetails.setJsonDetails",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_JSON_DETAILS + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, serializedJsonDetails)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setInt(3, version)
            statement.executeUpdate()
            this.serializedJsonDetails = serializedJsonDetails
        }
    }

    @Throws(SQLException::class)
    fun setPhotoUrl(photoUrl: String?, clearLabelAndKey: Boolean) {
        if (clearLabelAndKey) {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.setPhotoUrl",
                "UPDATE " + TABLE_NAME + " SET " +
                        PHOTO_URL + " = ?, " +
                        PHOTO_SERVER_LABEL + " = NULL, " +
                        PHOTO_SERVER_KEY + " = NULL " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setString(1, photoUrl)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setInt(3, version)
                statement.executeUpdate()
                this.photoUrl = photoUrl
                this.photoServerKey = null
                this.photoServerLabel = null
            }
        } else {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.setPhotoUrl",
                "UPDATE " + TABLE_NAME + " SET " +
                        PHOTO_URL + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setString(1, photoUrl)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setInt(3, version)
                statement.executeUpdate()
                this.photoUrl = photoUrl
            }
        }
    }

    @Throws(SQLException::class)
    fun setPhotoServerLabelAndKey(photoServerLabel: UID, photoServerKey: AuthEncKey) {
        identityManagerSession.session.prepareStatement(
            "OwnedIdentityDetails.setPhotoServerLabelAndKey",
            "UPDATE " + TABLE_NAME + " SET " +
                    PHOTO_SERVER_LABEL + " = ?, " +
                    PHOTO_SERVER_KEY + " = ? " +
                    " WHERE " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, photoServerLabel.bytes)
            statement.setBytes(2, Encoded.of(photoServerKey).bytes)
            statement.setBytes(3, ownedIdentity!!.getBytes())
            statement.setInt(4, version)
            statement.executeUpdate()
            this.photoServerLabel = photoServerLabel
            this.photoServerKey = photoServerKey
        }
    }


    // endregion
    override fun wasCommitted() {
    }


    // region backup
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.version = version
        pojo.serialized_details = serializedJsonDetails
        if (photoServerLabel != null) {
            pojo.photo_server_label = photoServerLabel!!.bytes
        }
        if (photoServerKey != null) {
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
        const val TABLE_NAME: String = "owned_identity_details"

        const val OWNED_IDENTITY: String = "owned_identity"
        const val VERSION: String = "version"
        const val SERIALIZED_JSON_DETAILS: String = "serialized_json_details"
        const val PHOTO_URL: String = "photo_url"
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"

        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            serializedJsonDetails: String?
        ): OwnedIdentityDetails? {
            if (ownedIdentity == null || serializedJsonDetails == null) {
                return null
            }
            try {
                var newVersion = 1
                identityManagerSession.session.prepareStatement(
                    "OwnedIdentityDetails.create",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " ORDER BY " + VERSION + " DESC LIMIT 1;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            newVersion = res.getInt(VERSION) + 1
                        }
                    }
                }
                val ownedIdentityDetails = OwnedIdentityDetails(
                    identityManagerSession,
                    ownedIdentity,
                    newVersion,
                    serializedJsonDetails
                )
                ownedIdentityDetails.insert()
                return ownedIdentityDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun create(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
        ): OwnedIdentityDetails? {
            if (ownedIdentity == null || jsonIdentityDetailsWithVersionAndPhoto == null) {
                return null
            }
            try {
                val ownedIdentityDetails = OwnedIdentityDetails(
                    identityManagerSession,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto.getVersion(),
                    identityManagerSession.jsonObjectMapper!!.writeValueAsString(
                        jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()
                    )
                )
                ownedIdentityDetails.photoServerKey =
                    if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() == null) null else Encoded(
                        jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                    ).decodeSymmetricKey() as AuthEncKey?
                ownedIdentityDetails.photoServerLabel =
                    if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel() == null) null else UID(
                        jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel()!!
                    )
                ownedIdentityDetails.insert()
                return ownedIdentityDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun copy(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            version: Int
        ): OwnedIdentityDetails? {
            if (ownedIdentity == null) {
                return null
            }
            try {
                var newVersion = version + 1
                identityManagerSession.session.prepareStatement(
                    "OwnedIdentityDetails.copy",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " ORDER BY " + VERSION + " DESC LIMIT 1;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            newVersion = res.getInt(VERSION) + 1
                        }
                    }
                }
                val oldDetails: OwnedIdentityDetails? =
                    get(identityManagerSession, ownedIdentity, version)
                if (oldDetails == null) {
                    return null
                }
                val ownedIdentityDetails = OwnedIdentityDetails(
                    identityManagerSession,
                    ownedIdentity,
                    newVersion,
                    oldDetails.serializedJsonDetails,
                    oldDetails.photoUrl,
                    oldDetails.photoServerLabel,
                    oldDetails.photoServerKey
                )
                ownedIdentityDetails.insert()
                return ownedIdentityDetails
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
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            VERSION + " INT NOT NULL, " +
                            SERIALIZED_JSON_DETAILS + " TEXT NOT NULL, " +
                            PHOTO_URL + " TEXT, " +
                            PHOTO_SERVER_LABEL + " BLOB, " +
                            PHOTO_SERVER_KEY + " BLOB, " +
                            "CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + OWNED_IDENTITY + ", " + VERSION + "));"
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
            ownedIdentity: Identity?,
            version: Int
        ): OwnedIdentityDetails? {
            if ((ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?" +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setInt(2, version)
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedIdentityDetails(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<String> {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.getAllPhotoUrl",
                "SELECT " + PHOTO_URL + " FROM " + TABLE_NAME + " WHERE " + PHOTO_URL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<String> = ArrayList<String>()
                    while (res.next()) {
                        list.add(res.getString(PHOTO_URL))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithMissingPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<OwnedIdentityDetails?> {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.getAllWithMissingPhotoUrl",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + PHOTO_URL + " IS NULL " +
                        " AND " + PHOTO_SERVER_KEY + " IS NOT NULL " +
                        " AND " + PHOTO_SERVER_LABEL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedIdentityDetails?> =
                        ArrayList<OwnedIdentityDetails?>()
                    while (res.next()) {
                        list.add(OwnedIdentityDetails(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllForOwnedIdentity(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): MutableList<OwnedIdentityDetails?> {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.getAllForOwnedIdentity",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<OwnedIdentityDetails?> =
                        ArrayList<OwnedIdentityDetails?>()
                    while (res.next()) {
                        list.add(OwnedIdentityDetails(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        // endregion
        // region setters
        @Throws(SQLException::class)
        fun cleanup(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            publishedVersion: Int,
            latestVersion: Int
        ) {
            identityManagerSession.session.prepareStatement(
                "OwnedIdentityDetails.cleanup",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + VERSION + " NOT IN (?,?);"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setInt(2, publishedVersion)
                statement.setInt(3, latestVersion)
                statement.executeUpdate()
            }
        }


        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            pojo: Pojo_0
        ): OwnedIdentityDetails {
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
            val ownedIdentityDetails = OwnedIdentityDetails(
                identityManagerSession,
                ownedIdentity,
                pojo.version,
                pojo.serialized_details,
                null,
                photoServerLabel,
                photoServerKey
            )
            ownedIdentityDetails.insert()
            if (photoServerLabel != null && photoServerKey != null) {
                ServerUserData.createForOwnedIdentityDetails(
                    identityManagerSession,
                    ownedIdentity,
                    photoServerLabel
                )
            }
            return ownedIdentityDetails
        }
    }
}
