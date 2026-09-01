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

class ContactIdentityDetails : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var contactIdentity: Identity
    private var ownedIdentity: Identity
    @JvmField val version: Int
    private var serializedJsonDetails: String?
    private var photoUrl: String?
    var photoServerLabel: UID? = null
        private set
    var photoServerKey: AuthEncKey? = null
        private set

    fun getContactIdentity(): Identity {
        return contactIdentity
    }

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    fun getSerializedJsonDetails(): String? {
        return serializedJsonDetails
    }

    val jsonIdentityDetails: JsonIdentityDetails?
        get() {
            try {
                return identityManagerSession.jsonObjectMapper!!.readValue(
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
                    identityManagerSession.jsonObjectMapper!!.readValue(
                        serializedJsonDetails,
                        JsonIdentityDetails::class.java
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

    fun getPhotoUrl(): String? {
        return photoUrl
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        contactIdentity: Identity,
        ownedIdentity: Identity,
        version: Int,
        serializedJsonDetails: String?,
        photoUrl: String?,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    ) {
        this.identityManagerSession = identityManagerSession
        this.contactIdentity = contactIdentity
        this.ownedIdentity = ownedIdentity
        this.version = version
        this.serializedJsonDetails = serializedJsonDetails
        this.photoUrl = photoUrl
        this.photoServerLabel = photoServerLabel
        this.photoServerKey = photoServerKey
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        try {
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
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
            "ContactIdentityDetails.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?);"
        ).use { statement ->
            statement.setBytes(1, contactIdentity.getBytes())
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
            "ContactIdentityDetails.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setBytes(1, contactIdentity.getBytes())
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, version)
            statement.executeUpdate()
        }
    }

    // endregion
    // region setters
    @Throws(SQLException::class)
    fun setPhotoUrl(photoUrl: String?) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentityDetails.setPhotoUrl",
            "UPDATE " + TABLE_NAME +
                    " SET " + PHOTO_URL + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, photoUrl)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.setInt(4, version)
            statement.executeUpdate()
            this.photoUrl = photoUrl
        }
    }

    @Throws(SQLException::class)
    fun setSerializedJsonDetails(serializedJsonDetails: String?) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentityDetails.setSerializedJsonDetails",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_JSON_DETAILS + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ? " +
                    " AND " + VERSION + " = ?;"
        ).use { statement ->
            statement.setString(1, serializedJsonDetails)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.setInt(4, version)
            statement.executeUpdate()
            this.serializedJsonDetails = serializedJsonDetails
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
        const val TABLE_NAME: String = "contact_identity_details"

        const val CONTACT_IDENTITY: String = "contact_identity"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val VERSION: String = "version"
        const val SERIALIZED_JSON_DETAILS: String = "serialized_json_details"
        const val PHOTO_URL: String = "photo_url"
        const val PHOTO_SERVER_LABEL: String = "photo_server_label"
        const val PHOTO_SERVER_KEY: String = "photo_server_key"


        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
        ): ContactIdentityDetails? {
            if (contactIdentity == null || ownedIdentity == null || jsonIdentityDetailsWithVersionAndPhoto == null || jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails() == null) {
                return null
            }
            try {
                val version = jsonIdentityDetailsWithVersionAndPhoto.getVersion()
                val serializedJsonDetails =
                    identityManagerSession.jsonObjectMapper!!.writeValueAsString(
                        jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()
                    )
                val photoServerLabel =
                    if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel() == null) null else UID(
                        jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel()!!
                    )
                val photoServerKey =
                    if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() == null) null else Encoded(
                        jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                    ).decodeSymmetricKey() as AuthEncKey?
                val contactIdentityDetails = ContactIdentityDetails(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    version,
                    serializedJsonDetails,
                    null,
                    photoServerLabel,
                    photoServerKey
                )
                contactIdentityDetails.insert()
                return contactIdentityDetails
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }
        }

        fun copy(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            contactIdentity: Identity,
            version: Int,
            newVersion: Int
        ): ContactIdentityDetails? {
            if (ownedIdentity == null) {
                return null
            }
            try {
                val oldDetails: ContactIdentityDetails =
                    get(identityManagerSession, contactIdentity, ownedIdentity, version)
                        ?: return null
                val ownedIdentityDetails = ContactIdentityDetails(
                    identityManagerSession,
                    contactIdentity,
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
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            VERSION + " INT NOT NULL, " +
                            SERIALIZED_JSON_DETAILS + " TEXT NOT NULL, " +
                            PHOTO_URL + " TEXT, " +
                            PHOTO_SERVER_LABEL + " BLOB, " +
                            PHOTO_SERVER_KEY + " BLOB, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + ", " + VERSION + "));"
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
            contactIdentity: Identity,
            ownedIdentity: Identity?,
            version: Int
        ): ContactIdentityDetails? {
            if (ownedIdentity == null) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactIdentityDetails.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + CONTACT_IDENTITY + " = ?" +
                        " AND " + OWNED_IDENTITY + " = ?" +
                        " AND " + VERSION + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactIdentity.getBytes())
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.setInt(3, version)
                statement.executeQuery().use { res ->
                    return if (res.next()) {
                        ContactIdentityDetails(identityManagerSession, res)
                    } else {
                        null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<String> {
            identityManagerSession.session.prepareStatement(
                "ContactIdentityDetails.getAllPhotoUrl",
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
        fun getAllWithMissingPhotoUrl(identityManagerSession: IdentityManagerSession): MutableList<ContactIdentityDetails?> {
            identityManagerSession.session.prepareStatement(
                "ContactIdentityDetails.getAllWithMissingPhotoUrl",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + PHOTO_URL + " IS NULL " +
                        " AND " + PHOTO_SERVER_KEY + " IS NOT NULL " +
                        " AND " + PHOTO_SERVER_LABEL + " IS NOT NULL;"
            ).use { statement ->
                statement.executeQuery().use { res ->
                    val list: MutableList<ContactIdentityDetails?> =
                        ArrayList()
                    while (res.next()) {
                        list.add(ContactIdentityDetails(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun cleanup(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity,
            publishedVersion: Int,
            trustedVersion: Int
        ) {
            identityManagerSession.session.prepareStatement(
                "ContactIdentityDetails.cleanup",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + CONTACT_IDENTITY + " = ? " +
                        " AND " + VERSION + " NOT IN (?,?);"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setInt(3, publishedVersion)
                statement.setInt(4, trustedVersion)
                statement.executeUpdate()
            }
        }


        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity,
            pojo: Pojo_0
        ): ContactIdentityDetails {
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
            val contactIdentityDetails = ContactIdentityDetails(
                identityManagerSession,
                contactIdentity,
                ownedIdentity,
                pojo.version,
                pojo.serialized_details,
                null,
                photoServerLabel,
                photoServerKey
            )
            contactIdentityDetails.insert()
            return contactIdentityDetails
        }
    }
}
