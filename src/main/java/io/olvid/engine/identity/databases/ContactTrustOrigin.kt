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

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.datatypes.TrustLevel.Companion.createDirect
import io.olvid.engine.datatypes.TrustLevel.Companion.createServer
import io.olvid.engine.datatypes.TrustLevel.Companion.createServerGroupV2
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createDirectTrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createGroupTrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createIntroductionTrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createKeycloakTrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createServerGroupV2TrustOrigin
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types

class ContactTrustOrigin : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var rowId: Long = 0
    private var contactIdentity: Identity? = null
    private var ownedIdentity: Identity? = null
    private val timestamp: Long
    private val trustType: Int
    private var mediatorOrGroupOwnerIdentity: Identity? = null
    private var mediatorOrGroupOwnerTrustLevelMajor: Int?
    private val identityServer: String?
    private val serializedGroupIdentifier: ByteArray?
    val trustLevel: TrustLevel?
        // region computed properties
        get() {
            when (trustType) {
                TRUST_TYPE_DIRECT -> return createDirect()
                TRUST_TYPE_GROUP, TRUST_TYPE_INTRODUCTION -> return TrustLevel.createIndirect(
                    mediatorOrGroupOwnerTrustLevelMajor!!
                )

                TRUST_TYPE_IDENTITY_SERVER -> return createServer()
                TRUST_TYPE_SERVER_GROUP_V2 -> return createServerGroupV2()
                else -> return null
            }
        }

    val trustOrigin: TrustOrigin?
        get() {
            when (trustType) {
                TRUST_TYPE_DIRECT -> return createDirectTrustOrigin(
                    timestamp
                )

                TRUST_TYPE_GROUP -> return createGroupTrustOrigin(
                    timestamp,
                    mediatorOrGroupOwnerIdentity
                )

                TRUST_TYPE_INTRODUCTION -> return createIntroductionTrustOrigin(
                    timestamp,
                    mediatorOrGroupOwnerIdentity
                )

                TRUST_TYPE_IDENTITY_SERVER -> return createKeycloakTrustOrigin(
                    timestamp,
                    identityServer
                )

                TRUST_TYPE_SERVER_GROUP_V2 -> {
                    try {
                        return createServerGroupV2TrustOrigin(
                            timestamp,
                            GroupV2.Identifier.of(serializedGroupIdentifier!!)
                        )
                    } catch (_: Exception) {
                        return null
                    }
                    return null
                }

                else -> return null
            }
        }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactTrustOrigin.insert",
            "INSERT INTO " + TABLE_NAME + "(" +
                    CONTACT_IDENTITY + ", " +
                    OWNED_IDENTITY + ", " +
                    TIMESTAMP + ", " +
                    TRUST_TYPE + ", " +
                    MEDIATOR_OR_GROUP_OWNER_IDENTITY + ", " +
                    MEDIATOR_OR_GROUP_OWNER_TRUST_LEVEL_MAJOR + ", " +
                    IDENTITY_SERVER + ", " +
                    SERIALIZED_GROUP_IDENTIFIER + ") " +
                    " VALUES (?,?,?,?,?, ?,?,?);",
            true
        ).use { statement ->
            statement.setBytes(1, contactIdentity!!.getBytes())
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setLong(3, timestamp)
            statement.setInt(4, trustType)
            if (mediatorOrGroupOwnerIdentity == null) {
                statement.setBytes(5, null)
            } else {
                statement.setBytes(5, mediatorOrGroupOwnerIdentity!!.getBytes())
            }
            if (mediatorOrGroupOwnerTrustLevelMajor == null) {
                statement.setNull(6, Types.INTEGER)
            } else {
                statement.setInt(6, mediatorOrGroupOwnerTrustLevelMajor!!)
            }
            statement.setString(7, identityServer)
            statement.setBytes(8, serializedGroupIdentifier)
            statement.executeUpdate()
            val res = statement.getGeneratedKeys()
            if (res.next()) {
                this.rowId = res.getLong(1)
            }
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "ContactTrustOrigin.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + ROW_ID + " = ?;"
        ).use { statement ->
            statement.setLong(1, rowId)
            statement.executeUpdate()
        }
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        contactIdentity: Identity,
        ownedIdentity: Identity,
        timestamp: Long,
        trustType: Int,
        mediatorOrGroupOwnerIdentity: Identity?,
        mediatorOrGroupOwnerTrustLevelMajor: Int?,
        identityServer: String?,
        serializedGroupIdentifier: ByteArray?
    ) {
        this.identityManagerSession = identityManagerSession
        this.contactIdentity = contactIdentity
        this.ownedIdentity = ownedIdentity
        this.timestamp = timestamp
        this.trustType = trustType
        this.mediatorOrGroupOwnerIdentity = mediatorOrGroupOwnerIdentity
        this.mediatorOrGroupOwnerTrustLevelMajor = mediatorOrGroupOwnerTrustLevelMajor
        this.identityServer = identityServer
        this.serializedGroupIdentifier = serializedGroupIdentifier
    }


    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.rowId = res.getLong(ROW_ID)
        this.identityManagerSession = identityManagerSession
        try {
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
            val mediatorBytes: ByteArray? = res.getBytes(MEDIATOR_OR_GROUP_OWNER_IDENTITY)
            if (mediatorBytes == null) {
                this.mediatorOrGroupOwnerIdentity = null
            } else {
                mediatorOrGroupOwnerIdentity = Identity.of(mediatorBytes)
            }
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.timestamp = res.getLong(TIMESTAMP)
        this.trustType = res.getInt(TRUST_TYPE)
        this.mediatorOrGroupOwnerTrustLevelMajor = res.getInt(
            MEDIATOR_OR_GROUP_OWNER_TRUST_LEVEL_MAJOR
        )
        if (res.wasNull()) {
            this.mediatorOrGroupOwnerTrustLevelMajor = null
        }
        this.identityServer = res.getString(IDENTITY_SERVER)
        this.serializedGroupIdentifier = res.getBytes(SERIALIZED_GROUP_IDENTIFIER)
    }

    // endregion
    // region hooks
    override fun wasCommitted() {
    }

    private fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.timestamp = timestamp
        pojo.writeTrust_type(trustType)
        if (mediatorOrGroupOwnerIdentity != null) {
            pojo.mediator_or_group_owner_identity = mediatorOrGroupOwnerIdentity!!.getBytes()
        }
        if (mediatorOrGroupOwnerTrustLevelMajor != null) {
            pojo.mediator_or_group_owner_trust_level_major = mediatorOrGroupOwnerTrustLevelMajor
        }
        pojo.identity_server = identityServer
        pojo.raw_obv_group_v2_identifier = serializedGroupIdentifier
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        var timestamp: Long = 0
        var trust_type: Int = 0
        var mediator_or_group_owner_identity: ByteArray? = null
        var mediator_or_group_owner_trust_level_major: Int? = null
        var identity_server: String? = null
        var raw_obv_group_v2_identifier: ByteArray? = null

        @JsonIgnore
        fun readTrust_type(): Int {
            when (trust_type) {
                TYPE_GROUP -> return TRUST_TYPE_GROUP
                TYPE_INTRODUCTION -> return TRUST_TYPE_INTRODUCTION
                TYPE_IDENTITY_SERVER -> return TRUST_TYPE_IDENTITY_SERVER
                TYPE_SERVER_GROUP_V2 -> return TRUST_TYPE_SERVER_GROUP_V2
                TYPE_DIRECT -> return TRUST_TYPE_DIRECT
                else -> return TRUST_TYPE_DIRECT
            }
        }

        @JsonIgnore
        fun writeTrust_type(trust_type: Int) {
            when (trust_type) {
                TRUST_TYPE_GROUP -> this.trust_type = TYPE_GROUP
                TRUST_TYPE_INTRODUCTION -> this.trust_type = TYPE_INTRODUCTION
                TRUST_TYPE_IDENTITY_SERVER -> this.trust_type = TYPE_IDENTITY_SERVER
                TRUST_TYPE_SERVER_GROUP_V2 -> this.trust_type = TYPE_SERVER_GROUP_V2
                TRUST_TYPE_DIRECT -> this.trust_type = TYPE_DIRECT
                else -> this.trust_type = TYPE_DIRECT
            }
        }

        companion object {
            private const val TYPE_DIRECT = 0
            private const val TYPE_GROUP = 1
            private const val TYPE_INTRODUCTION = 2
            private const val TYPE_IDENTITY_SERVER = 3
            private const val TYPE_SERVER_GROUP_V2 = 4
        }
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_trust_origin"

        const val ROW_ID: String = "row_id"
        const val CONTACT_IDENTITY: String = "contact_identity"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val TIMESTAMP: String = "timestamp"
        const val TRUST_TYPE: String = "trust_type"
        const val MEDIATOR_OR_GROUP_OWNER_IDENTITY: String = "mediator_or_group_owner_identity"
        const val MEDIATOR_OR_GROUP_OWNER_TRUST_LEVEL_MAJOR: String =
            "mediator_or_group_owner_trust_level_major"
        const val IDENTITY_SERVER: String = "identity_server"
        const val SERIALIZED_GROUP_IDENTIFIER: String = "serialized_group_identifier"

        const val TRUST_TYPE_DIRECT: Int = 1
        const val TRUST_TYPE_INTRODUCTION: Int = 2
        const val TRUST_TYPE_GROUP: Int = 3
        const val TRUST_TYPE_IDENTITY_SERVER: Int = 4
        const val TRUST_TYPE_SERVER_GROUP_V2: Int = 5

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            ROW_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            TIMESTAMP + " INTEGER NOT NULL, " +
                            TRUST_TYPE + " INTEGER NOT NULL, " +
                            MEDIATOR_OR_GROUP_OWNER_IDENTITY + " BLOB, " +
                            MEDIATOR_OR_GROUP_OWNER_TRUST_LEVEL_MAJOR + " INTEGER, " +
                            IDENTITY_SERVER + " TEXT, " +
                            SERIALIZED_GROUP_IDENTIFIER + " BLOB, " +
                            " FOREIGN KEY (" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + ") REFERENCES " + ContactIdentity.TABLE_NAME + " (" + ContactIdentity.CONTACT_IDENTITY + ", " + ContactIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 12 && newVersion >= 12) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "DELETE FROM contact_trust_origin AS p " +
                                " WHERE NOT EXISTS (" +
                                " SELECT 1 FROM contact_identity " +
                                " WHERE identity = p.contact_identity" +
                                " AND owned_identity = p.owned_identity" +
                                " )"
                    )
                }
                oldVersion = 12
            }
            if (oldVersion < 32 && newVersion >= 32) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "ALTER TABLE contact_trust_origin " +
                                " ADD COLUMN serialized_group_identifier BLOB DEFAULT NULL"
                    )
                }
                oldVersion = 32
            }
        }


        // endregion
        // region constructor
        fun create(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            trustOrigin: TrustOrigin?
        ): ContactTrustOrigin? {
            if (ownedIdentity == null || contactIdentity == null || trustOrigin == null) {
                return null
            }
            try {
                val trustType: Int
                val mediatorOrGroupOwnerIdentity: Identity?
                val identityServer: String?
                val serializedGroupIdentifier: ByteArray?
                when (trustOrigin.getType()) {
                    TrustOrigin.TYPE.DIRECT -> {
                        trustType = TRUST_TYPE_DIRECT
                        mediatorOrGroupOwnerIdentity = null
                        identityServer = null
                        serializedGroupIdentifier = null
                    }

                    TrustOrigin.TYPE.GROUP -> {
                        trustType = TRUST_TYPE_GROUP
                        mediatorOrGroupOwnerIdentity = trustOrigin.getMediatorOrGroupOwnerIdentity()
                        identityServer = null
                        serializedGroupIdentifier = null
                    }

                    TrustOrigin.TYPE.INTRODUCTION -> {
                        trustType = TRUST_TYPE_INTRODUCTION
                        mediatorOrGroupOwnerIdentity = trustOrigin.getMediatorOrGroupOwnerIdentity()
                        identityServer = null
                        serializedGroupIdentifier = null
                    }

                    TrustOrigin.TYPE.KEYCLOAK -> {
                        trustType = TRUST_TYPE_IDENTITY_SERVER
                        mediatorOrGroupOwnerIdentity = null
                        identityServer = trustOrigin.getKeycloakServer()
                        serializedGroupIdentifier = null
                    }

                    TrustOrigin.TYPE.SERVER_GROUP_V2 -> {
                        trustType = TRUST_TYPE_SERVER_GROUP_V2
                        mediatorOrGroupOwnerIdentity = null
                        identityServer = null
                        serializedGroupIdentifier = trustOrigin.getGroupIdentifier()!!.bytes
                    }
                }
                var mediatorOrGroupOwnerTrustLevelMajor: Int? = null
                if (mediatorOrGroupOwnerIdentity != null) {
                    val mediatorOrGroupOwner: ContactIdentity? = ContactIdentity.get(
                        identityManagerSession,
                        ownedIdentity,
                        mediatorOrGroupOwnerIdentity
                    )
                    if (mediatorOrGroupOwner == null) {
                        return null
                    }
                    mediatorOrGroupOwnerTrustLevelMajor = mediatorOrGroupOwner.getTrustLevel().major
                }

                val contactTrustOrigin = ContactTrustOrigin(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    trustOrigin.getTimestamp(),
                    trustType,
                    mediatorOrGroupOwnerIdentity,
                    mediatorOrGroupOwnerTrustLevelMajor,
                    identityServer,
                    serializedGroupIdentifier
                )
                contactTrustOrigin.insert()
                return contactTrustOrigin
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        // endregion
        // region getters
        fun getAll(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity,
            ownedIdentity: Identity
        ): Array<ContactTrustOrigin?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactTrustOrigin.getAll",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + CONTACT_IDENTITY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ?" +
                            " ORDER BY " + TIMESTAMP + " DESC;"
                ).use { statement ->
                    statement.setBytes(1, contactIdentity.getBytes())
                    statement.setBytes(2, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactTrustOrigin?> =
                            ArrayList<ContactTrustOrigin?>()
                        while (res.next()) {
                            list.add(ContactTrustOrigin(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactTrustOrigin?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ContactTrustOrigin>(0)
            }
        }

        // endregion
        // region backup
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): Array<Pojo_0?> {
            val contactTrustOrigins: Array<ContactTrustOrigin?> =
                getAll(identityManagerSession, contactIdentity, ownedIdentity)
            val pojos = arrayOfNulls<Pojo_0>(contactTrustOrigins.size)
            for (i in contactTrustOrigins.indices) {
                pojos[i] = contactTrustOrigins[i]!!.backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity,
            pojos: Array<Pojo_0>?
        ) {
            if (pojos == null) {
                return
            }
            for (pojo in pojos) {
                restore(identityManagerSession, ownedIdentity, contactIdentity, pojo)
            }
        }

        @Throws(SQLException::class)
        private fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity,
            pojo: Pojo_0
        ) {
            var mediatorOrGroupOwnerIdentity: Identity? = null
            try {
                if (pojo.mediator_or_group_owner_identity != null) {
                    mediatorOrGroupOwnerIdentity =
                        Identity.of(pojo.mediator_or_group_owner_identity!!)
                }
            } catch (e: DecodingException) {
                Logger.x(e)
            }
            val contactTrustOrigin = ContactTrustOrigin(
                identityManagerSession,
                contactIdentity,
                ownedIdentity,
                pojo.timestamp,
                pojo.readTrust_type(),
                mediatorOrGroupOwnerIdentity,
                pojo.mediator_or_group_owner_trust_level_major,
                pojo.identity_server,
                pojo.raw_obv_group_v2_identifier
            )
            contactTrustOrigin.insert()
        }
    }
}
