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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class KeycloakRevokedIdentity : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var rowId: Long = 0
    private var ownedIdentity: Identity? = null
    @JvmField val keycloakServerUrl: String?
    private var revokedIdentity: Identity? = null
    @JvmField val revocationType: Int
    @JvmField val revocationTimestamp: Long

    constructor(
        identityManagerSession: IdentityManagerSession,
        ownedIdentity: Identity,
        keycloakServerUrl: String?,
        revokedIdentity: Identity,
        revocationType: Int,
        revocationTimestamp: Long
    ) {
        this.identityManagerSession = identityManagerSession
        this.ownedIdentity = ownedIdentity
        this.keycloakServerUrl = keycloakServerUrl
        this.revokedIdentity = revokedIdentity
        this.revocationType = revocationType
        this.revocationTimestamp = revocationTimestamp
    }

    constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.rowId = res.getLong(ROW_ID)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.keycloakServerUrl = res.getString(KEYCLOAK_SERVER_URL)
        try {
            this.revokedIdentity = Identity.of(res.getBytes(REVOKED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.revocationType = res.getInt(REVOCATION_TYPE)
        this.revocationTimestamp = res.getLong(REVOCATION_TIMESTAMP)
    }

    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "KeycloakRevokedIdentity.insert",
            "INSERT INTO " + TABLE_NAME + "(" +
                    OWNED_IDENTITY + ", " +
                    KEYCLOAK_SERVER_URL + ", " +
                    REVOKED_IDENTITY + ", " +
                    REVOCATION_TYPE + ", " +
                    REVOCATION_TIMESTAMP + ") " +
                    " VALUES (?,?,?,?,?);",
            true
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setString(2, keycloakServerUrl)
            statement.setBytes(3, revokedIdentity!!.getBytes())
            statement.setInt(4, revocationType)
            statement.setLong(5, revocationTimestamp)
            statement.executeUpdate()
            statement.getGeneratedKeys().use { res ->
                if (res.next()) {
                    this.rowId = res.getLong(1)
                }
            }
        }
    }


    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "KeycloakRevokedIdentity.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + ROW_ID + " = ?;"
        ).use { statement ->
            statement.setLong(1, rowId)
            statement.executeUpdate()
        }
    }

    // region hooks
    override fun wasCommitted() {
        // no hooks around here
    } // endregion

    companion object {
        const val TABLE_NAME: String = "keycloak_revoked_identity"

        const val ROW_ID: String = "row_id"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val KEYCLOAK_SERVER_URL: String = "keycloak_server_url"
        const val REVOKED_IDENTITY: String = "revoked_identity"
        const val REVOCATION_TYPE: String = "revocation_type"
        const val REVOCATION_TIMESTAMP: String = "revocation_timestamp"

        const val TYPE_COMPROMISED: Int = 0
        const val TYPE_LEFT_COMPANY: Int = 1

        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            keycloakServerUrl: String?,
            revokedIdentity: Identity?,
            revocationType: Int,
            revocationTimestamp: Long
        ): KeycloakRevokedIdentity? {
            if (ownedIdentity == null || keycloakServerUrl == null || revokedIdentity == null) {
                return null
            }
            try {
                val keycloakRevokedIdentity = KeycloakRevokedIdentity(
                    identityManagerSession,
                    ownedIdentity,
                    keycloakServerUrl,
                    revokedIdentity,
                    revocationType,
                    revocationTimestamp
                )
                keycloakRevokedIdentity.insert()
                return keycloakRevokedIdentity
            } catch (_: SQLException) {
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
                            ROW_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            KEYCLOAK_SERVER_URL + " TEXT NOT NULL, " +
                            REVOKED_IDENTITY + " BLOB NOT NULL, " +
                            REVOCATION_TYPE + " INT NOT NULL, " +
                            REVOCATION_TIMESTAMP + " BIGINT NOT NULL, " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ", " + KEYCLOAK_SERVER_URL + ") REFERENCES " + KeycloakServer.TABLE_NAME + "(" + KeycloakServer.OWNED_IDENTITY + ", " + KeycloakServer.SERVER_URL + ") ON DELETE CASCADE);"
                )
                statement.execute("CREATE INDEX IF NOT EXISTS `index_" + TABLE_NAME + "_" + REVOKED_IDENTITY + "` ON " + TABLE_NAME + " (" + REVOKED_IDENTITY + ")")
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 25 && newVersion >= 25) {
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE keycloak_revoked_identity (" +
                                " row_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                " owned_identity BLOB NOT NULL, " +
                                " keycloak_server_url TEXT NOT NULL, " +
                                " revoked_identity BLOB NOT NULL, " +
                                " revocation_type INT NOT NULL, " +
                                " revocation_timestamp BIGINT NOT NULL, " +
                                " FOREIGN KEY (owned_identity, keycloak_server_url) REFERENCES keycloak_server (owned_identity, server_url) ON DELETE CASCADE);"
                    )
                    statement.execute("CREATE INDEX `index_keycloak_revoked_identity_revoked_identity` ON keycloak_revoked_identity (revoked_identity)")
                }
                oldVersion = 25
            }
        }


        // endregion
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            identityToVerify: Identity?
        ): MutableList<KeycloakRevokedIdentity?>? {
            if ((ownedIdentity == null) || (identityToVerify == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "KeycloakRevokedIdentity.get",
                "SELECT kr.* FROM " + TABLE_NAME + " AS kr " +
                        " INNER JOIN " + OwnedIdentity.TABLE_NAME + " AS oi " +
                        " ON kr." + OWNED_IDENTITY + " = oi." + OwnedIdentity.OWNED_IDENTITY +
                        " AND kr." + KEYCLOAK_SERVER_URL + " = oi." + OwnedIdentity.KEYCLOAK_SERVER_URL +
                        " WHERE oi." + OwnedIdentity.OWNED_IDENTITY + " = ? " +
                        " AND kr." + REVOKED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setBytes(2, identityToVerify.getBytes())
                statement.executeQuery().use { res ->
                    val list: MutableList<KeycloakRevokedIdentity?> =
                        ArrayList<KeycloakRevokedIdentity?>()
                    while (res.next()) {
                        list.add(KeycloakRevokedIdentity(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        @Throws(SQLException::class)
        fun prune(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            keycloakServerUrl: String?,
            timestamp: Long
        ) {
            if ((ownedIdentity == null) || (keycloakServerUrl == null)) {
                return
            }
            identityManagerSession.session.prepareStatement(
                "KeycloakRevokedIdentity.prune",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + KEYCLOAK_SERVER_URL + " = ? " +
                        " AND " + REVOCATION_TIMESTAMP + " < ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setString(2, keycloakServerUrl)
                statement.setLong(3, timestamp)
                statement.executeUpdate()
            }
        }
    }
}
