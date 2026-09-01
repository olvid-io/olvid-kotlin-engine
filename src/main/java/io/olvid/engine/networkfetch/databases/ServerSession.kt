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
package io.olvid.engine.networkfetch.databases

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.networkfetch.datatypes.FetchManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class ServerSession : ObvDatabase {
    enum class Permission {
        CALL,
        WEB_CLIENT,
        MULTI_DEVICE,
    }

    enum class ApiKeyStatus {
        VALID,
        UNKNOWN,
        LICENSES_EXHAUSTED,
        EXPIRED,
        OPEN_BETA_KEY,
        FREE_TRIAL_KEY,
        AWAITING_PAYMENT_GRACE_PERIOD,
        AWAITING_PAYMENT_ON_HOLD,
        FREE_TRIAL_KEY_EXPIRED,
    }

    private val fetchManagerSession: FetchManagerSession

    private var ownedIdentity: Identity? = null
    var nonce: ByteArray?
        private set
    var challenge: ByteArray?
        private set
    var response: ByteArray?
        private set
    var token: ByteArray?
        private set
    private var apiKeyStatus: Int
    private var permissions: Long
    var apiKeyExpirationTimestamp: Long
        private set

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getApiKeyStatus(): ApiKeyStatus {
        return deserializeApiKeyStatus(apiKeyStatus)
    }

    fun getPermissions(): MutableList<Permission?> {
        return deserializePermissions(permissions)
    }

    fun setChallengeAndNonce(challenge: ByteArray?, nonce: ByteArray?) {
        try {
            fetchManagerSession.session.prepareStatement(
                "ServerSession.setChallengeAndNonce",
                "UPDATE " + TABLE_NAME + " SET " + CHALLENGE + " = ?, " + NONCE + " = ? WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, challenge)
                statement.setBytes(2, nonce)
                statement.setBytes(3, ownedIdentity!!.getBytes())
                statement.executeUpdate()
                this.challenge = challenge
                this.nonce = nonce
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun setResponseForChallenge(challenge: ByteArray?, response: ByteArray?) {
        if (response == null || challenge == null) {
            return
        }
        try {
            fetchManagerSession.session.prepareStatement(
                "ServerSession.setResponseForChallenge",
                "UPDATE " + TABLE_NAME +
                        " SET " + RESPONSE + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + CHALLENGE + " = ?;"
            ).use { statement ->
                statement.setBytes(1, response)
                statement.setBytes(2, ownedIdentity!!.getBytes())
                statement.setBytes(3, challenge)
                statement.executeUpdate()
                if (this.challenge.contentEquals(challenge)) {
                    this.response = response
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    fun setTokenAndPermissions(
        token: ByteArray?,
        apiKeyStatus: Int,
        permissions: Long,
        apiKeyExpirationTimestamp: Long
    ) {
        if (token == null) {
            return
        }
        try {
            fetchManagerSession.session.prepareStatement(
                "ServerSession.setTokenAndPermissions",
                "UPDATE " + TABLE_NAME +
                        " SET " + TOKEN + " = ?, " +
                        API_KEY_STATUS + " = ?, " +
                        PERMISSIONS + " = ?, " +
                        API_KEY_EXPIRATION_TIMESTAMP + " = ? " +
                        " WHERE " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, token)
                statement.setInt(2, apiKeyStatus)
                statement.setLong(3, permissions)
                statement.setLong(4, apiKeyExpirationTimestamp)
                statement.setBytes(5, ownedIdentity!!.getBytes())
                statement.executeUpdate()
                this.token = token
                this.apiKeyStatus = apiKeyStatus
                this.permissions = permissions
                this.apiKeyExpirationTimestamp = apiKeyExpirationTimestamp
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    private constructor(fetchManagerSession: FetchManagerSession, ownedIdentity: Identity) {
        this.fetchManagerSession = fetchManagerSession
        this.ownedIdentity = ownedIdentity
        this.nonce = null
        this.challenge = null
        this.response = null
        this.token = null
        this.apiKeyStatus = -1
        this.permissions = 0
        this.apiKeyExpirationTimestamp = 0
    }

    private constructor(fetchManagerSession: FetchManagerSession, res: ResultSet) {
        this.fetchManagerSession = fetchManagerSession
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (e: DecodingException) {
            Logger.x(e)
        }
        this.nonce = res.getBytes(NONCE)
        this.challenge = res.getBytes(CHALLENGE)
        this.response = res.getBytes(RESPONSE)
        this.token = res.getBytes(TOKEN)

        this.apiKeyStatus = res.getInt(API_KEY_STATUS)
        this.permissions = res.getLong(PERMISSIONS)
        this.apiKeyExpirationTimestamp = res.getLong(API_KEY_EXPIRATION_TIMESTAMP)
    }


    @Throws(SQLException::class)
    override fun insert() {
        fetchManagerSession.session.prepareStatement(
            "ServerSession.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES(?,?,?,?,?, ?,?,?);"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.setBytes(2, nonce)
            statement.setBytes(3, challenge)
            statement.setBytes(4, response)
            statement.setBytes(5, token)

            statement.setInt(6, apiKeyStatus)
            statement.setLong(7, permissions)
            statement.setLong(8, apiKeyExpirationTimestamp)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        fetchManagerSession.session.prepareStatement(
            "ServerSession.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, ownedIdentity!!.getBytes())
            statement.executeUpdate()
        }
    }


    override fun wasCommitted() {
        // No hooks
    }

    companion object {
        const val TABLE_NAME: String = "server_session"

        const val OWNED_IDENTITY: String = "identity"
        const val NONCE: String = "nonce"
        const val CHALLENGE: String = "challenge"
        const val RESPONSE: String = "response"
        const val TOKEN: String = "token"
        const val API_KEY_STATUS: String = "api_key_status"
        const val PERMISSIONS: String = "permissions"
        const val API_KEY_EXPIRATION_TIMESTAMP: String = "api_key_expiration_timestamp"

        fun deserializeApiKeyStatus(apiKeyStatus: Int): ApiKeyStatus {
            when (apiKeyStatus) {
                Constants.API_KEY_STATUS_VALID -> return ApiKeyStatus.VALID
                Constants.API_KEY_STATUS_EXPIRED -> return ApiKeyStatus.EXPIRED
                Constants.API_KEY_STATUS_LICENSES_EXHAUSTED -> return ApiKeyStatus.LICENSES_EXHAUSTED
                Constants.API_KEY_STATUS_OPEN_BETA_KEY -> return ApiKeyStatus.OPEN_BETA_KEY
                Constants.API_KEY_STATUS_FREE_TRIAL_KEY -> return ApiKeyStatus.FREE_TRIAL_KEY
                Constants.API_KEY_STATUS_AWAITING_PAYMENT_GRACE_PERIOD -> return ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD
                Constants.API_KEY_STATUS_AWAITING_PAYMENT_ON_HOLD -> return ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD
                Constants.API_KEY_STATUS_FREE_TRIAL_KEY_EXPIRED -> return ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED
                Constants.API_KEY_STATUS_UNKNOWN -> return ApiKeyStatus.UNKNOWN
                else -> return ApiKeyStatus.UNKNOWN
            }
        }

        fun deserializePermissions(permissions: Long): MutableList<Permission?> {
            val out: MutableList<Permission?> = ArrayList<Permission?>()
            if ((permissions and Constants.API_KEY_PERMISSION_CALL) != 0L) {
                out.add(Permission.CALL)
            }
            if ((permissions and Constants.API_KEY_PERMISSION_WEB_CLIENT) != 0L) {
                out.add(Permission.WEB_CLIENT)
            }
            if ((permissions and Constants.API_KEY_PERMISSION_MULTI_DEVICE) != 0L) {
                out.add(Permission.MULTI_DEVICE)
            }
            return out
        }

        fun deleteCurrentTokenIfEqualTo(
            fetchManagerSession: FetchManagerSession,
            token: ByteArray?,
            ownedIdentity: Identity?
        ) {
            if (ownedIdentity == null) {
                return
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "ServerSession.deleteCurrentTokenIfEqualTo",
                    "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ? AND " + TOKEN + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, token)
                    statement.executeUpdate()
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
        }

        fun deleteForIdentity(fetchManagerSession: FetchManagerSession, ownedIdentity: Identity?) {
            if (ownedIdentity == null) {
                return
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "ServerSession.deleteForIdentity",
                    "DELETE FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeUpdate()
                }
            } catch (e: SQLException) {
                Logger.x(e)
            }
        }


        fun create(
            fetchManagerSession: FetchManagerSession?,
            ownedIdentity: Identity?
        ): ServerSession? {
            if (ownedIdentity == null) {
                return null
            }
            try {
                val serverSession = ServerSession(fetchManagerSession!!, ownedIdentity)
                serverSession.insert()
                return serverSession
            } catch (_: SQLException) {
                Logger.w("SQLException during ServerSession insert.")
                return null
            }
        }

        fun getToken(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?
        ): ByteArray? {
            val serverSession: ServerSession? = get(fetchManagerSession, ownedIdentity)
            return if (serverSession == null) null else serverSession.token
        }

        fun get(
            fetchManagerSession: FetchManagerSession,
            ownedIdentity: Identity?
        ): ServerSession? {
            if (ownedIdentity == null) {
                return null
            }
            try {
                fetchManagerSession.session.prepareStatement(
                    "ServerSession.get",
                    "SELECT * FROM " + TABLE_NAME + " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return ServerSession(fetchManagerSession, res)
                        } else {
                            return null
                        }
                    }
                }
            } catch (e: SQLException) {
                Logger.x(e)
                return null
            }
        }

        @Throws(SQLException::class)
        fun getAll(fetchManagerSession: FetchManagerSession): Array<ServerSession?> {
            fetchManagerSession.session.createStatement("ServerSession.getAll").use { statement ->
                statement.executeQuery("SELECT * FROM " + TABLE_NAME).use { res ->
                    val list: MutableList<ServerSession?> = ArrayList<ServerSession?>()
                    while (res.next()) {
                        list.add(ServerSession(fetchManagerSession, res))
                    }
                    return list.toTypedArray<ServerSession?>()
                }
            }
        }


        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            OWNED_IDENTITY + " BLOB PRIMARY KEY, " +
                            NONCE + " BLOB, " +
                            CHALLENGE + " BLOB, " +
                            RESPONSE + " BLOB, " +
                            TOKEN + " BLOB, " +
                            API_KEY_STATUS + " INT NOT NULL, " +
                            PERMISSIONS + " BIGINT NOT NULL, " +
                            API_KEY_EXPIRATION_TIMESTAMP + " BIGINT NOT NULL);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 18 && newVersion >= 18) {
                Logger.d("MIGRATING `server_session` DATABASE FROM VERSION " + oldVersion + " TO 18")
                session.createStatement().use { statement ->
                    statement.execute("DROP TABLE server_session")
                    statement.execute(
                        "CREATE TABLE server_session (" +
                                "identity BLOB PRIMARY KEY, " +
                                "nonce BLOB, " +
                                "challenge BLOB, " +
                                "response BLOB, " +
                                "token BLOB, " +
                                "api_key_status INT NOT NULL, " +
                                "permissions BIGINT NOT NULL, " +
                                "api_key_expiration_timestamp BIGINT NOT NULL);"
                    )
                }
                oldVersion = 18
            }
        }
    }
}
