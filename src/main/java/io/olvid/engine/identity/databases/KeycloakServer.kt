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
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.sql.ResultSet
import java.sql.SQLException
import java.util.Arrays
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet

class KeycloakServer : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    @JvmField val serverUrl: String?
    private var ownedIdentity: Identity? = null
    @JvmField val serializedJwks: String?
    @JvmField val clientId: String? // non null only for the keycloak server of a managed identity
    @JvmField val clientSecret: String? // non null only for the keycloak server of a managed identity
    private var keycloakUserId: String? // non null only for the keycloak server of a managed identity
    @JvmField val serializedAuthState: String? // non null only for the keycloak server of a managed identity
    private var serializedPushTopics: ByteArray? // non null only for the keycloak server of a managed identity. Contains a serialized array of String, separated by 0 byte (null or empty are equivalent)
    @JvmField val serializedSignatureKey: String? // the key (serialized JsonWebKey) used to sign the user's details which should not change
    private var selfRevocationTestNonce: String? // a secret nonce given to the user when they upload their key, to check whether they were revoked
    var latestRevocationListTimestamp: Long // the last time a revocation list was retrieved from the keycloak server
        private set
    private val latestGroupUpdateTimestamp: Long // the last time groups wre retrieved from the keycloak server
    @JvmField val ownApiKey: String? // the api key given to us by keycloak, non null only for the keycloak server of a managed identity
    private var transferRestricted: Boolean // true if transfer requires a re-authentication, may only be true for the keycloak server of a managed identity
    var isIdBasedAuthSupported: Boolean // true if ID-based authentication is supported, may only be true for the keycloak server of a managed identity
        private set

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    fun getKeycloakUserId(): String? {
        return keycloakUserId
    }

    @get:Throws(Exception::class)
    val jwks: JsonWebKeySet
        get() = JsonWebKeySet(serializedJwks)

    @get:Throws(Exception::class)
    val signatureKey: JsonWebKey?
        get() {
            if (serializedSignatureKey == null) {
                return null
            }
            return JsonWebKey.Factory.newJwk(serializedSignatureKey)
        }

    fun getSelfRevocationTestNonce(): String? {
        return selfRevocationTestNonce
    }

    fun isTransferRestricted(): Boolean {
        return transferRestricted
    }

    val pushTopics: MutableList<String>
        get() {
            val serializedPT = serializedPushTopics ?: return ArrayList(0)

            val res: MutableList<String> = ArrayList()
            var startPos = 0
            for (i in serializedPT.indices) {
                if (serializedPT[i].toInt() == 0) {
                    res.add(
                        String(
                            serializedPT.copyOfRange(startPos, i), StandardCharsets.UTF_8
                        )
                    )
                    startPos = i + 1
                }
            }
            if (startPos != serializedPT.size) {
                res.add(
                    String(
                        serializedPT.copyOfRange(startPos, serializedPT.size), StandardCharsets.UTF_8
                    )
                )
            }
            return res
        }

    fun getLatestGroupUpdateTimestamp(): Long {
        return latestGroupUpdateTimestamp
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        serverUrl: String?,
        ownedIdentity: Identity,
        serializedJwks: String?,
        serializedSignatureKey: String?,
        clientId: String?,
        clientSecret: String?,
        transferRestricted: Boolean,
        supportsIdBasedAuth: Boolean
    ) {
        this.identityManagerSession = identityManagerSession
        this.serverUrl = serverUrl
        this.ownedIdentity = ownedIdentity
        this.serializedJwks = serializedJwks
        this.clientId = clientId
        this.clientSecret = clientSecret
        this.keycloakUserId = null
        this.serializedAuthState = null
        this.serializedPushTopics = null
        this.serializedSignatureKey = serializedSignatureKey
        this.selfRevocationTestNonce = null
        this.latestRevocationListTimestamp = 0
        this.latestGroupUpdateTimestamp = 0
        this.ownApiKey = null
        this.transferRestricted = transferRestricted
        this.isIdBasedAuthSupported = supportsIdBasedAuth
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.serverUrl = res.getString(SERVER_URL)
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.serializedJwks = res.getString(SERIALIZED_JWKS)
        this.clientId = res.getString(CLIENT_ID)
        this.clientSecret = res.getString(CLIENT_SECRET)
        this.keycloakUserId = res.getString(KEYCLOAK_USER_ID)
        this.serializedAuthState = res.getString(SERIALIZED_AUTH_STATE)
        this.serializedPushTopics = res.getBytes(SERIALIZED_PUSH_TOPICS)
        this.serializedSignatureKey = res.getString(SERIALIZED_SIGNATURE_KEY)
        this.selfRevocationTestNonce = res.getString(SELF_REVOCATION_TEST_NONCE)
        this.latestRevocationListTimestamp = res.getLong(LATEST_REVOCATION_LIST_TIMESTAMP)
        this.latestGroupUpdateTimestamp = res.getLong(LATEST_GROUP_UPDATE_TIMESTAMP)
        this.ownApiKey = res.getString(OWN_API_KEY)
        this.transferRestricted = res.getBoolean(TRANSFER_RESTRICTED)
        this.isIdBasedAuthSupported = res.getBoolean(SUPPORTS_ID_BASED_AUTH)
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?);"
        ).use { statement ->
            statement.setString(1, serverUrl)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setString(3, serializedJwks)
            statement.setString(4, clientId)
            statement.setString(5, clientSecret)

            statement.setString(6, keycloakUserId)
            statement.setString(7, serializedAuthState)
            statement.setBytes(8, serializedPushTopics)
            statement.setString(9, serializedSignatureKey)
            statement.setString(10, selfRevocationTestNonce)

            statement.setLong(11, latestRevocationListTimestamp)
            statement.setLong(12, latestGroupUpdateTimestamp)
            statement.setString(13, ownApiKey)
            statement.setBoolean(14, transferRestricted)
            statement.setBoolean(15, this.isIdBasedAuthSupported)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, serverUrl)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    fun setKeycloakUserId(userId: String?) {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setKeycloakUserId",
            "UPDATE " + TABLE_NAME +
                    " SET " + KEYCLOAK_USER_ID + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, userId)
            statement.setString(2, this.serverUrl)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.keycloakUserId = userId
        }
    }

    @Throws(SQLException::class)
    fun setTransferRestricted(transferRestricted: Boolean) {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setTransferRestricted",
            "UPDATE " + TABLE_NAME +
                    " SET " + TRANSFER_RESTRICTED + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, transferRestricted)
            statement.setString(2, this.serverUrl)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.transferRestricted = transferRestricted
        }
    }

    @Throws(SQLException::class)
    fun setSupportsIdBasedAuth(supportsIdBasedAuth: Boolean) {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setSupportsIdBasedAuth",
            "UPDATE " + TABLE_NAME +
                    " SET " + SUPPORTS_ID_BASED_AUTH + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, supportsIdBasedAuth)
            statement.setString(2, this.serverUrl)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.isIdBasedAuthSupported = supportsIdBasedAuth
        }
    }

    @Throws(SQLException::class)
    fun setPushTopics(pushTopics: MutableList<String>?) {
        var serializedPushTopics: ByteArray? = null
        if (pushTopics == null || pushTopics.isEmpty()) {
            serializedPushTopics = null
        } else {
            try {
                ByteArrayOutputStream().use { baos ->
                    var first = true
                    for (pushTopic in pushTopics) {
                        if (!first) {
                            baos.write(byteArrayOf(0))
                        }
                        first = false
                        baos.write(pushTopic.toByteArray(StandardCharsets.UTF_8))
                    }
                    serializedPushTopics = baos.toByteArray()
                }
            } catch (_: IOException) {
                serializedPushTopics = null
            }
        }

        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setPushTopics",
            "UPDATE " + TABLE_NAME +
                    " SET " + SERIALIZED_PUSH_TOPICS + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, serializedPushTopics)
            statement.setString(2, this.serverUrl)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.serializedPushTopics = serializedPushTopics
        }
    }

    @Throws(SQLException::class)
    fun setSelfRevocationTestNonce(selfRevocationTestNonce: String?) {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setSelfRevocationTestNonce",
            "UPDATE " + TABLE_NAME +
                    " SET " + SELF_REVOCATION_TEST_NONCE + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, selfRevocationTestNonce)
            statement.setString(2, this.serverUrl)
            statement.setBytes(3, this.ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.selfRevocationTestNonce = selfRevocationTestNonce
        }
    }

    @Throws(SQLException::class)
    fun setLatestGroupUpdateTimestamp(latestGroupUpdateTimestamp: Long) {
        identityManagerSession.session.prepareStatement(
            "KeycloakServer.setLatestGroupUpdateTimestamp",
            "UPDATE " + TABLE_NAME +
                    " SET " + LATEST_GROUP_UPDATE_TIMESTAMP + " = ? " +
                    " WHERE " + SERVER_URL + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setLong(1, latestGroupUpdateTimestamp)
            statement.setString(2, serverUrl)
            statement.setBytes(3, ownedIdentity!!.getBytes())
            statement.executeUpdate()
            this.latestRevocationListTimestamp = latestGroupUpdateTimestamp
        }
    }


    // endregion
    // region hooks
    override fun wasCommitted() {
        // No notifications here
    }

    // endregion
    // region backup
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.server_url = serverUrl
        pojo.jwks = serializedJwks

        pojo.client_id = clientId
        pojo.client_secret = clientSecret
        pojo.keycloak_user_id = keycloakUserId

        pojo.serialized_signature_key = serializedSignatureKey
        pojo.self_revocation_test_nonce = selfRevocationTestNonce
        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        @JvmField var server_url: String? = null
        @JvmField var jwks: String? = null
        @JvmField var client_id: String? = null
        @JvmField var client_secret: String? = null
        @JvmField var keycloak_user_id: String? = null
        @JvmField var serialized_signature_key: String? = null
        @JvmField var self_revocation_test_nonce: String? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "keycloak_server"

        const val SERVER_URL: String = "server_url"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val SERIALIZED_JWKS: String = "serialized_jwks"
        const val CLIENT_ID: String = "client_id"
        const val CLIENT_SECRET: String = "client_secret"
        const val KEYCLOAK_USER_ID: String = "keycloak_user_id"
        const val SERIALIZED_AUTH_STATE: String = "serialized_auth_state"
        const val SERIALIZED_PUSH_TOPICS: String = "serialized_push_topics"
        const val SERIALIZED_SIGNATURE_KEY: String = "serialized_signature_key"
        const val SELF_REVOCATION_TEST_NONCE: String = "self_revocation_test_nonce"
        const val LATEST_REVOCATION_LIST_TIMESTAMP: String = "latest_revocation_list_timestamp"
        const val LATEST_GROUP_UPDATE_TIMESTAMP: String = "latest_group_update_timestamp"
        const val OWN_API_KEY: String = "own_api_key"
        const val TRANSFER_RESTRICTED: String = "transfer_restricted"
        const val SUPPORTS_ID_BASED_AUTH: String = "supports_id_based_auth"


        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity?,
            serializedJwks: String?,
            serializedKey: String?,
            clientId: String?,
            clientSecret: String?,
            transferRestricted: Boolean,
            supportsIdBasedAuth: Boolean
        ): KeycloakServer? {
            if (serverUrl == null || ownedIdentity == null || serializedJwks == null) {
                return null
            }
            try {
                val keycloakServer = KeycloakServer(
                    identityManagerSession,
                    serverUrl,
                    ownedIdentity,
                    serializedJwks,
                    serializedKey,
                    clientId,
                    clientSecret,
                    transferRestricted,
                    supportsIdBasedAuth
                )
                keycloakServer.insert()
                return keycloakServer
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
                            SERVER_URL + " TEXT NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            SERIALIZED_JWKS + " TEXT NOT NULL, " +
                            CLIENT_ID + " TEXT, " +
                            CLIENT_SECRET + " TEXT, " +
                            KEYCLOAK_USER_ID + " TEXT, " +
                            SERIALIZED_AUTH_STATE + " TEXT, " +
                            SERIALIZED_PUSH_TOPICS + " BLOB, " +
                            SERIALIZED_SIGNATURE_KEY + " TEXT, " +
                            SELF_REVOCATION_TEST_NONCE + " TEXT, " +
                            LATEST_REVOCATION_LIST_TIMESTAMP + " BIGINT NOT NULL, " +
                            LATEST_GROUP_UPDATE_TIMESTAMP + " BIGINT NOT NULL, " +
                            OWN_API_KEY + " TEXT, " +
                            TRANSFER_RESTRICTED + " BIT NOT NULL, " +
                            SUPPORTS_ID_BASED_AUTH + " BIT NOT NULL, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + SERVER_URL + ", " + OWNED_IDENTITY + "), " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + " (" + OwnedIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 24 && newVersion >= 24) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 24")
                session.createStatement().use { statement ->
                    // migration anomaly
                    // we forgot to add the create table statement in the v20 migration, we add it here with an "if not exist"
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS keycloak_server (" +
                                " server_url TEXT NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " serialized_jwks TEXT NOT NULL, " +
                                " client_id TEXT, " +
                                " client_secret TEXT, " +
                                " keycloak_user_id TEXT, " +
                                " serialized_auth_state TEXT, " +
                                " CONSTRAINT PK_keycloak_server PRIMARY KEY(server_url, owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity (identity) ON DELETE CASCADE);"
                    )
                    // back to normal migration
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `serialized_push_topics` BLOB DEFAULT NULL;")
                }
                oldVersion = 24
            }
            if (oldVersion < 25 && newVersion >= 25) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 25")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `serialized_signature_key` TEXT DEFAULT NULL;")
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `self_revocation_test_nonce` TEXT DEFAULT NULL;")
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `latest_revocation_list_timestamp` BIGINT NOT NULL DEFAULT 0;")
                }
                oldVersion = 25
            }
            if (oldVersion < 34 && newVersion >= 34) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 34")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `latest_group_update_timestamp` BIGINT NOT NULL DEFAULT 0;")
                }
                oldVersion = 34
            }
            if (oldVersion < 35 && newVersion >= 35) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 35")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `own_api_key` TEXT DEFAULT NULL;")
                }
                oldVersion = 35
            }
            if (oldVersion < 42 && newVersion >= 42) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 42")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `transfer_restricted` BIT NOT NULL DEFAULT 0;")
                }
                oldVersion = 42
            }
            if (oldVersion < 49 && newVersion >= 49) {
                Logger.d("MIGRATING `keycloak_server` DATABASE FROM VERSION " + oldVersion + " TO 49")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE keycloak_server ADD COLUMN `supports_id_based_auth` BIT NOT NULL DEFAULT 0;")
                }
                oldVersion = 49
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity
        ): KeycloakServer? {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + SERVER_URL + " = ?" +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, serverUrl)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return KeycloakServer(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun getAllWithPushTopic(
            identityManagerSession: IdentityManagerSession,
            pushTopic: String?
        ): MutableList<KeycloakServer?> {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.getAllWithPushTopic",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + SERIALIZED_PUSH_TOPICS + " LIKE ?;"
            ).use { statement ->
                statement.setBytes(1, ("%" + pushTopic + "%").toByteArray(StandardCharsets.UTF_8))
                statement.executeQuery().use { res ->
                    val list: MutableList<KeycloakServer?> = ArrayList<KeycloakServer?>()
                    while (res.next()) {
                        list.add(KeycloakServer(identityManagerSession, res))
                    }
                    return list
                }
            }
        }

        // endregion
        // region setters
        @Throws(SQLException::class)
        fun saveAuthState(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            serializedAuthState: String?
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.saveAuthState",
                "UPDATE " + TABLE_NAME +
                        " SET " + SERIALIZED_AUTH_STATE + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, serializedAuthState)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun saveJwks(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            serializedJwks: String?
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.saveJwks",
                "UPDATE " + TABLE_NAME +
                        " SET " + SERIALIZED_JWKS + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, serializedJwks)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun saveApiKey(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            apiKey: String?
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.saveApiKey",
                "UPDATE " + TABLE_NAME +
                        " SET " + OWN_API_KEY + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, apiKey)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun setKeycloakUserId(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            userId: String?
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.setKeycloakUserId",
                "UPDATE " + TABLE_NAME +
                        " SET " + KEYCLOAK_USER_ID + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, userId)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun setSignatureKey(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            signatureKey: JsonWebKey?
        ) {
            // everytime we reset the signature key, we also reset the latestGroupUpdateTimestamp to re-download all groups
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.setSignatureKey",
                "UPDATE " + TABLE_NAME +
                        " SET " + SERIALIZED_SIGNATURE_KEY + " = ?, " +
                        LATEST_GROUP_UPDATE_TIMESTAMP + " = 0 " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setString(1, if (signatureKey == null) null else signatureKey.toJson())
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun setSupportsIdBasedAuth(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            supportsIdBasedAuth: Boolean
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.setSupportsIdBasedAuth",
                "UPDATE " + TABLE_NAME +
                        " SET " + SUPPORTS_ID_BASED_AUTH + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBoolean(1, supportsIdBasedAuth)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun setLatestRevocationListTimestamp(
            identityManagerSession: IdentityManagerSession,
            serverUrl: String?,
            ownedIdentity: Identity,
            latestRevocationListTimetamp: Long
        ) {
            identityManagerSession.session.prepareStatement(
                "KeycloakServer.setLatestRevocationListTimestamp",
                "UPDATE " + TABLE_NAME +
                        " SET " + LATEST_REVOCATION_LIST_TIMESTAMP + " = ? " +
                        " WHERE " + SERVER_URL + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setLong(1, latestRevocationListTimetamp)
                statement.setString(2, serverUrl)
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
            }
        }

        @Throws(SQLException::class)
        fun restore(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            pojo: Pojo_0
        ): KeycloakServer? {
            if (ownedIdentity == null || pojo.server_url == null || pojo.client_id == null || pojo.jwks == null) {
                return null
            }

            val keycloakServer = KeycloakServer(
                identityManagerSession,
                pojo.server_url,
                ownedIdentity,
                pojo.jwks,
                pojo.serialized_signature_key,
                pojo.client_id,
                pojo.client_secret,
                false,
                false
            )
            keycloakServer.keycloakUserId = pojo.keycloak_user_id
            keycloakServer.selfRevocationTestNonce = pojo.self_revocation_test_nonce
            keycloakServer.insert()

            return keycloakServer
        }
    }
}
