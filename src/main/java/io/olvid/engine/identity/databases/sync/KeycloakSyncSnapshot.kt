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
package io.olvid.engine.identity.databases.sync

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.KeycloakServer
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException
import java.util.Arrays
import kotlin.collections.HashSet
import kotlin.collections.MutableList

@JsonIgnoreProperties(ignoreUnknown = true)
class KeycloakSyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var server_url: String? = null
    @JvmField var client_id: String? = null
    @JvmField var client_secret: String? = null
    @JvmField var keycloak_user_id: String? = null
    @JvmField var jwks: String? = null
    @JvmField var signature_key: String? = null
    @JvmField var self_revocation_test_nonce: String? = null
    @JvmField var transfer_restricted: Boolean = false
    @JvmField var supports_id_based_auth: Boolean = false
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession?,
        ownedIdentity: Identity?,
        keycloak: KeycloakSyncSnapshot
    ): KeycloakServer? {
        if (!domain!!.contains(SERVER_URL) || !domain!!.contains(CLIENT_ID) || !domain!!.contains(
                KEYCLOAK_USER_ID
            ) || !domain!!.contains(JWKS)
        ) {
            Logger.e("Trying to restore an incomplete KeycloakSyncSnapshot. Domain: " + domain)
            throw Exception()
        }
        if (keycloak.server_url == null || keycloak.jwks == null) {
            return null
        }

        try {
            val keycloakServer = KeycloakServer(
                identityManagerSession!!,
                server_url,
                ownedIdentity!!,
                jwks,
                if (domain!!.contains(
                        SIGNATURE_KEY
                    )
                ) signature_key else null,
                client_id,
                client_secret,
                domain!!.contains(
                    TRANSFER_RESTRICTED
                ) && transfer_restricted,
                domain!!.contains(SUPPORTS_ID_BASED_AUTH) && supports_id_based_auth
            )
            keycloakServer.insert()
            keycloakServer.setKeycloakUserId(keycloak_user_id)
            keycloakServer.setSelfRevocationTestNonce(self_revocation_test_nonce)

            return keycloakServer
        } catch (e: Exception) {
            Logger.x(e)
            return null
        }
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        if (otherSnapshotNode !is KeycloakSyncSnapshot) {
            return false
        }

        val other = otherSnapshotNode
        val domainIntersection = HashSet<String?>(domain)
        domainIntersection.retainAll(other.domain ?: emptySet())

        for (item in domainIntersection) {
            when (item) {
                SERVER_URL -> {
                    if (server_url != other.server_url) {
                        return false
                    }
                }

                CLIENT_ID -> {
                    if (client_id != other.client_id) {
                        return false
                    }
                }

                CLIENT_SECRET -> {
                    if (client_secret != other.client_secret) {
                        return false
                    }
                }

                KEYCLOAK_USER_ID -> {
                    if (keycloak_user_id != other.keycloak_user_id) {
                        return false
                    }
                }

                JWKS -> {
                    // TODO: deserialize for comparison
                    if (jwks != other.jwks) {
                        return false
                    }
                }

                SIGNATURE_KEY -> {
                    // TODO: deserialize for comparison
                    if (signature_key != other.signature_key) {
                        return false
                    }
                }

                SELF_REVOCATION_TEST_NONCE -> {
                    if (self_revocation_test_nonce != other.self_revocation_test_nonce) {
                        return false
                    }
                }

                TRANSFER_RESTRICTED -> {
                    if (transfer_restricted xor other.transfer_restricted) {
                        return false
                    }
                }

                SUPPORTS_ID_BASED_AUTH -> {
                    if (supports_id_based_auth xor other.supports_id_based_auth) {
                        return false
                    }
                }
            }
        }
        return true
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        // TODO computeDiff
        return null
    }

    companion object {
        const val SERVER_URL: String = "server_url"
        const val CLIENT_ID: String = "client_id"
        const val CLIENT_SECRET: String = "client_secret"
        const val KEYCLOAK_USER_ID: String = "keycloak_user_id"
        const val JWKS: String = "jwks"
        const val SIGNATURE_KEY: String = "signature_key"
        const val SELF_REVOCATION_TEST_NONCE: String = "self_revocation_test_nonce"
        const val TRANSFER_RESTRICTED: String = "transfer_restricted"
        const val SUPPORTS_ID_BASED_AUTH: String = "supports_id_based_auth"
        var DEFAULT_DOMAIN: HashSet<String> = HashSet(
            listOf(
                SERVER_URL,
                CLIENT_ID,
                CLIENT_SECRET,
                KEYCLOAK_USER_ID,
                JWKS,
                SIGNATURE_KEY,
                SELF_REVOCATION_TEST_NONCE,
                TRANSFER_RESTRICTED,
                SUPPORTS_ID_BASED_AUTH
            )
        )


        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            keycloakServer: KeycloakServer
        ): KeycloakSyncSnapshot {
            val keycloakSyncSnapshot = KeycloakSyncSnapshot()
            keycloakSyncSnapshot.server_url = keycloakServer.serverUrl
            keycloakSyncSnapshot.client_id = keycloakServer.clientId
            keycloakSyncSnapshot.client_secret = keycloakServer.clientSecret
            keycloakSyncSnapshot.keycloak_user_id = keycloakServer.getKeycloakUserId()
            keycloakSyncSnapshot.jwks = keycloakServer.serializedJwks
            keycloakSyncSnapshot.signature_key = keycloakServer.serializedSignatureKey
            keycloakSyncSnapshot.self_revocation_test_nonce =
                keycloakServer.getSelfRevocationTestNonce()
            keycloakSyncSnapshot.transfer_restricted = keycloakServer.isTransferRestricted()
            keycloakSyncSnapshot.supports_id_based_auth = keycloakServer.isIdBasedAuthSupported
            keycloakSyncSnapshot.domain = DEFAULT_DOMAIN
            return keycloakSyncSnapshot
        }
    }
}
