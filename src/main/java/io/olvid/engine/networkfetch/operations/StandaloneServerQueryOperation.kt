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
package io.olvid.engine.networkfetch.operations

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2CreateBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2DeleteBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2DownloadProfilePictureQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2ListBackupsQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2UploadBackupQuery
import io.olvid.engine.datatypes.containers.ServerQuery.KeycloakIdBasedAuthGetSessionQuery
import io.olvid.engine.datatypes.containers.ServerQuery.KeycloakIdBasedAuthRequestChallengeQuery
import io.olvid.engine.datatypes.containers.ServerQuery.RegisterApiKeyQuery
import io.olvid.engine.encoder.Encoded
import javax.net.ssl.SSLSocketFactory

class StandaloneServerQueryOperation(
    private val serverQuery: ServerQuery,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?
) : Operation() {
    var serverResponse: Encoded? = null // will be set if the operation finishes normally
        private set

    override fun doExecute() {
        var finished = false
        try {
            val serverMethod: ServerQueryServerMethod?
            when (serverQuery.getType().id) {
                ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID -> {
                    serverMethod = OwnedDeviceDiscoveryServerMethod(serverQuery.getOwnedIdentity()!!)
                }

                ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID -> {
                    val registerApiKeyQuery = serverQuery.getType() as RegisterApiKeyQuery
                    serverMethod = RegisterApiKeyServerMethod(
                        serverQuery.getOwnedIdentity()!!,
                        registerApiKeyQuery.serverSessionToken,
                        registerApiKeyQuery.apiKeyString
                    )
                }

                ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID -> {
                    val backupsV2CreateBackupQuery =
                        serverQuery.getType() as BackupsV2CreateBackupQuery
                    serverMethod = BackupsV2CreateBackupServerMethod(
                        backupsV2CreateBackupQuery.server,
                        backupsV2CreateBackupQuery.backupUid!!,
                        backupsV2CreateBackupQuery.serverAuthenticationPublicKey!!
                    )
                }

                ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID -> {
                    val backupsV2UploadBackupQuery =
                        serverQuery.getType() as BackupsV2UploadBackupQuery
                    serverMethod = BackupsV2UploadBackupsServerMethod(
                        backupsV2UploadBackupQuery.server,
                        backupsV2UploadBackupQuery.backupUid!!,
                        backupsV2UploadBackupQuery.threadId!!,
                        backupsV2UploadBackupQuery.version,
                        backupsV2UploadBackupQuery.encryptedBackup!!,
                        backupsV2UploadBackupQuery.signature!!
                    )
                }

                ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID -> {
                    val backupsV2DeleteBackupQuery =
                        serverQuery.getType() as BackupsV2DeleteBackupQuery
                    serverMethod = BackupsV2DeleteBackupServerMethod(
                        backupsV2DeleteBackupQuery.server,
                        backupsV2DeleteBackupQuery.backupUid!!,
                        backupsV2DeleteBackupQuery.threadId!!,
                        backupsV2DeleteBackupQuery.version,
                        backupsV2DeleteBackupQuery.signature!!
                    )
                }

                ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID -> {
                    val backupsV2ListBackupsQuery =
                        serverQuery.getType() as BackupsV2ListBackupsQuery
                    serverMethod = BackupsV2ListBackupsServerMethod(
                        backupsV2ListBackupsQuery.server,
                        backupsV2ListBackupsQuery.backupUid!!
                    )
                }

                ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID -> {
                    val backupsV2DownloadProfilePictureQuery =
                        serverQuery.getType() as BackupsV2DownloadProfilePictureQuery
                    serverMethod = BackupsV2DownloadProfilePictureServerMethod(
                        backupsV2DownloadProfilePictureQuery.identity,
                        backupsV2DownloadProfilePictureQuery.photoLabel!!,
                        backupsV2DownloadProfilePictureQuery.photoKey
                    )
                }

                ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE -> {
                    val keycloakIdBasedAuthRequestChallengeQuery =
                        serverQuery.getType() as KeycloakIdBasedAuthRequestChallengeQuery
                    serverMethod = KeycloakIdBasedAuthRequestChallengeServerMethod(
                        keycloakIdBasedAuthRequestChallengeQuery.keycloakServerUrl,
                        keycloakIdBasedAuthRequestChallengeQuery.keycloakUserId!!,
                        keycloakIdBasedAuthRequestChallengeQuery.nonce!!
                    )
                }

                ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION -> {
                    val keycloakIdBasedAuthGetSessionQuery =
                        serverQuery.getType() as KeycloakIdBasedAuthGetSessionQuery
                    serverMethod = KeycloakIdBasedAuthGetSessionServerMethod(
                        keycloakIdBasedAuthGetSessionQuery.keycloakServerUrl,
                        keycloakIdBasedAuthGetSessionQuery.challengeResponse!!,
                        keycloakIdBasedAuthGetSessionQuery.nonce!!
                    )
                }

                ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID, ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID, ServerQuery.TypeId.GET_USER_DATA_QUERY_ID, ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID, ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID, ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID, ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID, ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID, ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID, ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID, ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID, ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID -> {
                    cancel(RFC_UNSUPPORTED_SERVER_QUERY_TYPE)
                    return
                }

                else -> {
                    cancel(RFC_UNSUPPORTED_SERVER_QUERY_TYPE)
                    return
                }
            }

            serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)
            val returnStatus = serverMethod.execute(true)
            Logger.d("?? Server query return status (after parse): " + returnStatus)

            when (returnStatus) {
                ServerMethod.OK -> {
                    serverResponse = serverMethod.serverResponse
                    finished = true
                    return
                }

                ServerMethod.INVALID_SESSION -> {
                    cancel(RFC_INVALID_SERVER_SESSION)
                    return
                }

                ServerMethod.INVALID_API_KEY -> {
                    cancel(RFC_INVALID_API_KEY)
                    return
                }

                ServerMethod.BACKUP_UID_ALREADY_USED -> {
                    cancel(RFC_BACKUP_UID_ALREADY_USED)
                    return
                }

                ServerMethod.BACKUP_VERSION_TOO_SMALL -> {
                    cancel(RFC_BACKUP_VERSION_TOO_SMALL)
                    return
                }

                ServerMethod.UNKNOWN_BACKUP_UID -> {
                    cancel(RFC_UNKNOWN_BACKUP_UID)
                    return
                }

                ServerMethod.UNKNOWN_BACKUP_THREAD_ID -> {
                    cancel(RFC_UNKNOWN_BACKUP_THREAD_ID)
                    return
                }

                ServerMethod.UNKNOWN_BACKUP_VERSION -> {
                    cancel(RFC_UNKNOWN_BACKUP_VERSION)
                    return
                }

                ServerMethod.PARSING_ERROR -> {
                    cancel(RFC_SERVER_PARSING_ERROR)
                    return
                }

                ServerMethod.PERMISSION_DENIED -> {
                    cancel(RFC_PERMISSION_DENIED)
                    return
                }

                else -> {
                    cancel(RFC_NETWORK_ERROR)
                    return
                }
            }
        } catch (e: Exception) {
            Logger.x(e)
        } finally {
            if (finished) {
                setFinished()
            } else {
                if (hasNoReasonForCancel()) {
                    cancel(null)
                }
                processCancel()
            }
        }
    }

    override fun doCancel() {
        // nothing to do here
    }

    companion object {
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_UNSUPPORTED_SERVER_QUERY_TYPE: Int = 2
        const val RFC_INVALID_SERVER_SESSION: Int = 3
        const val RFC_INVALID_API_KEY: Int = 4

        const val RFC_BACKUP_UID_ALREADY_USED: Int = 5
        const val RFC_BACKUP_VERSION_TOO_SMALL: Int = 6
        const val RFC_UNKNOWN_BACKUP_UID: Int = 7
        const val RFC_UNKNOWN_BACKUP_THREAD_ID: Int = 8
        const val RFC_UNKNOWN_BACKUP_VERSION: Int = 9

        const val RFC_PERMISSION_DENIED: Int = 10

        const val RFC_SERVER_PARSING_ERROR: Int = 100
    }
}
