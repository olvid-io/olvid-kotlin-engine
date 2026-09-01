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
package io.olvid.engine.engine

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.OwnedIdentitySynchronizationStatus
import io.olvid.engine.datatypes.containers.ReceivedAttachment
import io.olvid.engine.datatypes.notifications.DownloadNotifications
import io.olvid.engine.datatypes.notifications.DownloadNotifications.TurnCredentialsFailedReason
import io.olvid.engine.engine.types.EngineAPI
import io.olvid.engine.engine.types.EngineAPI.ApiKeyPermission
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.engine.types.ObvAttachment
import io.olvid.engine.engine.types.ObvMessage
import io.olvid.engine.engine.types.ObvTurnCredentialsFailedReason
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.notification.NotificationManager
import java.util.UUID

class NotificationListenerDownloads(private val engine: Engine) : NotificationListener {
    private var latestNetworkRestart = System.currentTimeMillis()

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED,
            DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED,
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED,
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED,
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS,
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED,
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_EXISTS,
            DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED,
//             DownloadNotifications.NOTIFICATION_API_KEY_REJECTED_BY_SERVER,
            DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED,
            DownloadNotifications.NOTIFICATION_SERVER_POLLED,
            DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED,
            DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED,
            DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED,
            DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS,
            DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED,
            DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS,
            DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_FAILED,
            DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS,
            DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED,
            DownloadNotifications.NOTIFICATION_VERIFY_RECEIPT_SUCCESS,
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED,
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS,
            DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED,
            DownloadNotifications.NOTIFICATION_PING_LOST,
            DownloadNotifications.NOTIFICATION_PING_RECEIVED,
            DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED,
            DownloadNotifications.NOTIFICATION_WEBSOCKET_DETECTED_SOME_NETWORK,
            DownloadNotifications.NOTIFICATION_PUSH_TOPIC_NOTIFIED,
            DownloadNotifications.NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED,
            DownloadNotifications.NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE,
            DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED -> {
                val decryptedMessage =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED_MESSAGE_KEY) as? DecryptedApplicationMessage?
                val receivedAttachments =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_MESSAGE_DECRYPTED_ATTACHMENTS_KEY) as? Array<ReceivedAttachment?>?
                if (decryptedMessage == null || receivedAttachments == null) {
                    return
                }

                @Suppress("UNCHECKED_CAST")
                val message = ObvMessage(decryptedMessage, receivedAttachments as Array<ReceivedAttachment>)

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_MESSAGE_RECEIVED_MESSAGE_KEY] = message

                engine.postEngineNotification(EngineNotifications.NEW_MESSAGE_RECEIVED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_UID_KEY) as? UID?
                val extendedPayload =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY) as? ByteArray?
                if (ownedIdentity == null || messageUid == null || extendedPayload == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_IDENTIFIER_KEY] =
                    messageUid.bytes
                engineInfo[EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY] =
                    extendedPayload
                engine.postEngineNotification(
                    EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED -> {}
            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_IDENTIFIER_KEY] = messageUid.bytes
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY] = attachmentNumber

                engine.postEngineNotification(
                    EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_ATTACHMENT_NUMBER_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null) {
                    return
                }

                val attachment: ObvAttachment = ObvAttachment.create(
                    engine.fetchManager,
                    ownedIdentity,
                    messageUid,
                    attachmentNumber
                ) ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOADED_ATTACHMENT_KEY] = attachment

                engine.postEngineNotification(EngineNotifications.ATTACHMENT_DOWNLOADED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY) as? Int?
                val progress =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY) as? Float?
                val speed =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY) as? Float?
                val eta =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null || progress == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY] = messageUid.bytes
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] = attachmentNumber
                engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY] = progress
                if (speed != null && eta != null) {
                    engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY] = speed
                    engineInfo[EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY] = eta
                }

                engine.postEngineNotification(
                    EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_SERVER_SESSION_EXISTS, DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY) as? Identity?
                val apiKeyStatus =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_STATUS_KEY) as? ServerSession.ApiKeyStatus?
                val permissions =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_PERMISSIONS_KEY) as? MutableList<ServerSession.Permission>?
                val apiKeyExpirationTimestamp =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_EXPIRATION_TIMESTAMP_KEY) as? Long?
                if (ownedIdentity == null || apiKeyStatus == null || permissions == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.API_KEY_ACCEPTED_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                when (apiKeyStatus) {
                    ServerSession.ApiKeyStatus.VALID -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.VALID

                    ServerSession.ApiKeyStatus.UNKNOWN -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.UNKNOWN

                    ServerSession.ApiKeyStatus.LICENSES_EXHAUSTED -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.LICENSES_EXHAUSTED

                    ServerSession.ApiKeyStatus.EXPIRED -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.EXPIRED

                    ServerSession.ApiKeyStatus.OPEN_BETA_KEY -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.OPEN_BETA_KEY

                    ServerSession.ApiKeyStatus.FREE_TRIAL_KEY -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.FREE_TRIAL_KEY

                    ServerSession.ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD

                    ServerSession.ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD

                    ServerSession.ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED -> engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED
                }
                val enginePermissions: MutableList<ApiKeyPermission?> = ArrayList()
                for (permission in permissions) {
                    when (permission) {
                        ServerSession.Permission.CALL -> enginePermissions.add(ApiKeyPermission.CALL)
                        ServerSession.Permission.WEB_CLIENT -> enginePermissions.add(
                            ApiKeyPermission.WEB_CLIENT
                        )

                        ServerSession.Permission.MULTI_DEVICE -> enginePermissions.add(
                            ApiKeyPermission.MULTI_DEVICE
                        )
                    }
                }
                engineInfo[EngineNotifications.API_KEY_ACCEPTED_PERMISSIONS_KEY] = enginePermissions
                if (apiKeyExpirationTimestamp != null && apiKeyExpirationTimestamp != 0L) {
                    engineInfo[EngineNotifications.API_KEY_ACCEPTED_API_KEY_EXPIRATION_TIMESTAMP_KEY] = apiKeyExpirationTimestamp
                }
                engine.postEngineNotification(EngineNotifications.API_KEY_ACCEPTED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_OWNED_IDENTITY_KEY) as? Identity?
                val userInitiated =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_POLL_REQUESTED_USER_INITIATED_KEY) as? Boolean?
                if (ownedIdentity == null || userInitiated == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.SERVER_POLL_REQUESTED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.SERVER_POLL_REQUESTED_USER_INITIATED_KEY] = userInitiated
                engine.postEngineNotification(EngineNotifications.SERVER_POLL_REQUESTED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_SERVER_POLLED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_POLLED_OWNED_IDENTITY_KEY) as? Identity?
                val success =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_POLLED_SUCCESS_KEY) as? Boolean?
                val truncated =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_SERVER_POLLED_TRUNCATED_KEY) as? Boolean?
                if (ownedIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.SERVER_POLLED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.SERVER_POLLED_SUCCESS_KEY] = success
                engineInfo[EngineNotifications.SERVER_POLLED_TRUNCATED_KEY] = truncated
                engine.postEngineNotification(EngineNotifications.SERVER_POLLED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_OWNED_IDENTITY_KEY) as? Identity?
                val serverUid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY) as? ByteArray?
                val nonce =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_NONCE_KEY) as? ByteArray?
                val encryptedPayload =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY) as? ByteArray?
                val timestamp =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY) as? Long?
                if (ownedIdentity == null || serverUid == null || nonce == null || encryptedPayload == null || timestamp == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.RETURN_RECEIPT_RECEIVED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY] = serverUid
                engineInfo[EngineNotifications.RETURN_RECEIPT_RECEIVED_NONCE_KEY] = nonce
                engineInfo[EngineNotifications.RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY] = encryptedPayload
                engineInfo[EngineNotifications.RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY] = timestamp
                engine.postEngineNotification(
                    EngineNotifications.RETURN_RECEIPT_RECEIVED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY) as? Identity?
                val callUuid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY) as? UUID?
                val username1 =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY) as? String?
                val password1 =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY) as? String?
                val username2 =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY) as? String?
                val password2 =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY) as? String?
                val turnServers =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_SERVERS_KEY) as? MutableList<String?>?
                val altTurnServers =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY) as? MutableList<String?>?
                if (ownedIdentity == null || callUuid == null) {
                    return
                }


                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY] = callUuid
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY] = username1
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY] = password1
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY] = username2
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY] = password2
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_SERVERS_KEY] = turnServers
                engineInfo[EngineNotifications.TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY] = altTurnServers
                engine.postEngineNotification(
                    EngineNotifications.TURN_CREDENTIALS_RECEIVED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                val callUuid =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_CALL_UUID_KEY) as? UUID?
                val rfc =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_TURN_CREDENTIALS_FAILED_REASON_KEY) as? TurnCredentialsFailedReason?
                if (ownedIdentity == null || callUuid == null || rfc == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_CALL_UUID_KEY] = callUuid
                when (rfc) {
                    TurnCredentialsFailedReason.PERMISSION_DENIED -> engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_REASON_KEY] =
                        ObvTurnCredentialsFailedReason.PERMISSION_DENIED

                    TurnCredentialsFailedReason.BAD_SERVER_SESSION -> engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_REASON_KEY] =
                        ObvTurnCredentialsFailedReason.BAD_SERVER_SESSION

                    TurnCredentialsFailedReason.UNABLE_TO_CONTACT_SERVER -> engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_REASON_KEY] =
                        ObvTurnCredentialsFailedReason.UNABLE_TO_CONTACT_SERVER

                    TurnCredentialsFailedReason.CALLS_NOT_SUPPORTED_ON_SERVER -> engineInfo[EngineNotifications.TURN_CREDENTIALS_FAILED_REASON_KEY] =
                        ObvTurnCredentialsFailedReason.CALLS_NOT_SUPPORTED_ON_SERVER
                }
                engine.postEngineNotification(
                    EngineNotifications.TURN_CREDENTIALS_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_OWNED_IDENTITY_KEY) as? Identity?
                val apiKey =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY) as? UUID?
                val apiKeyStatus =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY) as? ServerSession.ApiKeyStatus?
                val permissions =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY) as? MutableList<ServerSession.Permission>?
                val apiKeyExpirationTimestamp =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY) as? Long?
                if (ownedIdentity == null || apiKey == null || apiKeyStatus == null || permissions == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY] = apiKey
                when (apiKeyStatus) {
                    ServerSession.ApiKeyStatus.VALID -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.VALID

                    ServerSession.ApiKeyStatus.UNKNOWN -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.UNKNOWN

                    ServerSession.ApiKeyStatus.LICENSES_EXHAUSTED -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.LICENSES_EXHAUSTED

                    ServerSession.ApiKeyStatus.EXPIRED -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.EXPIRED

                    ServerSession.ApiKeyStatus.OPEN_BETA_KEY -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.OPEN_BETA_KEY

                    ServerSession.ApiKeyStatus.FREE_TRIAL_KEY -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.FREE_TRIAL_KEY

                    ServerSession.ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.AWAITING_PAYMENT_GRACE_PERIOD

                    ServerSession.ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.AWAITING_PAYMENT_ON_HOLD

                    ServerSession.ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED -> engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY] =
                        EngineAPI.ApiKeyStatus.FREE_TRIAL_KEY_EXPIRED
                }
                val enginePermissions: MutableList<ApiKeyPermission?> =
                    ArrayList()
                for (permission in permissions) {
                    when (permission) {
                        ServerSession.Permission.CALL -> enginePermissions.add(ApiKeyPermission.CALL)
                        ServerSession.Permission.WEB_CLIENT -> enginePermissions.add(
                            ApiKeyPermission.WEB_CLIENT
                        )

                        ServerSession.Permission.MULTI_DEVICE -> enginePermissions.add(
                            ApiKeyPermission.MULTI_DEVICE
                        )
                    }
                }
                engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY] = enginePermissions
                if (apiKeyExpirationTimestamp != null && apiKeyExpirationTimestamp != 0L) {
                    engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY] = apiKeyExpirationTimestamp
                }
                engine.postEngineNotification(
                    EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                val apiKey =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY) as? UUID?
                if (ownedIdentity == null || apiKey == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY] = apiKey
                engine.postEngineNotification(
                    EngineNotifications.API_KEY_STATUS_QUERY_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_OWNED_IDENTITY_KEY) as? Identity?
                val available =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY) as? Boolean?
                if (ownedIdentity == null || available == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.FREE_TRIAL_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY] = available
                engine.postEngineNotification(
                    EngineNotifications.FREE_TRIAL_QUERY_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_FREE_TRIAL_QUERY_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.FREE_TRIAL_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engine.postEngineNotification(
                    EngineNotifications.FREE_TRIAL_QUERY_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.FREE_TRIAL_RETRIEVE_SUCCESS_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engine.postEngineNotification(
                    EngineNotifications.FREE_TRIAL_RETRIEVE_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.FREE_TRIAL_RETRIEVE_FAILED_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engine.postEngineNotification(
                    EngineNotifications.FREE_TRIAL_RETRIEVE_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_VERIFY_RECEIPT_SUCCESS -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_VERIFY_RECEIPT_SUCCESS_OWNED_IDENTITY_KEY) as? Identity?
                val storeToken =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_VERIFY_RECEIPT_SUCCESS_STORE_TOKEN_KEY) as? String?
                if (ownedIdentity == null || storeToken == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.VERIFY_RECEIPT_SUCCESS_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()
                engineInfo[EngineNotifications.VERIFY_RECEIPT_SUCCESS_STORE_TOKEN_KEY] = storeToken
                engine.postEngineNotification(
                    EngineNotifications.VERIFY_RECEIPT_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED -> {
                val server =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED_SERVER_KEY) as? String?
                val appInfo =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WELL_KNOWN_UPDATED_APP_INFO_KEY) as? MutableMap<String?, Int?>?
                if (server == null || appInfo == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY] = server
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY] = appInfo
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_UPDATED_KEY] = true
                engine.postEngineNotification(
                    EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS -> {
                val server =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY) as? String?
                val appInfo =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY) as? MutableMap<String?, Int?>?
                if (server == null || appInfo == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY] = server
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY] = appInfo
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_UPDATED_KEY] = false
                engine.postEngineNotification(
                    EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED -> {
                val server =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY) as? String?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY] = server
                engine.postEngineNotification(
                    EngineNotifications.WELL_KNOWN_DOWNLOAD_FAILED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_PING_LOST -> {
                val engineInfo = HashMap<String, Any?>()
                engine.postEngineNotification(EngineNotifications.PING_LOST, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_PING_RECEIVED -> {
                val delay =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_PING_RECEIVED_DELAY_KEY) as? Long?
                        ?: return
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PING_RECEIVED_DELAY_KEY] = delay

                engine.postEngineNotification(EngineNotifications.PING_RECEIVED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED -> {
                val state =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY) as? Int?
                        ?: return
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY] = state

                engine.postEngineNotification(
                    EngineNotifications.WEBSOCKET_CONNECTION_STATE_CHANGED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_WEBSOCKET_DETECTED_SOME_NETWORK -> {
                // this notification is only sent if websocket are monitoring network state. In case network is detected --> reschedule all network tasks
                if (latestNetworkRestart + 5000 < System.currentTimeMillis()) {
                    latestNetworkRestart = System.currentTimeMillis()
                    Logger.i("Network detected (WebSocket connected), retrying all scheduled network jobs")
                    engine.retryScheduledNetworkTasks()
                }
                engine.postEngineNotification(
                    EngineNotifications.WEBSOCKET_DETECTED_SOME_NETWORK,
                    HashMap()
                )
            }

            DownloadNotifications.NOTIFICATION_PUSH_TOPIC_NOTIFIED -> {
                val topic =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_PUSH_TOPIC_NOTIFIED_TOPIC_KEY) as? String?
                        ?: return
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PUSH_TOPIC_NOTIFIED_TOPIC_KEY] = topic

                engine.postEngineNotification(EngineNotifications.PUSH_TOPIC_NOTIFIED, engineInfo)
            }

            DownloadNotifications.NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.KEYCLOAK_UPDATE_REQUIRED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.KEYCLOAK_UPDATE_REQUIRED,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_BYTES_OWNED_IDENTITY_KEY] = ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE,
                    engineInfo
                )
            }

            DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER -> {
                val ownedIdentity =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_OWNED_IDENTITY_KEY) as? Identity?
                val status =
                    userInfo?.get(DownloadNotifications.NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY) as? OwnedIdentitySynchronizationStatus?
                if (ownedIdentity == null || status == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY] = status

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER,
                    engineInfo
                )
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
