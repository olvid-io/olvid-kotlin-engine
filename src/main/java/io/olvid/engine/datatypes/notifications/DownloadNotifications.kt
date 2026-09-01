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

package io.olvid.engine.datatypes.notifications


object DownloadNotifications {
    const val NOTIFICATION_MESSAGE_DECRYPTED = "network_fetch_notification_message_payload_set"
    const val NOTIFICATION_MESSAGE_DECRYPTED_MESSAGE_KEY = "message" // DecryptedApplicationMessage
    const val NOTIFICATION_MESSAGE_DECRYPTED_ATTACHMENTS_KEY = "attachments" // ReceivedAttachment[]

    const val NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED = "network_fetch_notification_message_extended_payload_downloaded"
    const val NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_UID_KEY = "message_uid" // UID
    const val NOTIFICATION_MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY = "extended_payload" // byte[]

    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS = "network_fetch_notification_attachment_download_progress"
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_UID_KEY = "messageUid" // UID
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY = "attachmentNumber" // int
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY = "progress" // float
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY = "speed" // float
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY = "eta" // int

    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED = "network_fetch_notification_attachment_download_finished"
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_MESSAGE_UID_KEY = "messageUid" // UID
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FINISHED_ATTACHMENT_NUMBER_KEY = "attachmentNumber"

    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED = "network_fetch_notification_attachment_download_was_paused"
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_MESSAGE_UID_KEY = "messageUid" // UID
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_WAS_PAUSED_ATTACHMENT_NUMBER = "attachmentNumber"

    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED = "network_fetch_notification_attachment_download_failed"
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_UID_KEY = "messageUid" // UID
    const val NOTIFICATION_ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY = "attachmentNumber"

    const val NOTIFICATION_SERVER_SESSION_EXISTS = "network_fetch_notification_server_session_exists" // used instead of created during initial queueing to refresh api key status in app
    const val NOTIFICATION_SERVER_SESSION_CREATED = "network_fetch_notification_server_session_created"
    const val NOTIFICATION_SERVER_SESSION_CREATED_IDENTITY_KEY = "identity"
    const val NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_STATUS_KEY = "api_key_status" // ServerSession.ApiKeyStatus
    const val NOTIFICATION_SERVER_SESSION_CREATED_PERMISSIONS_KEY = "permissions" // List<ServerSession.Permission>
    const val NOTIFICATION_SERVER_SESSION_CREATED_API_KEY_EXPIRATION_TIMESTAMP_KEY = "api_key_expiration_timestamp" // long -> 0 means no expiration


    const val NOTIFICATION_SERVER_POLL_REQUESTED = "network_fetch_notification_server_poll_requested"
    const val NOTIFICATION_SERVER_POLL_REQUESTED_OWNED_IDENTITY_KEY = "owned_identity"
    const val NOTIFICATION_SERVER_POLL_REQUESTED_USER_INITIATED_KEY = "user_initiated"

    const val NOTIFICATION_SERVER_POLLED = "network_fetch_notification_server_polled"
    const val NOTIFICATION_SERVER_POLLED_OWNED_IDENTITY_KEY = "owned_identity"
    const val NOTIFICATION_SERVER_POLLED_SUCCESS_KEY = "success"
    const val NOTIFICATION_SERVER_POLLED_TRUNCATED_KEY = "truncated"

    const val NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED = "network_fetch_notification_signed_url_refreshed"
    const val NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_MESSAGE_UID_KEY = "message_uid"
    const val NOTIFICATION_INBOX_ATTACHMENT_SIGNED_URL_REFRESHED_ATTACHMENT_NUMBER_KEY = "attachment_number"

    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED = "network_fetch_notification_return_receipt_received"
    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED_OWNED_IDENTITY_KEY = "bytes_owned_identity" // Identity
    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY = "server_uid" // byte[]
    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED_NONCE_KEY = "nonce" // byte[]
    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY = "encrypted_payload" // byte[]
    const val NOTIFICATION_RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY = "timestamp" // long

    const val NOTIFICATION_PUSH_NOTIFICATION_REGISTERED = "network_fetch_notification_push_notification_registered"
    const val NOTIFICATION_PUSH_NOTIFICATION_REGISTERED_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED = "network_fetch_notification_turn_credentials_recieved"
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY = "call_uuid" // Uuid
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY = "username1" // String
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY = "username2" // String
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY = "password1" // String
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY = "password2" // String
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_SERVERS_KEY = "turn_servers" // List<String>
    const val NOTIFICATION_TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY = "alt_servers" // List<String>

    const val NOTIFICATION_TURN_CREDENTIALS_FAILED = "network_fetch_notification_turn_credentials_failed"
    const val NOTIFICATION_TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_TURN_CREDENTIALS_FAILED_CALL_UUID_KEY = "call_uuid" // UUID
    const val NOTIFICATION_TURN_CREDENTIALS_FAILED_REASON_KEY = "reason" // TurnCredentialsFailedReason

    const val NOTIFICATION_PING_LOST = "network_fetch_notification_ping_lost"
    const val NOTIFICATION_PING_RECEIVED = "network_fetch_notification_ping_received"
    const val NOTIFICATION_PING_RECEIVED_DELAY_KEY = "delay" // long

    const val NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED = "network_fetch_notification_websocket_connection_state_changed"
    const val NOTIFICATION_WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY = "state" // int

    const val NOTIFICATION_WEBSOCKET_DETECTED_SOME_NETWORK = "network_fetch_notification_websocket_detected_some_network"

    enum class TurnCredentialsFailedReason {
        PERMISSION_DENIED,
        BAD_SERVER_SESSION,
        CALLS_NOT_SUPPORTED_ON_SERVER,
        UNABLE_TO_CONTACT_SERVER
    }

    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS = "network_fetch_notification_api_key_status_query_success"
    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY = "api_key" // UUID
    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY = "api_key_status" // ServerSession.ApiKeyStatus
    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY = "permissions" // List<ServerSession.Permission>
    const val NOTIFICATION_API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY = "api_key_expiration_timestamp" // long

    const val NOTIFICATION_API_KEY_STATUS_QUERY_FAILED = "network_fetch_notification_api_key_status_query_failed"
    const val NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY = "api_key" // UUID

    const val NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS = "network_fetch_notification_free_trial_query_success"
    const val NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY = "available" // boolean

    const val NOTIFICATION_FREE_TRIAL_QUERY_FAILED = "network_fetch_notification_free_trial_query_failed"
    const val NOTIFICATION_FREE_TRIAL_QUERY_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS = "network_fetch_notification_free_trial_retrieve_success"
    const val NOTIFICATION_FREE_TRIAL_RETRIEVE_SUCCESS_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED = "network_fetch_notification_free_trial_retrieve_failed"
    const val NOTIFICATION_FREE_TRIAL_RETRIEVE_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_VERIFY_RECEIPT_SUCCESS = "network_fetch_notification_verify_receipt_success"
    const val NOTIFICATION_VERIFY_RECEIPT_SUCCESS_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_VERIFY_RECEIPT_SUCCESS_STORE_TOKEN_KEY = "store_token" // String

    const val NOTIFICATION_WELL_KNOWN_CACHE_INITIALIZED = "network_fetch_notification_well_known_cache_initialized"

    const val NOTIFICATION_WELL_KNOWN_UPDATED = "network_fetch_notification_well_known_updated"
    const val NOTIFICATION_WELL_KNOWN_UPDATED_SERVER_KEY = "server" // String
    const val NOTIFICATION_WELL_KNOWN_UPDATED_SERVER_CONFIG_KEY = "server_config" // JsonWellKnownServerConfig
    const val NOTIFICATION_WELL_KNOWN_UPDATED_APP_INFO_KEY = "app_info" // Map<String, Integer>

    const val NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS = "network_fetch_notification_well_known_download_success"
    const val NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY = "server" // String
    const val NOTIFICATION_WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY = "app_info" // Map<String, Integer>

    const val NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED = "network_fetch_notification_well_known_download_failed"
    const val NOTIFICATION_WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY = "server" // String

    const val NOTIFICATION_PUSH_TOPIC_NOTIFIED = "network_fetch_notification_push_topic_notified"
    const val NOTIFICATION_PUSH_TOPIC_NOTIFIED_TOPIC_KEY = "topic" // String

    const val NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED = "network_fetch_notification_keycloak_update_required"
    const val NOTIFICATION_PUSH_KEYCLOAK_UPDATE_REQUIRED_OWNED_IDENTITY_KEY = "identity" // Identity

    const val NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE = "network_fetch_notification_push_register_failed_bad_device_uid_to_replace"
    const val NOTIFICATION_PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER = "network_fetch_notification_owned_identity_synchronizing_with_server"
    const val NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY = "status" // OwnedIdentitySynchronizationStatus
}
