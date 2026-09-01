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
package io.olvid.engine.engine.types

object EngineNotifications {
    const val UI_DIALOG_DELETED: String = "engine_notification_ui_dialog_deleted"
    const val UI_DIALOG_DELETED_UUID_KEY: String = "uuid" // UUID

    const val UI_DIALOG: String = "engine_notification_ui_dialog"
    const val UI_DIALOG_UUID_KEY: String = "uuid" // UUID
    const val UI_DIALOG_DIALOG_KEY: String = "dialog" // ObvDialog
    const val UI_DIALOG_CREATION_TIMESTAMP_KEY: String = "creation_timestamp" // long

    const val SERVER_POLL_REQUESTED: String = "engine_notification_server_poll_requested"
    const val SERVER_POLL_REQUESTED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val SERVER_POLL_REQUESTED_USER_INITIATED_KEY: String = "user_initiated" // boolean

    const val SERVER_POLLED: String = "engine_notification_server_polled"
    const val SERVER_POLLED_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val SERVER_POLLED_SUCCESS_KEY: String = "success" // boolean
    const val SERVER_POLLED_TRUNCATED_KEY: String =
        "truncated" // boolean --> if success == true, this indicates whether there are still some messages to list on the server

    const val NEW_MESSAGE_RECEIVED: String = "engine_notification_new_message_received"
    const val NEW_MESSAGE_RECEIVED_MESSAGE_KEY: String = "message" // ObvMessage

    const val MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED: String =
        "engine_notification_message_extended_payload_downloaded"
    const val MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[]
    const val MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY: String =
        "extended_payload" // byte[]

    const val ATTACHMENT_DOWNLOAD_PROGRESS: String =
        "engine_notification_download_attachment_progress"
    const val ATTACHMENT_DOWNLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[]
    const val ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY: String =
        "attachment_number" // int
    const val ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY: String = "progress" // float
    const val ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY: String = "speed" // float
    const val ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY: String = "eta" // int

    const val ATTACHMENT_DOWNLOADED: String = "engine_notification_attachment_downloaded"
    const val ATTACHMENT_DOWNLOADED_ATTACHMENT_KEY: String = "attachment" // ObvAttachment

    const val ATTACHMENT_UPLOAD_PROGRESS: String = "engine_notification_upload_attachment_progress"
    const val ATTACHMENT_UPLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[]
    const val ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY: String = "attachment_number" // int
    const val ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY: String = "progress" // float
    const val ATTACHMENT_UPLOAD_PROGRESS_SPEED_BPS_KEY: String = "speed" // float
    const val ATTACHMENT_UPLOAD_PROGRESS_ETA_SECONDS_KEY: String = "eta" // int

    const val ATTACHMENT_UPLOADED: String = "engine_notification_attachment_uploaded"
    const val ATTACHMENT_UPLOADED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val ATTACHMENT_UPLOADED_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[] (message UID)
    const val ATTACHMENT_UPLOADED_ATTACHMENT_NUMBER_KEY: String = "attachment_number" // int

    const val ATTACHMENT_UPLOAD_CANCELLED: String =
        "engine_notification_attachment_upload_cancelled"
    const val ATTACHMENT_UPLOAD_CANCELLED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val ATTACHMENT_UPLOAD_CANCELLED_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[] (message UID)
    const val ATTACHMENT_UPLOAD_CANCELLED_ATTACHMENT_NUMBER_KEY: String = "attachment_number" // int

    const val ATTACHMENT_DOWNLOAD_FAILED: String = "engine_notification_attachment_failed"
    const val ATTACHMENT_DOWNLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_IDENTIFIER_KEY: String =
        "message_identifier" // byte[] (message UID)
    const val ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY: String = "attachment_number" // int

    const val MESSAGE_UPLOADED: String = "engine_notification_message_uploaded"
    const val MESSAGE_UPLOADED_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val MESSAGE_UPLOADED_IDENTIFIER_KEY: String = "identifier" // byte[] (message UID)
    const val MESSAGE_UPLOADED_TIMESTAMP_FROM_SERVER: String = "timestamp_from_server"

    const val MESSAGE_UPLOAD_FAILED: String = "engine_notification_message_upload_failed"
    const val MESSAGE_UPLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val MESSAGE_UPLOAD_FAILED_IDENTIFIER_KEY: String = "identifier" // byte[] (message UID)

    const val NEW_CONTACT: String = "engine_notification_new_contact"
    const val NEW_CONTACT_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val NEW_CONTACT_CONTACT_IDENTITY_KEY: String = "contact_identity" // ObvIdentity
    const val NEW_CONTACT_ONE_TO_ONE_KEY: String = "one_to_one" // boolean
    const val NEW_CONTACT_TRUST_LEVEL_KEY: String = "trust_level" // int
    const val NEW_CONTACT_HAS_UNTRUSTED_PUBLISHED_DETAILS_KEY: String =
        "has_untrusted_published_details" // boolean

    const val CONTACT_DELETED: String = "engine_notification_contact_deleted"
    const val CONTACT_DELETED_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val CONTACT_DELETED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]

    const val CONTACT_DEVICES_UPDATED: String = "engine_notification_contact_devices_updated"
    const val CONTACT_DEVICES_UPDATED_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val CONTACT_DEVICES_UPDATED_CONTACT_IDENTITY_KEY: String = "contact_identity" // byte[]

    const val CHANNEL_CONFIRMED_OR_DELETED: String =
        "engine_notification_channel_confirmed_or_deleted"
    const val CHANNEL_CONFIRMED_OR_DELETED_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val CHANNEL_CONFIRMED_OR_DELETED_CONTACT_IDENTITY_KEY: String =
        "contact_identity" // byte[]
    const val CHANNEL_CONFIRMED_OR_DELETED_CONTACT_DEVICE_UID_KEY = "contact_device_uid" // byte[] only set for channel creations

    const val GROUP_CREATED: String = "engine_notification_group_created"
    const val GROUP_CREATED_GROUP_KEY: String = "group" // ObvGroup
    const val GROUP_CREATED_HAS_MULTIPLE_DETAILS_KEY: String = "has_multiple_details" // boolean
    const val GROUP_CREATED_PHOTO_URL_KEY: String = "photo_url" // String
    const val GROUP_CREATED_ON_OTHER_DEVICE_KEY: String =
        "on_other_device" // boolean --> true if I am the group owner and the group was created on another device


    const val GROUP_DELETED: String = "engine_notification_group_deleted"
    const val GROUP_DELETED_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val GROUP_DELETED_BYTES_GROUP_OWNER_AND_UID_KEY: String =
        "bytes_group_owner_and_uid" // byte[]


    const val GROUP_MEMBER_ADDED: String = "engine_notification_group_member_added"
    const val GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY: String = "group_uid" // byte[]
    const val GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val GROUP_MEMBER_ADDED_BYTES_CONTACT_IDENTITY_KEY: String = "contact_identity" // byte[]

    const val GROUP_MEMBER_REMOVED: String = "engine_notification_group_member_removed"
    const val GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY: String = "bytes_group_uid" // byte[]
    const val GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val GROUP_MEMBER_REMOVED_BYTES_CONTACT_IDENTITY_KEY: String = "contact_identity" // byte[]

    const val PENDING_GROUP_MEMBER_ADDED: String = "engine_notification_pending_group_member_added"
    const val PENDING_GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY: String = "bytes_group_uid" // byte[]
    const val PENDING_GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val PENDING_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY: String =
        "contact_identity" // ObvIdentity

    const val PENDING_GROUP_MEMBER_REMOVED: String =
        "engine_notification_pending_group_member_removed"
    const val PENDING_GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY: String = "bytes_group_uid" // byte[]
    const val PENDING_GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val PENDING_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY: String =
        "contact_identity" // ObvIdentity

    const val API_KEY_ACCEPTED: String = "engine_notification_api_key_accepted"
    const val API_KEY_ACCEPTED_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val API_KEY_ACCEPTED_API_KEY_STATUS_KEY: String =
        "api_key_status" // EngineApi.ApiKeyStatus
    const val API_KEY_ACCEPTED_PERMISSIONS_KEY: String = "permissions" // List<EngineApi.Permission>
    const val API_KEY_ACCEPTED_API_KEY_EXPIRATION_TIMESTAMP_KEY: String =
        "api_key_expiration_timestamp" // long

    const val OWNED_IDENTITY_LIST_UPDATED: String =
        "engine_notification_owned_identity_list_updated"

    const val OWNED_IDENTITY_DETAILS_CHANGED: String =
        "engine_notification_owned_identity_display_name_changed"
    const val OWNED_IDENTITY_DETAILS_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val OWNED_IDENTITY_DETAILS_CHANGED_IDENTITY_DETAILS_KEY: String =
        "display_name" // JsonIdentityDetails
    const val OWNED_IDENTITY_DETAILS_CHANGED_PHOTO_URL_KEY: String = "photo_url" // String

    const val NEW_CONTACT_PUBLISHED_DETAILS: String =
        "engine_notification_new_contact_published_details"
    const val NEW_CONTACT_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val NEW_CONTACT_PUBLISHED_DETAILS_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]

    const val CONTACT_PUBLISHED_DETAILS_TRUSTED: String =
        "engine_notification_contact_published_details_trusted"
    const val CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_PUBLISHED_DETAILS_TRUSTED_IDENTITY_DETAILS_KEY: String =
        "identity_details" // JsonIdentityDetailsWithVersionAndPhoto

    const val CONTACT_KEYCLOAK_MANAGED_CHANGED: String =
        "engine_notification_contact_keycloak_managed_changed"
    const val CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_KEYCLOAK_MANAGED_CHANGED_KEYCLOAK_MANAGED_KEY: String =
        "keycloak_managed" // boolean

    const val CONTACT_ACTIVE_CHANGED: String = "engine_notification_contact_active_changed"
    const val CONTACT_ACTIVE_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_ACTIVE_CHANGED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_ACTIVE_CHANGED_ACTIVE_KEY: String = "active" // boolean

    const val CONTACT_REVOKED: String = "engine_notification_contact_revoked"
    const val CONTACT_REVOKED_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val CONTACT_REVOKED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]

    const val NEW_CONTACT_PHOTO: String = "engine_notification_new_contact_photo"
    const val NEW_CONTACT_PHOTO_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val NEW_CONTACT_PHOTO_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val NEW_CONTACT_PHOTO_VERSION_KEY: String = "version" // int
    const val NEW_CONTACT_PHOTO_IS_TRUSTED_KEY: String = "is_trusted" // boolean

    const val NEW_GROUP_PHOTO: String = "engine_notification_new_group_photo"
    const val NEW_GROUP_PHOTO_BYTES_OWNED_IDENTITY_KEY: String = "bytes_owned_identity" // byte[]
    const val NEW_GROUP_PHOTO_BYTES_GROUP_OWNER_AND_UID_KEY: String = "bytes_group_uid" // byte[]
    const val NEW_GROUP_PHOTO_VERSION_KEY: String = "version" // int
    const val NEW_GROUP_PHOTO_IS_TRUSTED_KEY: String = "is_trusted" // boolean

    const val GROUP_PUBLISHED_DETAILS_UPDATED: String =
        "engine_notification_group_published_details_updated"
    const val GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_GROUP_UID_KEY: String =
        "bytes_group_uid" // byte[]
    const val GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_DETAILS_KEY: String =
        "group_details" // JsonGroupDetailsWithVersionAndPhoto

    const val GROUP_PUBLISHED_DETAILS_TRUSTED: String =
        "engine_notification_group_published_details_trusted"
    const val GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_GROUP_UID_KEY: String =
        "bytes_group_uid" // byte[]
    const val GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_DETAILS_KEY: String =
        "group_details" // JsonGroupDetailsWithVersionAndPhoto

    const val NEW_GROUP_PUBLISHED_DETAILS: String =
        "engine_notification_new_group_published_details"
    const val NEW_GROUP_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val NEW_GROUP_PUBLISHED_DETAILS_BYTES_GROUP_OWNER_AND_UID_KEY: String =
        "bytes_group_uid" // byte[]

    const val PENDING_GROUP_MEMBER_DECLINE_TOGGLED: String =
        "engine_notification_pending_group_member_decline_toggled"
    const val PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_GROUP_UID_KEY: String =
        "bytes_group_uid" // byte[]
    const val PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val PENDING_GROUP_MEMBER_DECLINE_TOGGLED_DECLINED_KEY: String = "declined" // boolean

    const val OWNED_IDENTITY_LATEST_DETAILS_UPDATED: String =
        "engine_notification_owned_identity_latest_details_updated"
    const val OWNED_IDENTITY_LATEST_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val OWNED_IDENTITY_LATEST_DETAILS_UPDATED_HAS_UNPUBLISHED_KEY: String =
        "has_unpublished" // boolean

    const val OWNED_IDENTITY_ACTIVE_STATUS_CHANGED: String =
        "engine_notification_owned_identity_changed_active_status"
    const val OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_ACTIVE_KEY: String = "active" // boolean

    const val RETURN_RECEIPT_RECEIVED: String = "engine_notification_return_receipt_received"
    const val RETURN_RECEIPT_RECEIVED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY: String = "server_uid" // byte[]
    const val RETURN_RECEIPT_RECEIVED_NONCE_KEY: String = "nonce" // byte[]
    const val RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY: String = "encrypted_payload" // byte[]
    const val RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY: String = "timestamp" // long

    const val NEW_BACKUP_SEED_GENERATED: String = "engine_notification_new_backup_seed_generated"
    const val NEW_BACKUP_SEED_GENERATED_SEED_KEY: String = "seed" // String

    const val BACKUP_SEED_GENERATION_FAILED: String =
        "engine_notification_backup_seed_generation_failed"

    const val BACKUP_KEY_VERIFICATION_SUCCESSFUL: String =
        "engine_notification_backup_key_verification_successful"

    const val BACKUP_FOR_EXPORT_FINISHED: String = "engine_notification_backup_for_export_finished"
    const val BACKUP_FOR_EXPORT_FINISHED_BYTES_BACKUP_KEY_UID_KEY: String =
        "backup_key_uid" // byte[]
    const val BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY: String = "version" // int
    const val BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY: String =
        "encrypted_content" // byte[]

    const val BACKUP_FINISHED: String = "engine_notification_backup_finished"
    const val BACKUP_FINISHED_BYTES_BACKUP_KEY_UID_KEY: String = "backup_key_uid" // byte[]
    const val BACKUP_FINISHED_VERSION_KEY: String = "version" // int
    const val BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY: String = "encrypted_content" // byte[]

    const val BACKUP_FOR_EXPORT_FAILED: String = "engine_notification_backup_for_export_failed"

    const val TURN_CREDENTIALS_RECEIVED: String = "engine_notification_turn_credentials_received"
    const val TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY: String = "owned_identity" // Identity
    const val TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY: String = "call_uuid" // Uuid
    const val TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY: String = "username1" // String
    const val TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY: String = "username2" // String
    const val TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY: String = "password1" // String
    const val TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY: String = "password2" // String
    const val TURN_CREDENTIALS_RECEIVED_SERVERS_KEY: String = "servers" // List<String>
    const val TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY: String = "alt_servers" // List<String>

    const val TURN_CREDENTIALS_FAILED: String = "engine_notification_turn_credentials_failed"
    const val TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY: String = "owned_identity" // byte[]
    const val TURN_CREDENTIALS_FAILED_CALL_UUID_KEY: String = "call_uuid" // UUID
    const val TURN_CREDENTIALS_FAILED_REASON_KEY: String =
        "reason" // ObvTurnCredentialsFailedReason

    const val API_KEY_STATUS_QUERY_SUCCESS: String =
        "engine_notification_api_key_status_query_success"
    const val API_KEY_STATUS_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY: String = "api_key" // UUID
    const val API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY: String =
        "api_key_status" // EngineAPI.ApiKeyStatus
    const val API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY: String =
        "permissions" // List<EngineAPI.Permission>
    const val API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY: String =
        "api_key_expiration_timestamp" // long

    const val API_KEY_STATUS_QUERY_FAILED: String =
        "engine_notification_api_key_status_query_failed"
    const val API_KEY_STATUS_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY: String = "api_key" // UUID

    const val FREE_TRIAL_QUERY_SUCCESS: String = "engine_notification_free_trial_query_success"
    const val FREE_TRIAL_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY: String = "available" // boolean

    const val FREE_TRIAL_QUERY_FAILED: String = "engine_notification_free_trial_query_failed"
    const val FREE_TRIAL_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val FREE_TRIAL_RETRIEVE_SUCCESS: String = "engine_notification_retrieve_query_success"
    const val FREE_TRIAL_RETRIEVE_SUCCESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val FREE_TRIAL_RETRIEVE_FAILED: String = "engine_notification_retrieve_query_failed"
    const val FREE_TRIAL_RETRIEVE_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val VERIFY_RECEIPT_SUCCESS: String = "engine_notification_verify_receipt_success"
    const val VERIFY_RECEIPT_SUCCESS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val VERIFY_RECEIPT_SUCCESS_STORE_TOKEN_KEY: String = "store_token" // String

    const val WELL_KNOWN_DOWNLOAD_SUCCESS: String =
        "engine_notification_well_known_download_success"
    const val WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY: String = "server" // String
    const val WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY: String = "app_info" // Map<String, Integer>
    const val WELL_KNOWN_DOWNLOAD_SUCCESS_UPDATED_KEY: String = "updated" // boolean

    const val WELL_KNOWN_DOWNLOAD_FAILED: String = "engine_notification_well_known_download_failed"
    const val WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY: String = "server" // String

    const val MUTUAL_SCAN_CONTACT_ADDED: String = "engine_notification_mutual_scan_contact_added"
    const val MUTUAL_SCAN_CONTACT_ADDED_BYTES_OWNED_IDENTITIY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val MUTUAL_SCAN_CONTACT_ADDED_BYTES_CONTACT_IDENTITIY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY: String = "signature" // byte[]

    const val APP_BACKUP_REQUESTED: String = "engine_notification_app_backup_requested"
    const val APP_BACKUP_REQUESTED_BYTES_BACKUP_KEY_UID_KEY: String =
        "bytes_backup_key_uid" // byte[]
    const val APP_BACKUP_REQUESTED_VERSION_KEY: String = "version" // int

    const val ENGINE_BACKUP_RESTORATION_FINISHED: String =
        "engine_notification_engine_backup_restoration_finished"

    const val ENGINE_SNAPSHOT_RESTORATION_FINISHED: String =
        "engine_notification_engine_snapshot_restoration_finished"

    const val PING_LOST: String = "engine_notification_ping_lost"

    const val PING_RECEIVED: String = "engine_notification_ping_received"
    const val PING_RECEIVED_DELAY_KEY: String = "delay" // long (in milliseconds)

    const val WEBSOCKET_CONNECTION_STATE_CHANGED: String =
        "engine_notification_websocket_connection_state_changed"
    const val WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY: String = "state" // int

    const val WEBSOCKET_DETECTED_SOME_NETWORK: String =
        "engine_notification_websocket_detected_some_network"

    const val CONTACT_CAPABILITIES_UPDATED: String =
        "engine_notification_contact_capabilities_updated" // List<ObvCapabilities>
    const val CONTACT_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_CAPABILITIES_UPDATED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_CAPABILITIES_UPDATED_CAPABILITIES: String =
        "capabilities" // List<ObvCapabilities>

    const val OWN_CAPABILITIES_UPDATED: String =
        "engine_notification_own_capabilities_updated" // List<ObvCapabilities>
    const val OWN_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val OWN_CAPABILITIES_UPDATED_CAPABILITIES: String =
        "capabilities" // List<ObvCapabilities>

    const val CONTACT_ONE_TO_ONE_CHANGED: String = "engine_notification_contact_one_to_one_changed"
    const val CONTACT_ONE_TO_ONE_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_ONE_TO_ONE_CHANGED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY: String = "one_to_one" // boolean

    const val CONTACT_RECENTLY_ONLINE_CHANGED: String =
        "engine_notification_contact_recently_online_changed"
    const val CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_RECENTLY_ONLINE_CHANGED_RECENTLY_ONLINE_KEY: String =
        "recently_online" // boolean

    const val CONTACT_TRUST_LEVEL_INCREASED: String =
        "engine_notification_contact_trust_level_increased"
    const val CONTACT_TRUST_LEVEL_INCREASED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_TRUST_LEVEL_INCREASED_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_TRUST_LEVEL_INCREASED_TRUST_LEVEL_KEY: String = "trust_level" // int

    const val GROUP_V2_CREATED_OR_UPDATED: String =
        "engine_notification_group_v2_created_or_updated"
    const val GROUP_V2_CREATED_OR_UPDATED_GROUP_KEY: String = "group" // ObvGroupV2
    const val GROUP_V2_CREATED_OR_UPDATED_NEW_GROUP_KEY: String =
        "new_group" // boolean --> if true, the group was created by be (as opposed to joined groups created by someone else)
    const val GROUP_V2_CREATED_OR_UPDATED_BY_ME_KEY: String = "by_me" // boolean
    const val GROUP_V2_CREATED_OR_UPDATED_BY_KEY: String = "by" // byte[]
    const val GROUP_V2_CREATED_OR_UPDATED_GROUP_LEAVERS_KEY: String = "group_leavers" // byte[][]
    const val GROUP_V2_CREATED_OR_UPDATED_CREATED_ON_OTHER_DEVICE: String =
        "created_on_other_device" // boolean --> only meaningful for new groups created by be ("new_group" == true). true if created on another device, false if created on this device

    const val GROUP_V2_PHOTO_CHANGED: String = "engine_notification_group_v2_photo_changed"
    const val GROUP_V2_PHOTO_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val GROUP_V2_PHOTO_CHANGED_BYTES_GROUP_IDENTIFIER_KEY: String =
        "bytes_group_identifier" // byte[]

    const val GROUP_V2_UPDATE_IN_PROGRESS_CHANGED: String =
        "engine_notification_group_v2_update_in_progress_changed"
    const val GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_GROUP_IDENTIFIER_KEY: String =
        "bytes_group_identifier" // byte[]
    const val GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_UPDATING_KEY: String = "updating" // boolean
    const val GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_CREATING_KEY: String = "creating" // boolean

    const val GROUP_V2_DELETED: String = "engine_notification_group_v2_deleted"
    const val GROUP_V2_DELETED_BYTES_OWNED_IDENTITY: String = "bytes_owned_identity" // byte[]
    const val GROUP_V2_DELETED_BYTES_GROUP_IDENTIFIER_KEY: String =
        "bytes_group_identifier" // byte[]
    const val GROUP_V2_DELETED_DELETED_BY_KEY: String = "deleted_by" // byte[]

    const val GROUP_V2_UPDATE_FAILED: String = "engine_notification_group_v2_update_failed"
    const val GROUP_V2_UPDATE_FAILED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val GROUP_V2_UPDATE_FAILED_BYTES_GROUP_IDENTIFIER_KEY: String =
        "bytes_group_identifier" // byte[]
    const val GROUP_V2_UPDATE_FAILED_ERROR_KEY: String = "error" // boolean

    const val PUSH_TOPIC_NOTIFIED: String = "engine_notification_push_topic_notified"
    const val PUSH_TOPIC_NOTIFIED_TOPIC_KEY: String = "topic" // String

    const val KEYCLOAK_UPDATE_REQUIRED: String = "engine_notification_keycloak_update_required"
    const val KEYCLOAK_UPDATE_REQUIRED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val KEYCLOAK_GROUP_V2_SHARED_SETTINGS: String =
        "engine_notification_keycloak_group_v2_shared_settings"
    const val KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_GROUP_IDENTIFIER_KEY: String =
        "bytes_group_identifier" // byte[]
    const val KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SHARED_SETTINGS_KEY: String =
        "shared_settings" // String, serialized JsonSharedSettings
    const val KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY: String =
        "timestamp" // long

    const val OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE: String =
        "engine_notification_owned_identity_deleted_from_another_device"
    const val OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val OWNED_IDENTITY_DEVICE_LIST_CHANGED: String =
        "engine_notification_owned_identity_device_list_changed"
    const val OWNED_IDENTITY_DEVICE_LIST_CHANGED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val KEYCLOAK_SYNCHRONIZATION_REQUIRED: String =
        "engine_notification_keycloak_synchronization_required"
    const val KEYCLOAK_SYNCHRONIZATION_REQUIRED_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val CONTACT_INTRODUCTION_INVITATION_SENT: String =
        "engine_notification_contact_introduction_invitation_sent"
    const val CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_A_KEY: String =
        "bytes_contact_identity_a" // byte[]
    const val CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_B_KEY: String =
        "bytes_contact_identity_b" // byte[]

    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE: String =
        "engine_notification_contact_introduction_invitation_response"
    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_MEDIATOR_IDENTITY_KEY: String =
        "bytes_mediator_identity" // byte[]
    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_CONTACT_IDENTITY_KEY: String =
        "bytes_contact_identity" // byte[]
    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY: String =
        "contact_serialized_Details" // String
    const val CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY: String = "accepted" // boolean

    const val PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE: String =
        "engine_notification_push_register_failed_bad_device_uid_to_replace"
    const val PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]

    const val OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER: String =
        "engine_notification_owned_identity_synchronizing_with_server"
    const val OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
    const val OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY: String =
        "status" // OwnedIdentitySynchronizationStatus

    const val OWNED_DEVICE_DISCOVERY_DONE: String =
        "engine_notification_owned_device_discovery_done"
    const val OWNED_DEVICE_DISCOVERY_DONE_BYTES_OWNED_IDENTITY_KEY: String =
        "bytes_owned_identity" // byte[]
}
