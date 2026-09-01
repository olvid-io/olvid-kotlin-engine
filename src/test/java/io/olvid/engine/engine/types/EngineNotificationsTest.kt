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

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Characterization tests for [EngineNotifications].
 *
 * Every constant in [EngineNotifications] is a wire-format String. The engine fires
 * notifications using these strings as topic names and payload-map keys; the app registers
 * listeners by exact string match. A Java→Kotlin migration (or any stray refactoring) that
 * changes ANY string silently stops the corresponding notification from being delivered.
 *
 * Each test pins the exact string value of one constant. The test name is the contract
 * documentation.
 *
 * Tests are grouped by notification topic. Within each group:
 *   - The first test pins the topic string (the notification name the engine fires).
 *   - Subsequent tests pin each payload-key constant for that topic.
 */
class EngineNotificationsTest {

    // ─── UI_DIALOG_DELETED ────────────────────────────────────────────────────

    @Test
    fun testUiDialogDeletedTopic() {
        assertEquals("engine_notification_ui_dialog_deleted", EngineNotifications.UI_DIALOG_DELETED)
    }

    @Test
    fun testUiDialogDeletedUuidKey() {
        assertEquals("uuid", EngineNotifications.UI_DIALOG_DELETED_UUID_KEY)
    }

    // ─── UI_DIALOG ────────────────────────────────────────────────────────────

    @Test
    fun testUiDialogTopic() {
        assertEquals("engine_notification_ui_dialog", EngineNotifications.UI_DIALOG)
    }

    @Test
    fun testUiDialogUuidKey() {
        assertEquals("uuid", EngineNotifications.UI_DIALOG_UUID_KEY)
    }

    @Test
    fun testUiDialogDialogKey() {
        assertEquals("dialog", EngineNotifications.UI_DIALOG_DIALOG_KEY)
    }

    @Test
    fun testUiDialogCreationTimestampKey() {
        assertEquals("creation_timestamp", EngineNotifications.UI_DIALOG_CREATION_TIMESTAMP_KEY)
    }

    // ─── SERVER_POLL_REQUESTED ────────────────────────────────────────────────

    @Test
    fun testServerPollRequestedTopic() {
        assertEquals("engine_notification_server_poll_requested", EngineNotifications.SERVER_POLL_REQUESTED)
    }

    @Test
    fun testServerPollRequestedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.SERVER_POLL_REQUESTED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testServerPollRequestedUserInitiatedKey() {
        assertEquals("user_initiated", EngineNotifications.SERVER_POLL_REQUESTED_USER_INITIATED_KEY)
    }

    // ─── SERVER_POLLED ────────────────────────────────────────────────────────

    @Test
    fun testServerPolledTopic() {
        assertEquals("engine_notification_server_polled", EngineNotifications.SERVER_POLLED)
    }

    @Test
    fun testServerPolledBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.SERVER_POLLED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testServerPolledSuccessKey() {
        assertEquals("success", EngineNotifications.SERVER_POLLED_SUCCESS_KEY)
    }

    @Test
    fun testServerPolledTruncatedKey() {
        assertEquals("truncated", EngineNotifications.SERVER_POLLED_TRUNCATED_KEY)
    }

    // ─── NEW_MESSAGE_RECEIVED ─────────────────────────────────────────────────

    @Test
    fun testNewMessageReceivedTopic() {
        assertEquals("engine_notification_new_message_received", EngineNotifications.NEW_MESSAGE_RECEIVED)
    }

    @Test
    fun testNewMessageReceivedMessageKey() {
        assertEquals("message", EngineNotifications.NEW_MESSAGE_RECEIVED_MESSAGE_KEY)
    }

    // ─── MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED ──────────────────────────────────

    @Test
    fun testMessageExtendedPayloadDownloadedTopic() {
        assertEquals("engine_notification_message_extended_payload_downloaded", EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED)
    }

    @Test
    fun testMessageExtendedPayloadDownloadedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testMessageExtendedPayloadDownloadedMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testMessageExtendedPayloadDownloadedExtendedPayloadKey() {
        assertEquals("extended_payload", EngineNotifications.MESSAGE_EXTENDED_PAYLOAD_DOWNLOADED_EXTENDED_PAYLOAD_KEY)
    }

    // ─── ATTACHMENT_DOWNLOAD_PROGRESS ────────────────────────────────────────

    @Test
    fun testAttachmentDownloadProgressTopic() {
        assertEquals("engine_notification_download_attachment_progress", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS)
    }

    @Test
    fun testAttachmentDownloadProgressBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testAttachmentDownloadProgressMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testAttachmentDownloadProgressAttachmentNumberKey() {
        assertEquals("attachment_number", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY)
    }

    @Test
    fun testAttachmentDownloadProgressProgressKey() {
        assertEquals("progress", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_PROGRESS_KEY)
    }

    @Test
    fun testAttachmentDownloadProgressSpeedBpsKey() {
        assertEquals("speed", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_SPEED_BPS_KEY)
    }

    @Test
    fun testAttachmentDownloadProgressEtaSecondsKey() {
        assertEquals("eta", EngineNotifications.ATTACHMENT_DOWNLOAD_PROGRESS_ETA_SECONDS_KEY)
    }

    // ─── ATTACHMENT_DOWNLOADED ────────────────────────────────────────────────

    @Test
    fun testAttachmentDownloadedTopic() {
        assertEquals("engine_notification_attachment_downloaded", EngineNotifications.ATTACHMENT_DOWNLOADED)
    }

    @Test
    fun testAttachmentDownloadedAttachmentKey() {
        assertEquals("attachment", EngineNotifications.ATTACHMENT_DOWNLOADED_ATTACHMENT_KEY)
    }

    // ─── ATTACHMENT_UPLOAD_PROGRESS ───────────────────────────────────────────

    @Test
    fun testAttachmentUploadProgressTopic() {
        assertEquals("engine_notification_upload_attachment_progress", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS)
    }

    @Test
    fun testAttachmentUploadProgressBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testAttachmentUploadProgressMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testAttachmentUploadProgressAttachmentNumberKey() {
        assertEquals("attachment_number", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY)
    }

    @Test
    fun testAttachmentUploadProgressProgressKey() {
        assertEquals("progress", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY)
    }

    @Test
    fun testAttachmentUploadProgressSpeedBpsKey() {
        assertEquals("speed", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_SPEED_BPS_KEY)
    }

    @Test
    fun testAttachmentUploadProgressEtaSecondsKey() {
        assertEquals("eta", EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_ETA_SECONDS_KEY)
    }

    // ─── ATTACHMENT_UPLOADED ──────────────────────────────────────────────────

    @Test
    fun testAttachmentUploadedTopic() {
        assertEquals("engine_notification_attachment_uploaded", EngineNotifications.ATTACHMENT_UPLOADED)
    }

    @Test
    fun testAttachmentUploadedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.ATTACHMENT_UPLOADED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testAttachmentUploadedMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.ATTACHMENT_UPLOADED_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testAttachmentUploadedAttachmentNumberKey() {
        assertEquals("attachment_number", EngineNotifications.ATTACHMENT_UPLOADED_ATTACHMENT_NUMBER_KEY)
    }

    // ─── ATTACHMENT_UPLOAD_CANCELLED ──────────────────────────────────────────

    @Test
    fun testAttachmentUploadCancelledTopic() {
        assertEquals("engine_notification_attachment_upload_cancelled", EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED)
    }

    @Test
    fun testAttachmentUploadCancelledBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testAttachmentUploadCancelledMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testAttachmentUploadCancelledAttachmentNumberKey() {
        assertEquals("attachment_number", EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_ATTACHMENT_NUMBER_KEY)
    }

    // ─── ATTACHMENT_DOWNLOAD_FAILED ───────────────────────────────────────────

    @Test
    fun testAttachmentDownloadFailedTopic() {
        assertEquals("engine_notification_attachment_failed", EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED)
    }

    @Test
    fun testAttachmentDownloadFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testAttachmentDownloadFailedMessageIdentifierKey() {
        assertEquals("message_identifier", EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_MESSAGE_IDENTIFIER_KEY)
    }

    @Test
    fun testAttachmentDownloadFailedAttachmentNumberKey() {
        assertEquals("attachment_number", EngineNotifications.ATTACHMENT_DOWNLOAD_FAILED_ATTACHMENT_NUMBER_KEY)
    }

    // ─── MESSAGE_UPLOADED ─────────────────────────────────────────────────────

    @Test
    fun testMessageUploadedTopic() {
        assertEquals("engine_notification_message_uploaded", EngineNotifications.MESSAGE_UPLOADED)
    }

    @Test
    fun testMessageUploadedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.MESSAGE_UPLOADED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testMessageUploadedIdentifierKey() {
        assertEquals("identifier", EngineNotifications.MESSAGE_UPLOADED_IDENTIFIER_KEY)
    }

    @Test
    fun testMessageUploadedTimestampFromServer() {
        assertEquals("timestamp_from_server", EngineNotifications.MESSAGE_UPLOADED_TIMESTAMP_FROM_SERVER)
    }

    // ─── MESSAGE_UPLOAD_FAILED ────────────────────────────────────────────────

    @Test
    fun testMessageUploadFailedTopic() {
        assertEquals("engine_notification_message_upload_failed", EngineNotifications.MESSAGE_UPLOAD_FAILED)
    }

    @Test
    fun testMessageUploadFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.MESSAGE_UPLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testMessageUploadFailedIdentifierKey() {
        assertEquals("identifier", EngineNotifications.MESSAGE_UPLOAD_FAILED_IDENTIFIER_KEY)
    }

    // ─── NEW_CONTACT ──────────────────────────────────────────────────────────

    @Test
    fun testNewContactTopic() {
        assertEquals("engine_notification_new_contact", EngineNotifications.NEW_CONTACT)
    }

    @Test
    fun testNewContactOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.NEW_CONTACT_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testNewContactContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.NEW_CONTACT_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testNewContactOneToOneKey() {
        assertEquals("one_to_one", EngineNotifications.NEW_CONTACT_ONE_TO_ONE_KEY)
    }

    @Test
    fun testNewContactTrustLevelKey() {
        assertEquals("trust_level", EngineNotifications.NEW_CONTACT_TRUST_LEVEL_KEY)
    }

    @Test
    fun testNewContactHasUntrustedPublishedDetailsKey() {
        assertEquals("has_untrusted_published_details", EngineNotifications.NEW_CONTACT_HAS_UNTRUSTED_PUBLISHED_DETAILS_KEY)
    }

    // ─── CONTACT_DELETED ──────────────────────────────────────────────────────

    @Test
    fun testContactDeletedTopic() {
        assertEquals("engine_notification_contact_deleted", EngineNotifications.CONTACT_DELETED)
    }

    @Test
    fun testContactDeletedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_DELETED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactDeletedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_DELETED_BYTES_CONTACT_IDENTITY_KEY)
    }

    // ─── CONTACT_DEVICES_UPDATED ──────────────────────────────────────────────

    @Test
    fun testContactDevicesUpdatedTopic() {
        assertEquals("engine_notification_contact_devices_updated", EngineNotifications.CONTACT_DEVICES_UPDATED)
    }

    @Test
    fun testContactDevicesUpdatedOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.CONTACT_DEVICES_UPDATED_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactDevicesUpdatedContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.CONTACT_DEVICES_UPDATED_CONTACT_IDENTITY_KEY)
    }

    // ─── CHANNEL_CONFIRMED_OR_DELETED ────────────────────────────────────────

    @Test
    fun testChannelConfirmedOrDeletedTopic() {
        assertEquals("engine_notification_channel_confirmed_or_deleted", EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED)
    }

    @Test
    fun testChannelConfirmedOrDeletedOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testChannelConfirmedOrDeletedContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_CONTACT_IDENTITY_KEY)
    }

    // ─── GROUP_CREATED ────────────────────────────────────────────────────────

    @Test
    fun testGroupCreatedTopic() {
        assertEquals("engine_notification_group_created", EngineNotifications.GROUP_CREATED)
    }

    @Test
    fun testGroupCreatedGroupKey() {
        assertEquals("group", EngineNotifications.GROUP_CREATED_GROUP_KEY)
    }

    @Test
    fun testGroupCreatedHasMultipleDetailsKey() {
        assertEquals("has_multiple_details", EngineNotifications.GROUP_CREATED_HAS_MULTIPLE_DETAILS_KEY)
    }

    @Test
    fun testGroupCreatedPhotoUrlKey() {
        assertEquals("photo_url", EngineNotifications.GROUP_CREATED_PHOTO_URL_KEY)
    }

    @Test
    fun testGroupCreatedOnOtherDeviceKey() {
        assertEquals("on_other_device", EngineNotifications.GROUP_CREATED_ON_OTHER_DEVICE_KEY)
    }

    // ─── GROUP_DELETED ────────────────────────────────────────────────────────

    @Test
    fun testGroupDeletedTopic() {
        assertEquals("engine_notification_group_deleted", EngineNotifications.GROUP_DELETED)
    }

    @Test
    fun testGroupDeletedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_DELETED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupDeletedBytesGroupOwnerAndUidKey() {
        assertEquals("bytes_group_owner_and_uid", EngineNotifications.GROUP_DELETED_BYTES_GROUP_OWNER_AND_UID_KEY)
    }

    // ─── GROUP_MEMBER_ADDED ───────────────────────────────────────────────────

    @Test
    fun testGroupMemberAddedTopic() {
        assertEquals("engine_notification_group_member_added", EngineNotifications.GROUP_MEMBER_ADDED)
    }

    @Test
    fun testGroupMemberAddedBytesGroupUidKey() {
        assertEquals("group_uid", EngineNotifications.GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testGroupMemberAddedBytesOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupMemberAddedBytesContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.GROUP_MEMBER_ADDED_BYTES_CONTACT_IDENTITY_KEY)
    }

    // ─── GROUP_MEMBER_REMOVED ─────────────────────────────────────────────────

    @Test
    fun testGroupMemberRemovedTopic() {
        assertEquals("engine_notification_group_member_removed", EngineNotifications.GROUP_MEMBER_REMOVED)
    }

    @Test
    fun testGroupMemberRemovedBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testGroupMemberRemovedBytesOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupMemberRemovedBytesContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_CONTACT_IDENTITY_KEY)
    }

    // ─── PENDING_GROUP_MEMBER_ADDED ───────────────────────────────────────────

    @Test
    fun testPendingGroupMemberAddedTopic() {
        assertEquals("engine_notification_pending_group_member_added", EngineNotifications.PENDING_GROUP_MEMBER_ADDED)
    }

    @Test
    fun testPendingGroupMemberAddedBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.PENDING_GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testPendingGroupMemberAddedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.PENDING_GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testPendingGroupMemberAddedContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.PENDING_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY)
    }

    // ─── PENDING_GROUP_MEMBER_REMOVED ─────────────────────────────────────────

    @Test
    fun testPendingGroupMemberRemovedTopic() {
        assertEquals("engine_notification_pending_group_member_removed", EngineNotifications.PENDING_GROUP_MEMBER_REMOVED)
    }

    @Test
    fun testPendingGroupMemberRemovedBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testPendingGroupMemberRemovedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testPendingGroupMemberRemovedContactIdentityKey() {
        assertEquals("contact_identity", EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY)
    }

    // ─── API_KEY_ACCEPTED ─────────────────────────────────────────────────────

    @Test
    fun testApiKeyAcceptedTopic() {
        assertEquals("engine_notification_api_key_accepted", EngineNotifications.API_KEY_ACCEPTED)
    }

    @Test
    fun testApiKeyAcceptedOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.API_KEY_ACCEPTED_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testApiKeyAcceptedApiKeyStatusKey() {
        assertEquals("api_key_status", EngineNotifications.API_KEY_ACCEPTED_API_KEY_STATUS_KEY)
    }

    @Test
    fun testApiKeyAcceptedPermissionsKey() {
        assertEquals("permissions", EngineNotifications.API_KEY_ACCEPTED_PERMISSIONS_KEY)
    }

    @Test
    fun testApiKeyAcceptedApiKeyExpirationTimestampKey() {
        assertEquals("api_key_expiration_timestamp", EngineNotifications.API_KEY_ACCEPTED_API_KEY_EXPIRATION_TIMESTAMP_KEY)
    }

    // ─── OWNED_IDENTITY_LIST_UPDATED ─────────────────────────────────────────

    @Test
    fun testOwnedIdentityListUpdatedTopic() {
        assertEquals("engine_notification_owned_identity_list_updated", EngineNotifications.OWNED_IDENTITY_LIST_UPDATED)
    }

    // ─── OWNED_IDENTITY_DETAILS_CHANGED ──────────────────────────────────────

    @Test
    fun testOwnedIdentityDetailsChangedTopic() {
        assertEquals("engine_notification_owned_identity_display_name_changed", EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED)
    }

    @Test
    fun testOwnedIdentityDetailsChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testOwnedIdentityDetailsChangedIdentityDetailsKey() {
        assertEquals("display_name", EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_IDENTITY_DETAILS_KEY)
    }

    @Test
    fun testOwnedIdentityDetailsChangedPhotoUrlKey() {
        assertEquals("photo_url", EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_PHOTO_URL_KEY)
    }

    // ─── NEW_CONTACT_PUBLISHED_DETAILS ────────────────────────────────────────

    @Test
    fun testNewContactPublishedDetailsTopic() {
        assertEquals("engine_notification_new_contact_published_details", EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS)
    }

    @Test
    fun testNewContactPublishedDetailsBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testNewContactPublishedDetailsBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS_BYTES_CONTACT_IDENTITY_KEY)
    }

    // ─── CONTACT_PUBLISHED_DETAILS_TRUSTED ───────────────────────────────────

    @Test
    fun testContactPublishedDetailsTrustedTopic() {
        assertEquals("engine_notification_contact_published_details_trusted", EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED)
    }

    @Test
    fun testContactPublishedDetailsTrustedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactPublishedDetailsTrustedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactPublishedDetailsTrustedIdentityDetailsKey() {
        assertEquals("identity_details", EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_IDENTITY_DETAILS_KEY)
    }

    // ─── CONTACT_KEYCLOAK_MANAGED_CHANGED ────────────────────────────────────

    @Test
    fun testContactKeycloakManagedChangedTopic() {
        assertEquals("engine_notification_contact_keycloak_managed_changed", EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED)
    }

    @Test
    fun testContactKeycloakManagedChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactKeycloakManagedChangedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactKeycloakManagedChangedKeycloakManagedKey() {
        assertEquals("keycloak_managed", EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_KEYCLOAK_MANAGED_KEY)
    }

    // ─── CONTACT_ACTIVE_CHANGED ───────────────────────────────────────────────

    @Test
    fun testContactActiveChangedTopic() {
        assertEquals("engine_notification_contact_active_changed", EngineNotifications.CONTACT_ACTIVE_CHANGED)
    }

    @Test
    fun testContactActiveChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_ACTIVE_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactActiveChangedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_ACTIVE_CHANGED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactActiveChangedActiveKey() {
        assertEquals("active", EngineNotifications.CONTACT_ACTIVE_CHANGED_ACTIVE_KEY)
    }

    // ─── CONTACT_REVOKED ──────────────────────────────────────────────────────

    @Test
    fun testContactRevokedTopic() {
        assertEquals("engine_notification_contact_revoked", EngineNotifications.CONTACT_REVOKED)
    }

    @Test
    fun testContactRevokedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_REVOKED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactRevokedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_REVOKED_BYTES_CONTACT_IDENTITY_KEY)
    }

    // ─── NEW_CONTACT_PHOTO ────────────────────────────────────────────────────

    @Test
    fun testNewContactPhotoTopic() {
        assertEquals("engine_notification_new_contact_photo", EngineNotifications.NEW_CONTACT_PHOTO)
    }

    @Test
    fun testNewContactPhotoBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.NEW_CONTACT_PHOTO_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testNewContactPhotoBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.NEW_CONTACT_PHOTO_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testNewContactPhotoVersionKey() {
        assertEquals("version", EngineNotifications.NEW_CONTACT_PHOTO_VERSION_KEY)
    }

    @Test
    fun testNewContactPhotoIsTrustedKey() {
        assertEquals("is_trusted", EngineNotifications.NEW_CONTACT_PHOTO_IS_TRUSTED_KEY)
    }

    // ─── NEW_GROUP_PHOTO ──────────────────────────────────────────────────────

    @Test
    fun testNewGroupPhotoTopic() {
        assertEquals("engine_notification_new_group_photo", EngineNotifications.NEW_GROUP_PHOTO)
    }

    @Test
    fun testNewGroupPhotoBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.NEW_GROUP_PHOTO_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testNewGroupPhotoBytesGroupOwnerAndUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.NEW_GROUP_PHOTO_BYTES_GROUP_OWNER_AND_UID_KEY)
    }

    @Test
    fun testNewGroupPhotoVersionKey() {
        assertEquals("version", EngineNotifications.NEW_GROUP_PHOTO_VERSION_KEY)
    }

    @Test
    fun testNewGroupPhotoIsTrustedKey() {
        assertEquals("is_trusted", EngineNotifications.NEW_GROUP_PHOTO_IS_TRUSTED_KEY)
    }

    // ─── GROUP_PUBLISHED_DETAILS_UPDATED ─────────────────────────────────────

    @Test
    fun testGroupPublishedDetailsUpdatedTopic() {
        assertEquals("engine_notification_group_published_details_updated", EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED)
    }

    @Test
    fun testGroupPublishedDetailsUpdatedBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testGroupPublishedDetailsUpdatedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupPublishedDetailsUpdatedGroupDetailsKey() {
        assertEquals("group_details", EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_DETAILS_KEY)
    }

    // ─── GROUP_PUBLISHED_DETAILS_TRUSTED ─────────────────────────────────────

    @Test
    fun testGroupPublishedDetailsTrustedTopic() {
        assertEquals("engine_notification_group_published_details_trusted", EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED)
    }

    @Test
    fun testGroupPublishedDetailsTrustedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupPublishedDetailsTrustedBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testGroupPublishedDetailsTrustedGroupDetailsKey() {
        assertEquals("group_details", EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_DETAILS_KEY)
    }

    // ─── NEW_GROUP_PUBLISHED_DETAILS ──────────────────────────────────────────

    @Test
    fun testNewGroupPublishedDetailsTopic() {
        assertEquals("engine_notification_new_group_published_details", EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS)
    }

    @Test
    fun testNewGroupPublishedDetailsBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testNewGroupPublishedDetailsBytesGroupOwnerAndUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS_BYTES_GROUP_OWNER_AND_UID_KEY)
    }

    // ─── PENDING_GROUP_MEMBER_DECLINE_TOGGLED ────────────────────────────────

    @Test
    fun testPendingGroupMemberDeclineToggledTopic() {
        assertEquals("engine_notification_pending_group_member_decline_toggled", EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED)
    }

    @Test
    fun testPendingGroupMemberDeclineToggledBytesGroupUidKey() {
        assertEquals("bytes_group_uid", EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_GROUP_UID_KEY)
    }

    @Test
    fun testPendingGroupMemberDeclineToggledBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testPendingGroupMemberDeclineToggledBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testPendingGroupMemberDeclineToggledDeclinedKey() {
        assertEquals("declined", EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_DECLINED_KEY)
    }

    // ─── OWNED_IDENTITY_LATEST_DETAILS_UPDATED ───────────────────────────────

    @Test
    fun testOwnedIdentityLatestDetailsUpdatedTopic() {
        assertEquals("engine_notification_owned_identity_latest_details_updated", EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED)
    }

    @Test
    fun testOwnedIdentityLatestDetailsUpdatedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testOwnedIdentityLatestDetailsUpdatedHasUnpublishedKey() {
        assertEquals("has_unpublished", EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED_HAS_UNPUBLISHED_KEY)
    }

    // ─── OWNED_IDENTITY_ACTIVE_STATUS_CHANGED ────────────────────────────────

    @Test
    fun testOwnedIdentityActiveStatusChangedTopic() {
        assertEquals("engine_notification_owned_identity_changed_active_status", EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED)
    }

    @Test
    fun testOwnedIdentityActiveStatusChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testOwnedIdentityActiveStatusChangedActiveKey() {
        assertEquals("active", EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_ACTIVE_KEY)
    }

    // ─── RETURN_RECEIPT_RECEIVED ──────────────────────────────────────────────

    @Test
    fun testReturnReceiptReceivedTopic() {
        assertEquals("engine_notification_return_receipt_received", EngineNotifications.RETURN_RECEIPT_RECEIVED)
    }

    @Test
    fun testReturnReceiptReceivedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.RETURN_RECEIPT_RECEIVED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testReturnReceiptReceivedServerUidKey() {
        assertEquals("server_uid", EngineNotifications.RETURN_RECEIPT_RECEIVED_SERVER_UID_KEY)
    }

    @Test
    fun testReturnReceiptReceivedNonceKey() {
        assertEquals("nonce", EngineNotifications.RETURN_RECEIPT_RECEIVED_NONCE_KEY)
    }

    @Test
    fun testReturnReceiptReceivedEncryptedPayloadKey() {
        assertEquals("encrypted_payload", EngineNotifications.RETURN_RECEIPT_RECEIVED_ENCRYPTED_PAYLOAD_KEY)
    }

    @Test
    fun testReturnReceiptReceivedTimestampKey() {
        assertEquals("timestamp", EngineNotifications.RETURN_RECEIPT_RECEIVED_TIMESTAMP_KEY)
    }

    // ─── NEW_BACKUP_SEED_GENERATED ────────────────────────────────────────────

    @Test
    fun testNewBackupSeedGeneratedTopic() {
        assertEquals("engine_notification_new_backup_seed_generated", EngineNotifications.NEW_BACKUP_SEED_GENERATED)
    }

    @Test
    fun testNewBackupSeedGeneratedSeedKey() {
        assertEquals("seed", EngineNotifications.NEW_BACKUP_SEED_GENERATED_SEED_KEY)
    }

    // ─── BACKUP_SEED_GENERATION_FAILED ───────────────────────────────────────

    @Test
    fun testBackupSeedGenerationFailedTopic() {
        assertEquals("engine_notification_backup_seed_generation_failed", EngineNotifications.BACKUP_SEED_GENERATION_FAILED)
    }

    // ─── BACKUP_KEY_VERIFICATION_SUCCESSFUL ──────────────────────────────────

    @Test
    fun testBackupKeyVerificationSuccessfulTopic() {
        assertEquals("engine_notification_backup_key_verification_successful", EngineNotifications.BACKUP_KEY_VERIFICATION_SUCCESSFUL)
    }

    // ─── BACKUP_FOR_EXPORT_FINISHED ───────────────────────────────────────────

    @Test
    fun testBackupForExportFinishedTopic() {
        assertEquals("engine_notification_backup_for_export_finished", EngineNotifications.BACKUP_FOR_EXPORT_FINISHED)
    }

    @Test
    fun testBackupForExportFinishedBytesBackupKeyUidKey() {
        assertEquals("backup_key_uid", EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_BYTES_BACKUP_KEY_UID_KEY)
    }

    @Test
    fun testBackupForExportFinishedVersionKey() {
        assertEquals("version", EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY)
    }

    @Test
    fun testBackupForExportFinishedEncryptedContentKey() {
        assertEquals("encrypted_content", EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY)
    }

    // ─── BACKUP_FINISHED ──────────────────────────────────────────────────────

    @Test
    fun testBackupFinishedTopic() {
        assertEquals("engine_notification_backup_finished", EngineNotifications.BACKUP_FINISHED)
    }

    @Test
    fun testBackupFinishedBytesBackupKeyUidKey() {
        assertEquals("backup_key_uid", EngineNotifications.BACKUP_FINISHED_BYTES_BACKUP_KEY_UID_KEY)
    }

    @Test
    fun testBackupFinishedVersionKey() {
        assertEquals("version", EngineNotifications.BACKUP_FINISHED_VERSION_KEY)
    }

    @Test
    fun testBackupFinishedEncryptedContentKey() {
        assertEquals("encrypted_content", EngineNotifications.BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY)
    }

    // ─── BACKUP_FOR_EXPORT_FAILED ─────────────────────────────────────────────

    @Test
    fun testBackupForExportFailedTopic() {
        assertEquals("engine_notification_backup_for_export_failed", EngineNotifications.BACKUP_FOR_EXPORT_FAILED)
    }

    // ─── TURN_CREDENTIALS_RECEIVED ───────────────────────────────────────────

    @Test
    fun testTurnCredentialsReceivedTopic() {
        assertEquals("engine_notification_turn_credentials_received", EngineNotifications.TURN_CREDENTIALS_RECEIVED)
    }

    @Test
    fun testTurnCredentialsReceivedOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.TURN_CREDENTIALS_RECEIVED_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedCallUuidKey() {
        assertEquals("call_uuid", EngineNotifications.TURN_CREDENTIALS_RECEIVED_CALL_UUID_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedUsername1Key() {
        assertEquals("username1", EngineNotifications.TURN_CREDENTIALS_RECEIVED_USERNAME_1_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedPassword1Key() {
        // Note: the constant name is PASSWORD_1_KEY but the wire value is "username2" (source typo preserved as contract).
        assertEquals("username2", EngineNotifications.TURN_CREDENTIALS_RECEIVED_PASSWORD_1_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedUsername2Key() {
        // Note: the constant name is USERNAME_2_KEY but the wire value is "password1" (source typo preserved as contract).
        assertEquals("password1", EngineNotifications.TURN_CREDENTIALS_RECEIVED_USERNAME_2_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedPassword2Key() {
        assertEquals("password2", EngineNotifications.TURN_CREDENTIALS_RECEIVED_PASSWORD_2_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedServersKey() {
        assertEquals("servers", EngineNotifications.TURN_CREDENTIALS_RECEIVED_SERVERS_KEY)
    }

    @Test
    fun testTurnCredentialsReceivedAltServersKey() {
        assertEquals("alt_servers", EngineNotifications.TURN_CREDENTIALS_RECEIVED_ALT_SERVERS_KEY)
    }

    // ─── TURN_CREDENTIALS_FAILED ─────────────────────────────────────────────

    @Test
    fun testTurnCredentialsFailedTopic() {
        assertEquals("engine_notification_turn_credentials_failed", EngineNotifications.TURN_CREDENTIALS_FAILED)
    }

    @Test
    fun testTurnCredentialsFailedOwnedIdentityKey() {
        assertEquals("owned_identity", EngineNotifications.TURN_CREDENTIALS_FAILED_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testTurnCredentialsFailedCallUuidKey() {
        assertEquals("call_uuid", EngineNotifications.TURN_CREDENTIALS_FAILED_CALL_UUID_KEY)
    }

    @Test
    fun testTurnCredentialsFailedReasonKey() {
        assertEquals("reason", EngineNotifications.TURN_CREDENTIALS_FAILED_REASON_KEY)
    }

    // ─── API_KEY_STATUS_QUERY_SUCCESS ─────────────────────────────────────────

    @Test
    fun testApiKeyStatusQuerySuccessTopic() {
        assertEquals("engine_notification_api_key_status_query_success", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS)
    }

    @Test
    fun testApiKeyStatusQuerySuccessBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testApiKeyStatusQuerySuccessApiKeyKey() {
        assertEquals("api_key", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_KEY)
    }

    @Test
    fun testApiKeyStatusQuerySuccessApiKeyStatusKey() {
        assertEquals("api_key_status", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_STATUS_KEY)
    }

    @Test
    fun testApiKeyStatusQuerySuccessPermissionsKey() {
        assertEquals("permissions", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_PERMISSIONS_KEY)
    }

    @Test
    fun testApiKeyStatusQuerySuccessApiKeyExpirationTimestampKey() {
        assertEquals("api_key_expiration_timestamp", EngineNotifications.API_KEY_STATUS_QUERY_SUCCESS_API_KEY_EXPIRATION_TIMESTAMP_KEY)
    }

    // ─── API_KEY_STATUS_QUERY_FAILED ──────────────────────────────────────────

    @Test
    fun testApiKeyStatusQueryFailedTopic() {
        assertEquals("engine_notification_api_key_status_query_failed", EngineNotifications.API_KEY_STATUS_QUERY_FAILED)
    }

    @Test
    fun testApiKeyStatusQueryFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.API_KEY_STATUS_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testApiKeyStatusQueryFailedApiKeyKey() {
        assertEquals("api_key", EngineNotifications.API_KEY_STATUS_QUERY_FAILED_API_KEY_KEY)
    }

    // ─── FREE_TRIAL_QUERY_SUCCESS ─────────────────────────────────────────────

    @Test
    fun testFreeTrialQuerySuccessTopic() {
        assertEquals("engine_notification_free_trial_query_success", EngineNotifications.FREE_TRIAL_QUERY_SUCCESS)
    }

    @Test
    fun testFreeTrialQuerySuccessBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.FREE_TRIAL_QUERY_SUCCESS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testFreeTrialQuerySuccessAvailableKey() {
        assertEquals("available", EngineNotifications.FREE_TRIAL_QUERY_SUCCESS_AVAILABLE_KEY)
    }

    // ─── FREE_TRIAL_QUERY_FAILED ──────────────────────────────────────────────

    @Test
    fun testFreeTrialQueryFailedTopic() {
        assertEquals("engine_notification_free_trial_query_failed", EngineNotifications.FREE_TRIAL_QUERY_FAILED)
    }

    @Test
    fun testFreeTrialQueryFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.FREE_TRIAL_QUERY_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── FREE_TRIAL_RETRIEVE_SUCCESS ──────────────────────────────────────────

    @Test
    fun testFreeTrialRetrieveSuccessTopic() {
        assertEquals("engine_notification_retrieve_query_success", EngineNotifications.FREE_TRIAL_RETRIEVE_SUCCESS)
    }

    @Test
    fun testFreeTrialRetrieveSuccessBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.FREE_TRIAL_RETRIEVE_SUCCESS_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── FREE_TRIAL_RETRIEVE_FAILED ───────────────────────────────────────────

    @Test
    fun testFreeTrialRetrieveFailedTopic() {
        assertEquals("engine_notification_retrieve_query_failed", EngineNotifications.FREE_TRIAL_RETRIEVE_FAILED)
    }

    @Test
    fun testFreeTrialRetrieveFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.FREE_TRIAL_RETRIEVE_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── VERIFY_RECEIPT_SUCCESS ───────────────────────────────────────────────

    @Test
    fun testVerifyReceiptSuccessTopic() {
        assertEquals("engine_notification_verify_receipt_success", EngineNotifications.VERIFY_RECEIPT_SUCCESS)
    }

    @Test
    fun testVerifyReceiptSuccessBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.VERIFY_RECEIPT_SUCCESS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testVerifyReceiptSuccessStoreTokenKey() {
        assertEquals("store_token", EngineNotifications.VERIFY_RECEIPT_SUCCESS_STORE_TOKEN_KEY)
    }

    // ─── WELL_KNOWN_DOWNLOAD_SUCCESS ──────────────────────────────────────────

    @Test
    fun testWellKnownDownloadSuccessTopic() {
        assertEquals("engine_notification_well_known_download_success", EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS)
    }

    @Test
    fun testWellKnownDownloadSuccessServerKey() {
        assertEquals("server", EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_SERVER_KEY)
    }

    @Test
    fun testWellKnownDownloadSuccessAppInfoKey() {
        assertEquals("app_info", EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_APP_INFO_KEY)
    }

    @Test
    fun testWellKnownDownloadSuccessUpdatedKey() {
        assertEquals("updated", EngineNotifications.WELL_KNOWN_DOWNLOAD_SUCCESS_UPDATED_KEY)
    }

    // ─── WELL_KNOWN_DOWNLOAD_FAILED ───────────────────────────────────────────

    @Test
    fun testWellKnownDownloadFailedTopic() {
        assertEquals("engine_notification_well_known_download_failed", EngineNotifications.WELL_KNOWN_DOWNLOAD_FAILED)
    }

    @Test
    fun testWellKnownDownloadFailedServerKey() {
        assertEquals("server", EngineNotifications.WELL_KNOWN_DOWNLOAD_FAILED_SERVER_KEY)
    }

    // ─── MUTUAL_SCAN_CONTACT_ADDED ────────────────────────────────────────────

    @Test
    fun testMutualScanContactAddedTopic() {
        assertEquals("engine_notification_mutual_scan_contact_added", EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED)
    }

    @Test
    fun testMutualScanContactAddedBytesOwnedIdentityKey() {
        // Note: source constant name has a typo "IDENTITIY" — the wire value is preserved as-is.
        assertEquals("bytes_owned_identity", EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_BYTES_OWNED_IDENTITIY_KEY)
    }

    @Test
    fun testMutualScanContactAddedBytesContactIdentityKey() {
        // Note: source constant name has a typo "IDENTITIY" — the wire value is preserved as-is.
        assertEquals("bytes_contact_identity", EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_BYTES_CONTACT_IDENTITIY_KEY)
    }

    @Test
    fun testMutualScanContactAddedSignatureKey() {
        assertEquals("signature", EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY)
    }

    // ─── APP_BACKUP_REQUESTED ─────────────────────────────────────────────────

    @Test
    fun testAppBackupRequestedTopic() {
        assertEquals("engine_notification_app_backup_requested", EngineNotifications.APP_BACKUP_REQUESTED)
    }

    @Test
    fun testAppBackupRequestedBytesBackupKeyUidKey() {
        assertEquals("bytes_backup_key_uid", EngineNotifications.APP_BACKUP_REQUESTED_BYTES_BACKUP_KEY_UID_KEY)
    }

    @Test
    fun testAppBackupRequestedVersionKey() {
        assertEquals("version", EngineNotifications.APP_BACKUP_REQUESTED_VERSION_KEY)
    }

    // ─── ENGINE_BACKUP_RESTORATION_FINISHED ──────────────────────────────────

    @Test
    fun testEngineBackupRestorationFinishedTopic() {
        assertEquals("engine_notification_engine_backup_restoration_finished", EngineNotifications.ENGINE_BACKUP_RESTORATION_FINISHED)
    }

    // ─── ENGINE_SNAPSHOT_RESTORATION_FINISHED ────────────────────────────────

    @Test
    fun testEngineSnapshotRestorationFinishedTopic() {
        assertEquals("engine_notification_engine_snapshot_restoration_finished", EngineNotifications.ENGINE_SNAPSHOT_RESTORATION_FINISHED)
    }

    // ─── PING_LOST ────────────────────────────────────────────────────────────

    @Test
    fun testPingLostTopic() {
        assertEquals("engine_notification_ping_lost", EngineNotifications.PING_LOST)
    }

    // ─── PING_RECEIVED ────────────────────────────────────────────────────────

    @Test
    fun testPingReceivedTopic() {
        assertEquals("engine_notification_ping_received", EngineNotifications.PING_RECEIVED)
    }

    @Test
    fun testPingReceivedDelayKey() {
        assertEquals("delay", EngineNotifications.PING_RECEIVED_DELAY_KEY)
    }

    // ─── WEBSOCKET_CONNECTION_STATE_CHANGED ───────────────────────────────────

    @Test
    fun testWebsocketConnectionStateChangedTopic() {
        assertEquals("engine_notification_websocket_connection_state_changed", EngineNotifications.WEBSOCKET_CONNECTION_STATE_CHANGED)
    }

    @Test
    fun testWebsocketConnectionStateChangedStateKey() {
        assertEquals("state", EngineNotifications.WEBSOCKET_CONNECTION_STATE_CHANGED_STATE_KEY)
    }

    // ─── WEBSOCKET_DETECTED_SOME_NETWORK ─────────────────────────────────────

    @Test
    fun testWebsocketDetectedSomeNetworkTopic() {
        assertEquals("engine_notification_websocket_detected_some_network", EngineNotifications.WEBSOCKET_DETECTED_SOME_NETWORK)
    }

    // ─── CONTACT_CAPABILITIES_UPDATED ────────────────────────────────────────

    @Test
    fun testContactCapabilitiesUpdatedTopic() {
        assertEquals("engine_notification_contact_capabilities_updated", EngineNotifications.CONTACT_CAPABILITIES_UPDATED)
    }

    @Test
    fun testContactCapabilitiesUpdatedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactCapabilitiesUpdatedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_CAPABILITIES_UPDATED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactCapabilitiesUpdatedCapabilities() {
        assertEquals("capabilities", EngineNotifications.CONTACT_CAPABILITIES_UPDATED_CAPABILITIES)
    }

    // ─── OWN_CAPABILITIES_UPDATED ────────────────────────────────────────────

    @Test
    fun testOwnCapabilitiesUpdatedTopic() {
        assertEquals("engine_notification_own_capabilities_updated", EngineNotifications.OWN_CAPABILITIES_UPDATED)
    }

    @Test
    fun testOwnCapabilitiesUpdatedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWN_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testOwnCapabilitiesUpdatedCapabilities() {
        assertEquals("capabilities", EngineNotifications.OWN_CAPABILITIES_UPDATED_CAPABILITIES)
    }

    // ─── CONTACT_ONE_TO_ONE_CHANGED ───────────────────────────────────────────

    @Test
    fun testContactOneToOneChangedTopic() {
        assertEquals("engine_notification_contact_one_to_one_changed", EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED)
    }

    @Test
    fun testContactOneToOneChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactOneToOneChangedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactOneToOneChangedOneToOneKey() {
        assertEquals("one_to_one", EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY)
    }

    // ─── CONTACT_RECENTLY_ONLINE_CHANGED ─────────────────────────────────────

    @Test
    fun testContactRecentlyOnlineChangedTopic() {
        assertEquals("engine_notification_contact_recently_online_changed", EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED)
    }

    @Test
    fun testContactRecentlyOnlineChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactRecentlyOnlineChangedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactRecentlyOnlineChangedRecentlyOnlineKey() {
        assertEquals("recently_online", EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_RECENTLY_ONLINE_KEY)
    }

    // ─── CONTACT_TRUST_LEVEL_INCREASED ───────────────────────────────────────

    @Test
    fun testContactTrustLevelIncreasedTopic() {
        assertEquals("engine_notification_contact_trust_level_increased", EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED)
    }

    @Test
    fun testContactTrustLevelIncreasedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactTrustLevelIncreasedBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactTrustLevelIncreasedTrustLevelKey() {
        assertEquals("trust_level", EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_TRUST_LEVEL_KEY)
    }

    // ─── GROUP_V2_CREATED_OR_UPDATED ──────────────────────────────────────────

    @Test
    fun testGroupV2CreatedOrUpdatedTopic() {
        assertEquals("engine_notification_group_v2_created_or_updated", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedGroupKey() {
        assertEquals("group", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_GROUP_KEY)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedNewGroupKey() {
        assertEquals("new_group", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_NEW_GROUP_KEY)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedByMeKey() {
        assertEquals("by_me", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_ME_KEY)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedByKey() {
        assertEquals("by", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_KEY)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedGroupLeaversKey() {
        assertEquals("group_leavers", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_GROUP_LEAVERS_KEY)
    }

    @Test
    fun testGroupV2CreatedOrUpdatedCreatedOnOtherDevice() {
        assertEquals("created_on_other_device", EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_CREATED_ON_OTHER_DEVICE)
    }

    // ─── GROUP_V2_PHOTO_CHANGED ───────────────────────────────────────────────

    @Test
    fun testGroupV2PhotoChangedTopic() {
        assertEquals("engine_notification_group_v2_photo_changed", EngineNotifications.GROUP_V2_PHOTO_CHANGED)
    }

    @Test
    fun testGroupV2PhotoChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_V2_PHOTO_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupV2PhotoChangedBytesGroupIdentifierKey() {
        assertEquals("bytes_group_identifier", EngineNotifications.GROUP_V2_PHOTO_CHANGED_BYTES_GROUP_IDENTIFIER_KEY)
    }

    // ─── GROUP_V2_UPDATE_IN_PROGRESS_CHANGED ─────────────────────────────────

    @Test
    fun testGroupV2UpdateInProgressChangedTopic() {
        assertEquals("engine_notification_group_v2_update_in_progress_changed", EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED)
    }

    @Test
    fun testGroupV2UpdateInProgressChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupV2UpdateInProgressChangedBytesGroupIdentifierKey() {
        assertEquals("bytes_group_identifier", EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_GROUP_IDENTIFIER_KEY)
    }

    @Test
    fun testGroupV2UpdateInProgressChangedUpdatingKey() {
        assertEquals("updating", EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_UPDATING_KEY)
    }

    @Test
    fun testGroupV2UpdateInProgressChangedCreatingKey() {
        assertEquals("creating", EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_CREATING_KEY)
    }

    // ─── GROUP_V2_DELETED ─────────────────────────────────────────────────────

    @Test
    fun testGroupV2DeletedTopic() {
        assertEquals("engine_notification_group_v2_deleted", EngineNotifications.GROUP_V2_DELETED)
    }

    @Test
    fun testGroupV2DeletedBytesOwnedIdentity() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_V2_DELETED_BYTES_OWNED_IDENTITY)
    }

    @Test
    fun testGroupV2DeletedBytesGroupIdentifierKey() {
        assertEquals("bytes_group_identifier", EngineNotifications.GROUP_V2_DELETED_BYTES_GROUP_IDENTIFIER_KEY)
    }

    @Test
    fun testGroupV2DeletedDeletedByKey() {
        assertEquals("deleted_by", EngineNotifications.GROUP_V2_DELETED_DELETED_BY_KEY)
    }

    // ─── GROUP_V2_UPDATE_FAILED ───────────────────────────────────────────────

    @Test
    fun testGroupV2UpdateFailedTopic() {
        assertEquals("engine_notification_group_v2_update_failed", EngineNotifications.GROUP_V2_UPDATE_FAILED)
    }

    @Test
    fun testGroupV2UpdateFailedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.GROUP_V2_UPDATE_FAILED_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testGroupV2UpdateFailedBytesGroupIdentifierKey() {
        assertEquals("bytes_group_identifier", EngineNotifications.GROUP_V2_UPDATE_FAILED_BYTES_GROUP_IDENTIFIER_KEY)
    }

    @Test
    fun testGroupV2UpdateFailedErrorKey() {
        assertEquals("error", EngineNotifications.GROUP_V2_UPDATE_FAILED_ERROR_KEY)
    }

    // ─── PUSH_TOPIC_NOTIFIED ──────────────────────────────────────────────────

    @Test
    fun testPushTopicNotifiedTopic() {
        assertEquals("engine_notification_push_topic_notified", EngineNotifications.PUSH_TOPIC_NOTIFIED)
    }

    @Test
    fun testPushTopicNotifiedTopicKey() {
        assertEquals("topic", EngineNotifications.PUSH_TOPIC_NOTIFIED_TOPIC_KEY)
    }

    // ─── KEYCLOAK_UPDATE_REQUIRED ─────────────────────────────────────────────

    @Test
    fun testKeycloakUpdateRequiredTopic() {
        assertEquals("engine_notification_keycloak_update_required", EngineNotifications.KEYCLOAK_UPDATE_REQUIRED)
    }

    @Test
    fun testKeycloakUpdateRequiredBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.KEYCLOAK_UPDATE_REQUIRED_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── KEYCLOAK_GROUP_V2_SHARED_SETTINGS ───────────────────────────────────

    @Test
    fun testKeycloakGroupV2SharedSettingsTopic() {
        assertEquals("engine_notification_keycloak_group_v2_shared_settings", EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS)
    }

    @Test
    fun testKeycloakGroupV2SharedSettingsBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testKeycloakGroupV2SharedSettingsBytesGroupIdentifierKey() {
        assertEquals("bytes_group_identifier", EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_GROUP_IDENTIFIER_KEY)
    }

    @Test
    fun testKeycloakGroupV2SharedSettingsSharedSettingsKey() {
        assertEquals("shared_settings", EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SHARED_SETTINGS_KEY)
    }

    @Test
    fun testKeycloakGroupV2SharedSettingsModificationTimestampKey() {
        assertEquals("timestamp", EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY)
    }

    // ─── OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE ───────────────────────────

    @Test
    fun testOwnedIdentityDeletedFromAnotherDeviceTopic() {
        assertEquals("engine_notification_owned_identity_deleted_from_another_device", EngineNotifications.OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE)
    }

    @Test
    fun testOwnedIdentityDeletedFromAnotherDeviceBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── OWNED_IDENTITY_DEVICE_LIST_CHANGED ──────────────────────────────────

    @Test
    fun testOwnedIdentityDeviceListChangedTopic() {
        assertEquals("engine_notification_owned_identity_device_list_changed", EngineNotifications.OWNED_IDENTITY_DEVICE_LIST_CHANGED)
    }

    @Test
    fun testOwnedIdentityDeviceListChangedBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_DEVICE_LIST_CHANGED_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── KEYCLOAK_SYNCHRONIZATION_REQUIRED ───────────────────────────────────

    @Test
    fun testKeycloakSynchronizationRequiredTopic() {
        assertEquals("engine_notification_keycloak_synchronization_required", EngineNotifications.KEYCLOAK_SYNCHRONIZATION_REQUIRED)
    }

    @Test
    fun testKeycloakSynchronizationRequiredBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.KEYCLOAK_SYNCHRONIZATION_REQUIRED_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── CONTACT_INTRODUCTION_INVITATION_SENT ────────────────────────────────

    @Test
    fun testContactIntroductionInvitationSentTopic() {
        assertEquals("engine_notification_contact_introduction_invitation_sent", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT)
    }

    @Test
    fun testContactIntroductionInvitationSentBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactIntroductionInvitationSentBytesContactIdentityAKey() {
        assertEquals("bytes_contact_identity_a", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_A_KEY)
    }

    @Test
    fun testContactIntroductionInvitationSentBytesContactIdentityBKey() {
        assertEquals("bytes_contact_identity_b", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_B_KEY)
    }

    // ─── CONTACT_INTRODUCTION_INVITATION_RESPONSE ────────────────────────────

    @Test
    fun testContactIntroductionInvitationResponseTopic() {
        assertEquals("engine_notification_contact_introduction_invitation_response", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE)
    }

    @Test
    fun testContactIntroductionInvitationResponseBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testContactIntroductionInvitationResponseBytesMediatorIdentityKey() {
        assertEquals("bytes_mediator_identity", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_MEDIATOR_IDENTITY_KEY)
    }

    @Test
    fun testContactIntroductionInvitationResponseBytesContactIdentityKey() {
        assertEquals("bytes_contact_identity", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_CONTACT_IDENTITY_KEY)
    }

    @Test
    fun testContactIntroductionInvitationResponseContactSerializedDetailsKey() {
        assertEquals("contact_serialized_Details", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY)
    }

    @Test
    fun testContactIntroductionInvitationResponseAcceptedKey() {
        assertEquals("accepted", EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY)
    }

    // ─── PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE ─────────────────────

    @Test
    fun testPushRegisterFailedBadDeviceUidToReplaceTopic() {
        assertEquals("engine_notification_push_register_failed_bad_device_uid_to_replace", EngineNotifications.PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE)
    }

    @Test
    fun testPushRegisterFailedBadDeviceUidToReplaceBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.PUSH_REGISTER_FAILED_BAD_DEVICE_UID_TO_REPLACE_BYTES_OWNED_IDENTITY_KEY)
    }

    // ─── OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER ────────────────────────────

    @Test
    fun testOwnedIdentitySynchronizingWithServerTopic() {
        assertEquals("engine_notification_owned_identity_synchronizing_with_server", EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER)
    }

    @Test
    fun testOwnedIdentitySynchronizingWithServerBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_BYTES_OWNED_IDENTITY_KEY)
    }

    @Test
    fun testOwnedIdentitySynchronizingWithServerStatusKey() {
        assertEquals("status", EngineNotifications.OWNED_IDENTITY_SYNCHRONIZING_WITH_SERVER_STATUS_KEY)
    }

    // ─── OWNED_DEVICE_DISCOVERY_DONE ─────────────────────────────────────────

    @Test
    fun testOwnedDeviceDiscoveryDoneTopic() {
        assertEquals("engine_notification_owned_device_discovery_done", EngineNotifications.OWNED_DEVICE_DISCOVERY_DONE)
    }

    @Test
    fun testOwnedDeviceDiscoveryDoneBytesOwnedIdentityKey() {
        assertEquals("bytes_owned_identity", EngineNotifications.OWNED_DEVICE_DISCOVERY_DONE_BYTES_OWNED_IDENTITY_KEY)
    }
}
