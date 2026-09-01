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


object ProtocolNotifications {
    const val NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED = "protocol_manager_notification_mutual_scan_contact_added"
    const val NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_CONTACT_IDENTITY_KEY = "contact_identity" // Identity
    const val NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY = "nonce" // byte[]

    const val NOTIFICATION_GROUP_V2_UPDATE_FAILED = "protocol_manager_notification_group_v2_update_failed"
    const val NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY = "group_identifier" // GroupV2.Identifier
    const val NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY = "error" // boolean: true indicates there was an error, false that there was no change to publish

    const val NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE = "protocol_manager_notification_owned_identity_deleted_from_another_device"
    const val NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED = "protocol_manager_notification_keycloak_synchronization_required"
    const val NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED_OWNED_IDENTITY_KEY = "owned_identity" // Identity

    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT = "protocol_manager_notification_contact_introduction_invitation_sent"
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_A_KEY = "contact_identity_a" // Identity
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_B_KEY = "contact_identity_b" // Identity

    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE = "protocol_manager_notification_contact_introduction_invitation_response"
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_OWNED_IDENTITY_KEY = "owned_identity" // Identity
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_MEDIATOR_IDENTITY_KEY = "mediator_identity" // Identity
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_IDENTITY_KEY = "contact_identity" // Identity
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY = "contact_serialized_details" // String
    const val NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY = "accepted" // boolean

    const val NOTIFICATION_SNAPSHOT_RESTORATION_FINISHED = "protocol_manager_notification_snapshot_restoration_finished"

    const val NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE = "protocol_manager_notification_owned_device_discovery_done"
    const val NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE_OWNED_IDENTITY_KEY = "owned_identity" // Identity
}
