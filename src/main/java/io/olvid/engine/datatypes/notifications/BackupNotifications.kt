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

object BackupNotifications {
    const val NOTIFICATION_NEW_BACKUP_SEED_GENERATED = "backup_notification_new_backup_seed_generated"
    const val NOTIFICATION_NEW_BACKUP_SEED_GENERATED_SEED_KEY = "seed"

    const val NOTIFICATION_BACKUP_SEED_GENERATION_FAILED = "backup_notification_backup_seed_generation_failed"

    const val NOTIFICATION_BACKUP_VERIFICATION_SUCCESSFUL = "backup_notification_backup_verification_successful"

    const val NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED = "backup_notification_backup_for_export_finished"
    const val NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_BACKUP_KEY_UID_KEY = "backup_key_uid" // UID
    const val NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY = "version" // int
    const val NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY = "encrypted_content" // byte[]

    const val NOTIFICATION_BACKUP_FINISHED = "backup_notification_backup_finished"
    const val NOTIFICATION_BACKUP_FINISHED_BACKUP_KEY_UID_KEY = "backup_key_uid" // UID
    const val NOTIFICATION_BACKUP_FINISHED_VERSION_KEY = "version" // int
    const val NOTIFICATION_BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY = "encrypted_content" // byte[]

    const val NOTIFICATION_BACKUP_FOR_EXPORT_FAILED = "backup_notification_backup_for_export_failed"

    const val NOTIFICATION_APP_BACKUP_INITIATION_REQUEST = "backup_notification_app_backup_initiation_request"
    const val NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_BACKUP_KEY_UID_KEY = "backup_uid"
    const val NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_VERSION_KEY = "version"

    const val NOTIFICATION_BACKUP_RESTORATION_FINISHED = "backup_notification_backup_restoration_finished"

    const val NOTIFICATION_DEVICE_BACKUP_NEEDED = "backup_notification_device_backup_needed"

    const val NOTIFICATION_PROFILE_BACKUP_NEEDED = "backup_notification_profile_backup_needed"
    const val NOTIFICATION_PROFILE_BACKUP_NEEDED_OWNED_IDENTITY = "owned_identity" // Identity
}
