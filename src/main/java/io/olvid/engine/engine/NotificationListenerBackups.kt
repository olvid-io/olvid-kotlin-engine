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
import io.olvid.engine.datatypes.NotificationListener
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.notifications.BackupNotifications
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.notification.NotificationManager

class NotificationListenerBackups(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            BackupNotifications.NOTIFICATION_NEW_BACKUP_SEED_GENERATED,
            BackupNotifications.NOTIFICATION_BACKUP_SEED_GENERATION_FAILED,
            BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED,
            BackupNotifications.NOTIFICATION_BACKUP_FINISHED,
            BackupNotifications.NOTIFICATION_BACKUP_VERIFICATION_SUCCESSFUL,
            BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FAILED,
            BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST,
            BackupNotifications.NOTIFICATION_BACKUP_RESTORATION_FINISHED,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            BackupNotifications.NOTIFICATION_NEW_BACKUP_SEED_GENERATED -> {
                val seed =
                    userInfo?.get(BackupNotifications.NOTIFICATION_NEW_BACKUP_SEED_GENERATED_SEED_KEY) as? String?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_BACKUP_SEED_GENERATED_SEED_KEY] = seed

                engine.postEngineNotification(
                    EngineNotifications.NEW_BACKUP_SEED_GENERATED,
                    engineInfo
                )
            }

            BackupNotifications.NOTIFICATION_BACKUP_SEED_GENERATION_FAILED -> {
                engine.postEngineNotification(
                    EngineNotifications.BACKUP_SEED_GENERATION_FAILED,
                    HashMap()
                )
            }

            BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED -> {
                val backupKeyUid =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_BACKUP_KEY_UID_KEY) as UID?
                val version =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY) as? Int?
                val encryptedContent =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY) as? ByteArray?

                if (backupKeyUid == null || version == null || encryptedContent == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_BYTES_BACKUP_KEY_UID_KEY] =
                    backupKeyUid.bytes
                engineInfo[EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_VERSION_KEY] = version
                engineInfo[EngineNotifications.BACKUP_FOR_EXPORT_FINISHED_ENCRYPTED_CONTENT_KEY] =
                    encryptedContent

                engine.postEngineNotification(
                    EngineNotifications.BACKUP_FOR_EXPORT_FINISHED,
                    engineInfo
                )
            }

            BackupNotifications.NOTIFICATION_BACKUP_FINISHED -> {
                val backupKeyUid =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FINISHED_BACKUP_KEY_UID_KEY) as? UID?
                val version =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FINISHED_VERSION_KEY) as? Int?
                val encryptedContent =
                    userInfo?.get(BackupNotifications.NOTIFICATION_BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY) as? ByteArray?

                if (backupKeyUid == null || version == null || encryptedContent == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.BACKUP_FINISHED_BYTES_BACKUP_KEY_UID_KEY] =
                    backupKeyUid.bytes
                engineInfo[EngineNotifications.BACKUP_FINISHED_VERSION_KEY] = version
                engineInfo[EngineNotifications.BACKUP_FINISHED_ENCRYPTED_CONTENT_KEY] =
                    encryptedContent

                engine.postEngineNotification(EngineNotifications.BACKUP_FINISHED, engineInfo)
            }

            BackupNotifications.NOTIFICATION_BACKUP_VERIFICATION_SUCCESSFUL -> {
                engine.postEngineNotification(
                    EngineNotifications.BACKUP_KEY_VERIFICATION_SUCCESSFUL,
                    HashMap()
                )
            }

            BackupNotifications.NOTIFICATION_BACKUP_FOR_EXPORT_FAILED -> {
                engine.postEngineNotification(
                    EngineNotifications.BACKUP_FOR_EXPORT_FAILED,
                    HashMap()
                )
            }

            BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST -> {
                val backupKeyUid =
                    userInfo?.get(BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_BACKUP_KEY_UID_KEY) as? UID?
                val version =
                    userInfo?.get(BackupNotifications.NOTIFICATION_APP_BACKUP_INITIATION_REQUEST_VERSION_KEY) as? Int?
                if (backupKeyUid == null || version == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.APP_BACKUP_REQUESTED_BYTES_BACKUP_KEY_UID_KEY] =
                    backupKeyUid.bytes
                engineInfo[EngineNotifications.APP_BACKUP_REQUESTED_VERSION_KEY] = version

                engine.postEngineNotification(EngineNotifications.APP_BACKUP_REQUESTED, engineInfo)
            }

            BackupNotifications.NOTIFICATION_BACKUP_RESTORATION_FINISHED -> {
                engine.postEngineNotification(
                    EngineNotifications.ENGINE_BACKUP_RESTORATION_FINISHED,
                    HashMap()
                )
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
