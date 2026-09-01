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
import io.olvid.engine.datatypes.notifications.UploadNotifications
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.notification.NotificationManager

class NotificationListenerUploads(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS,
            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED,
            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED,
            UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED,
            UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS -> {
                val ownedIdentity =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY) as? Int?
                val progress =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY) as? Float?
                val speed =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_SPEED_BPS_KEY) as? Float?
                val eta =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_PROGRESS_ETA_SECONDS_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null || progress == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_MESSAGE_IDENTIFIER_KEY] =
                    messageUid.bytes
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_ATTACHMENT_NUMBER_KEY] =
                    attachmentNumber
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_PROGRESS_KEY] = progress
                if (speed != null && eta != null) {
                    engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_SPEED_BPS_KEY] = speed
                    engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS_ETA_SECONDS_KEY] = eta
                }

                engine.postEngineNotification(
                    EngineNotifications.ATTACHMENT_UPLOAD_PROGRESS,
                    engineInfo
                )
            }

            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED -> {
                val ownedIdentity =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_FINISHED_ATTACHMENT_NUMBER_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOADED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOADED_MESSAGE_IDENTIFIER_KEY] =
                    messageUid.bytes
                engineInfo[EngineNotifications.ATTACHMENT_UPLOADED_ATTACHMENT_NUMBER_KEY] =
                    attachmentNumber

                engine.postEngineNotification(EngineNotifications.ATTACHMENT_UPLOADED, engineInfo)
            }

            UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED -> {
                val ownedIdentity =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_MESSAGE_UID_KEY) as? UID?
                val attachmentNumber =
                    userInfo?.get(UploadNotifications.NOTIFICATION_ATTACHMENT_UPLOAD_CANCELLED_ATTACHMENT_NUMBER_KEY) as? Int?
                if (ownedIdentity == null || messageUid == null || attachmentNumber == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_MESSAGE_IDENTIFIER_KEY] =
                    messageUid.bytes
                engineInfo[EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED_ATTACHMENT_NUMBER_KEY] =
                    attachmentNumber

                engine.postEngineNotification(
                    EngineNotifications.ATTACHMENT_UPLOAD_CANCELLED,
                    engineInfo
                )
            }

            UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED -> {
                val ownedIdentity =
                    userInfo?.get(UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_UID_KEY) as? UID?
                val timestampFromServer =
                    userInfo?.get(UploadNotifications.NOTIFICATION_MESSAGE_UPLOADED_TIMESTAMP_FROM_SERVER) as? Long?
                if (ownedIdentity == null || messageUid == null || timestampFromServer == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.MESSAGE_UPLOADED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.MESSAGE_UPLOADED_IDENTIFIER_KEY] = messageUid.bytes
                engineInfo[EngineNotifications.MESSAGE_UPLOADED_TIMESTAMP_FROM_SERVER] =
                    timestampFromServer

                engine.postEngineNotification(EngineNotifications.MESSAGE_UPLOADED, engineInfo)
            }

            UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                val messageUid =
                    userInfo?.get(UploadNotifications.NOTIFICATION_MESSAGE_UPLOAD_FAILED_UID_KEY) as? UID?
                if (ownedIdentity == null || messageUid == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.MESSAGE_UPLOAD_FAILED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.MESSAGE_UPLOAD_FAILED_IDENTIFIER_KEY] = messageUid.bytes

                engine.postEngineNotification(EngineNotifications.MESSAGE_UPLOAD_FAILED, engineInfo)
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
