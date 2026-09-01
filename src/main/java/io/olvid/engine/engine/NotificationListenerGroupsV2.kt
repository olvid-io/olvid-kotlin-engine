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
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.notification.NotificationManager

class NotificationListenerGroupsV2(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED,
            IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED,
            IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED,
            IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED,
            IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED,
            IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS,
            IdentityNotifications.NOTIFICATION_NEW_KEYCLOAK_GROUP_V2_PUSH_TOPIC,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED -> {
                try {
                    engine.getSession().use { engineSession ->
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_OWNED_IDENTITY_KEY) as? Identity?
                        val createdBy =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_BY_KEY) as? Identity?
                        val groupIdentifier =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                        val createdByMe =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_CREATED_BY_ME_KEY) as? Boolean?
                        val createdOnOtherDevice =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_CREATED_ON_OTHER_DEVICE_KEY) as? Boolean?
                        if (ownedIdentity == null || groupIdentifier == null || createdByMe == null || createdOnOtherDevice == null) {
                            return
                        }

                        val obvGroupV2 = engine.identityManager.getObvGroupV2(
                            engineSession.session,
                            ownedIdentity,
                            groupIdentifier
                        ) ?: return

                        val engineInfo = HashMap<String, Any?>()
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_GROUP_KEY] =
                            obvGroupV2
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_NEW_GROUP_KEY] =
                            createdByMe
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_ME_KEY] =
                            createdByMe
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_CREATED_ON_OTHER_DEVICE] =
                            createdOnOtherDevice
                        if (createdBy != null) {
                            engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_KEY] =
                                createdBy.getBytes()
                        }
                        engine.postEngineNotification(
                            EngineNotifications.GROUP_V2_CREATED_OR_UPDATED,
                            engineInfo
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED -> {
                try {
                    engine.getSession().use { engineSession ->
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                        val groupIdentifier =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                        val updatedByMe =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_BY_ME_KEY) as? Boolean?
                        val updatedBy =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_BY_KEY) as? Identity?
                        val groupLeavers =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_UPDATED_GROUP_LEAVERS_KEY) as? MutableList<Identity>?
                        if (ownedIdentity == null || groupIdentifier == null || updatedByMe == null) {
                            return
                        }

                        val obvGroupV2 = engine.identityManager.getObvGroupV2(
                            engineSession.session,
                            ownedIdentity,
                            groupIdentifier
                        ) ?: return

                        val engineInfo = HashMap<String, Any?>()
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_GROUP_KEY] =
                            obvGroupV2
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_NEW_GROUP_KEY] =
                            false
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_ME_KEY] =
                            updatedByMe
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_BY_KEY] =
                            updatedBy?.getBytes()
                        if (groupLeavers != null) {
                            val leavers = arrayOfNulls<ByteArray>(groupLeavers.size)
                            var i = 0
                            while (i < groupLeavers.size) {
                                leavers[i] = groupLeavers[i].getBytes()
                                i++
                            }
                            engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_GROUP_LEAVERS_KEY] = leavers
                        }
                        engineInfo[EngineNotifications.GROUP_V2_CREATED_OR_UPDATED_CREATED_ON_OTHER_DEVICE] = false
                        engine.postEngineNotification(
                            EngineNotifications.GROUP_V2_CREATED_OR_UPDATED,
                            engineInfo
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                val groupIdentifier =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_PHOTO_UPDATED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                if (ownedIdentity == null || groupIdentifier == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_V2_PHOTO_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_V2_PHOTO_CHANGED_BYTES_GROUP_IDENTIFIER_KEY] =
                    groupIdentifier.bytes
                engine.postEngineNotification(
                    EngineNotifications.GROUP_V2_PHOTO_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val groupIdentifier =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                val frozen =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_FROZEN_KEY) as? Boolean?
                val newGroup =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_FROZEN_CHANGED_NEW_GROUP_KEY) as? Boolean?
                if ((ownedIdentity == null) || (groupIdentifier == null) || (frozen == null) || (newGroup == null)) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_BYTES_GROUP_IDENTIFIER_KEY] =
                    groupIdentifier.bytes
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_UPDATING_KEY] =
                    frozen
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED_CREATING_KEY] =
                    newGroup
                engine.postEngineNotification(
                    EngineNotifications.GROUP_V2_UPDATE_IN_PROGRESS_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_OWNED_IDENTITY_KEY) as? Identity?
                val groupIdentifier =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                val deletedBy =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_V2_DELETED_DELETED_BY_KEY) as? Identity?
                if ((ownedIdentity == null) || (groupIdentifier == null)) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_V2_DELETED_BYTES_OWNED_IDENTITY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_V2_DELETED_BYTES_GROUP_IDENTIFIER_KEY] =
                    groupIdentifier.bytes
                if (deletedBy != null) {
                    engineInfo[EngineNotifications.GROUP_V2_DELETED_DELETED_BY_KEY] = deletedBy.getBytes()
                }
                engine.postEngineNotification(EngineNotifications.GROUP_V2_DELETED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_OWNED_IDENTITY_KEY) as? Identity?
                val groupIdentifier =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                val serializedSharedSettings =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SERIALIZED_SHARED_SETTINGS_KEY) as? String?
                val latestModificationTimestamp =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY) as? Long?

                if (ownedIdentity == null || groupIdentifier == null || latestModificationTimestamp == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_BYTES_GROUP_IDENTIFIER_KEY] =
                    groupIdentifier.bytes
                engineInfo[EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_SHARED_SETTINGS_KEY] =
                    serializedSharedSettings
                engineInfo[EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS_MODIFICATION_TIMESTAMP_KEY] =
                    latestModificationTimestamp

                engine.postEngineNotification(
                    EngineNotifications.KEYCLOAK_GROUP_V2_SHARED_SETTINGS,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_NEW_KEYCLOAK_GROUP_V2_PUSH_TOPIC -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_KEYCLOAK_GROUP_V2_SHARED_SETTINGS_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                engine.fetchManager.forceRegisterPushNotification(ownedIdentity, false)
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
