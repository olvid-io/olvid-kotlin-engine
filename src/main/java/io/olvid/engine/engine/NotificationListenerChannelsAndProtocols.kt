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
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelDialogMessageToSend
import io.olvid.engine.datatypes.containers.DialogType
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.notifications.ChannelNotifications
import io.olvid.engine.datatypes.notifications.ProtocolNotifications
import io.olvid.engine.engine.databases.UserInterfaceDialog
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.notification.NotificationManager

class NotificationListenerChannelsAndProtocols(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG,
            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED,
            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED,
            ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED,
            ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED,
            ProtocolNotifications.NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE,
            ProtocolNotifications.NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED,
            ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT,
            ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE,
            ProtocolNotifications.NOTIFICATION_SNAPSHOT_RESTORATION_FINISHED,
            ProtocolNotifications.NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG -> {
                try {
                    val session =
                        userInfo?.get(ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG_SESSION_KEY) as? Session
                    val channelDialogMessageToSend =
                        userInfo?.get(ChannelNotifications.NOTIFICATION_NEW_UI_DIALOG_CHANNEL_DIALOG_MESSAGE_TO_SEND_KEY) as? ChannelDialogMessageToSend?
                    if (session == null || channelDialogMessageToSend == null) {
                        return
                    }
                    // check whether it is a new/updated dialog, or a delete dialog
                    if (channelDialogMessageToSend.sendChannelInfo?.getDialogType()?.id == DialogType.DELETE_DIALOG_ID) {
                        val userInterfaceDialog: UserInterfaceDialog? =
                            UserInterfaceDialog.get(
                                engine.wrapSession(session),
                                channelDialogMessageToSend.sendChannelInfo.getDialogUuid()
                            )
                        if (userInterfaceDialog != null) {
                            // Only delete if the version still matches the dialog we were asked to delete.
                            // version == 0 means unknown/legacy → delete unconditionally (preserves the
                            // previous behavior). On mismatch the dialog was already replaced by a newer
                            // one (e.g. a double-answered dialog) and must not be deleted.
                            val version = channelDialogMessageToSend.sendChannelInfo.getDialogType()?.getVersion()
                            if (version == 0L || userInterfaceDialog.getCreationTimestamp() == version) {
                                userInterfaceDialog.delete()
                            }
                        }
                    } else {
                        UserInterfaceDialog.createOrReplace(
                            engine.wrapSession(session),
                            engine.createDialog(channelDialogMessageToSend)
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED -> {
                try {
                    engine.getSession().use { engineSession ->
                        val contactIdentity =
                            userInfo?.get(ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_IDENTITY_KEY) as? Identity?
                        val contactDeviceUid =
                            userInfo?.get(ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_REMOTE_DEVICE_UID__KEY) as? UID?
                        val currentDeviceUid =
                            userInfo?.get(ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_CONFIRMED_CURRENT_DEVICE_UID_KEY) as? UID?
                        if (contactIdentity == null || currentDeviceUid == null || contactDeviceUid == null) {
                            return
                        }

                        val engineInfo = HashMap<String, Any?>()
                        val ownedIdentity = engine.identityManager.getOwnedIdentityForCurrentDeviceUid(
                                engineSession.session,
                                currentDeviceUid
                            ) ?: return
                        engineInfo[EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_OWNED_IDENTITY_KEY] =
                            ownedIdentity.getBytes()
                        engineInfo[EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_CONTACT_IDENTITY_KEY] =
                            contactIdentity.getBytes()
                        engineInfo[EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_CONTACT_DEVICE_UID_KEY] =
                            contactDeviceUid.bytes
                        engine.postEngineNotification(
                            EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED,
                            engineInfo
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED -> {
                try {
                    engine.getSession().use { engineSession ->
                        val contactIdentity =
                            userInfo?.get(ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_REMOTE_IDENTITY_KEY) as? Identity?
                        val currentDeviceUid =
                            userInfo?.get(ChannelNotifications.NOTIFICATION_OBLIVIOUS_CHANNEL_DELETED_CURRENT_DEVICE_UID_KEY) as? UID?
                        if (contactIdentity == null || currentDeviceUid == null) {
                            return
                        }

                        val engineInfo = HashMap<String, Any?>()
                        val ownedIdentity =
                            engine.identityManager.getOwnedIdentityForCurrentDeviceUid(
                                engineSession.session,
                                currentDeviceUid
                            ) ?: return
                        engineInfo[EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_OWNED_IDENTITY_KEY] =
                            ownedIdentity.getBytes()
                        engineInfo[EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED_CONTACT_IDENTITY_KEY] =
                            contactIdentity.getBytes()
                        engine.postEngineNotification(
                            EngineNotifications.CHANNEL_CONFIRMED_OR_DELETED,
                            engineInfo
                        )
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_CONTACT_IDENTITY_KEY) as? Identity?
                val signature =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY) as? ByteArray?

                if (ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_BYTES_OWNED_IDENTITIY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_BYTES_CONTACT_IDENTITIY_KEY] =
                    contactIdentity.getBytes()
                if (signature != null) {
                    engineInfo[EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED_SIGNATURE_KEY] =
                        signature
                }

                engine.postEngineNotification(
                    EngineNotifications.MUTUAL_SCAN_CONTACT_ADDED,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_OWNED_IDENTITY_KEY) as? Identity?
                val groupIdentifier =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_GROUP_IDENTIFIER_KEY) as? GroupV2.Identifier?
                val error =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_GROUP_V2_UPDATE_FAILED_ERROR_KEY) as? Boolean?

                if (ownedIdentity == null || groupIdentifier == null || error == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_FAILED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_FAILED_BYTES_GROUP_IDENTIFIER_KEY] =
                    groupIdentifier.bytes
                engineInfo[EngineNotifications.GROUP_V2_UPDATE_FAILED_ERROR_KEY] = error

                engine.postEngineNotification(
                    EngineNotifications.GROUP_V2_UPDATE_FAILED,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_DELETED_FROM_ANOTHER_DEVICE,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_KEYCLOAK_SYNCHRONIZATION_REQUIRED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.KEYCLOAK_SYNCHRONIZATION_REQUIRED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.KEYCLOAK_SYNCHRONIZATION_REQUIRED,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentityA =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_A_KEY) as? Identity?
                val contactIdentityB =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_SENT_CONTACT_IDENTITY_B_KEY) as? Identity?

                if (ownedIdentity == null || contactIdentityA == null || contactIdentityB == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_A_KEY] =
                    contactIdentityA.getBytes()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT_BYTES_CONTACT_IDENTITY_B_KEY] =
                    contactIdentityB.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_INTRODUCTION_INVITATION_SENT,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_OWNED_IDENTITY_KEY) as? Identity?
                val mediatorIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_MEDIATOR_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_IDENTITY_KEY) as? Identity?
                val contactSerializedDetails =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY) as? String?
                val accepted =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY) as? Boolean?

                if (ownedIdentity == null || mediatorIdentity == null || contactSerializedDetails == null || accepted == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_MEDIATOR_IDENTITY_KEY] =
                    mediatorIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_CONTACT_SERIALIZED_DETAILS_KEY] =
                    contactSerializedDetails
                engineInfo[EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE_ACCEPTED_KEY] =
                    accepted

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_INTRODUCTION_INVITATION_RESPONSE,
                    engineInfo
                )
            }

            ProtocolNotifications.NOTIFICATION_SNAPSHOT_RESTORATION_FINISHED -> {
                engine.postEngineNotification(
                    EngineNotifications.ENGINE_SNAPSHOT_RESTORATION_FINISHED,
                    HashMap()
                )
            }

            ProtocolNotifications.NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE -> {
                val ownedIdentity =
                    userInfo?.get(ProtocolNotifications.NOTIFICATION_OWNED_DEVICE_DISCOVERY_DONE_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_DEVICE_DISCOVERY_DONE_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.OWNED_DEVICE_DISCOVERY_DONE,
                    engineInfo
                )
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
