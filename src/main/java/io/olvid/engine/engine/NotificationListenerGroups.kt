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
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.identities.ObvGroup
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.notification.NotificationManager
import java.io.IOException

class NotificationListenerGroups(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            IdentityNotifications.NOTIFICATION_GROUP_CREATED,
            IdentityNotifications.NOTIFICATION_GROUP_DELETED,
            IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED,
            IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED,
            IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS,
            IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED,
            IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED,
            IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET,
            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED,
            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED,
            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            IdentityNotifications.NOTIFICATION_GROUP_CREATED -> try {
                engine.getSession().use { engineSession ->
                    val groupOwnerAndUid =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_CREATED_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                    val ownedIdentity =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_CREATED_OWNED_IDENTITY_KEY) as? Identity?
                    val createdOnOtherDevice =
                        userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_CREATED_ON_OTHER_DEVICE_KEY) as? Boolean?
                    if (groupOwnerAndUid == null || ownedIdentity == null || createdOnOtherDevice == null) {
                        return
                    }

                    val group = engine.identityManager.getGroupWithDetails(
                        engineSession.session,
                        ownedIdentity,
                        groupOwnerAndUid
                    ) ?: return

                    val bytesContactIdentities =
                        arrayOfNulls<ByteArray>(group.getGroupMembers().size)
                    run {
                        var j = 0
                        while (j < bytesContactIdentities.size) {
                            bytesContactIdentities[j] = group.getGroupMembers()[j].getBytes()
                            j++
                        }
                    }
                    val pendingMembers =
                        arrayOfNulls<ObvIdentity>(group.getPendingGroupMembers().size)
                    run {
                        var j = 0
                        while (j < pendingMembers.size) {
                            try {
                                val identityDetails =
                                    engine.identityManager.jsonObjectMapper.readValue(
                                        group.getPendingGroupMembers()[j].serializedDetails,
                                        JsonIdentityDetails::class.java
                                    )
                                pendingMembers[j] = ObvIdentity(
                                    identity = group.getPendingGroupMembers()[j].identity,
                                    identityDetails = identityDetails,
                                    keycloakManaged = false,
                                    active = true
                                )
                            } catch (_: IOException) {
                                pendingMembers[j] = ObvIdentity(
                                    identity = group.getPendingGroupMembers()[j].identity,
                                    identityDetails = null,
                                    keycloakManaged = false,
                                    active = true
                                )
                            }
                            j++
                        }
                    }
                    val bytesDeclinesPendingMembers =
                        arrayOfNulls<ByteArray>(group.getDeclinedPendingMembers().size)
                    var j = 0
                    while (j < bytesDeclinesPendingMembers.size) {
                        bytesDeclinesPendingMembers[j] =
                            group.getDeclinedPendingMembers()[j].getBytes()
                        j++
                    }
                    val obvGroup: ObvGroup?
                    if (group.getGroupOwner() == null) {
                        obvGroup = ObvGroup(
                            group.getGroupOwnerAndUid(),
                            group.getPublishedGroupDetails(),
                            ownedIdentity.getBytes(),
                            bytesContactIdentities,
                            pendingMembers,
                            bytesDeclinesPendingMembers,
                            null
                        )
                    } else {
                        obvGroup = ObvGroup(
                            group.getGroupOwnerAndUid(),
                            group.getLatestOrTrustedGroupDetails(),
                            ownedIdentity.getBytes(),
                            bytesContactIdentities,
                            pendingMembers,
                            bytesDeclinesPendingMembers,
                            group.getGroupOwner()!!.getBytes()
                        )
                    }

                    val photoUrl = engine.identityManager.getGroupPhotoUrl(
                        engineSession.session,
                        ownedIdentity,
                        groupOwnerAndUid
                    )

                    val engineInfo = HashMap<String, Any?>()
                    engineInfo[EngineNotifications.GROUP_CREATED_GROUP_KEY] = obvGroup
                    engineInfo[EngineNotifications.GROUP_CREATED_HAS_MULTIPLE_DETAILS_KEY] = group.hasMultipleDetails()
                    engineInfo[EngineNotifications.GROUP_CREATED_PHOTO_URL_KEY] = photoUrl
                    engineInfo[EngineNotifications.GROUP_CREATED_ON_OTHER_DEVICE_KEY] =
                        createdOnOtherDevice
                    engine.postEngineNotification(EngineNotifications.GROUP_CREATED, engineInfo)
                }
            } catch (e: Exception) {
                Logger.x(e)
            }

            IdentityNotifications.NOTIFICATION_GROUP_DELETED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_DELETED_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_DELETED_OWNED_IDENTITY_KEY) as? Identity?
                if (groupUid == null || ownedIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_DELETED_BYTES_GROUP_OWNER_AND_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.GROUP_DELETED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(EngineNotifications.GROUP_DELETED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_OWNED_IDENTITY_KEY) as? Identity?
                val groupDetailsWithVersionAndPhoto =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_DETAILS_KEY) as? JsonGroupDetailsWithVersionAndPhoto?
                if (groupUid == null || ownedIdentity == null || groupDetailsWithVersionAndPhoto == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_GROUP_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED_GROUP_DETAILS_KEY] =
                    groupDetailsWithVersionAndPhoto

                engine.postEngineNotification(
                    EngineNotifications.GROUP_PUBLISHED_DETAILS_TRUSTED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED -> {
                val groupOwnerAndUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY) as? Identity?
                if (groupOwnerAndUid == null || ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY] =
                    groupOwnerAndUid
                engineInfo[EngineNotifications.GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_MEMBER_ADDED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(EngineNotifications.GROUP_MEMBER_ADDED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_GROUP_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY) as? Identity?
                if (groupUid == null || ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY] = groupUid
                engineInfo[EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_MEMBER_REMOVED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(EngineNotifications.GROUP_MEMBER_REMOVED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                val groupDetails =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_DETAILS_KEY) as? JsonGroupDetailsWithVersionAndPhoto?
                if (groupUid == null || ownedIdentity == null || groupDetails == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_GROUP_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED_GROUP_DETAILS_KEY] =
                    groupDetails
                engine.postEngineNotification(
                    EngineNotifications.GROUP_PUBLISHED_DETAILS_UPDATED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_GROUP_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY) as? Identity?
                val contactSerializedDetails =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_ADDED_CONTACT_SERIALIZED_DETAILS_KEY) as? String?
                if (groupUid == null || ownedIdentity == null || contactIdentity == null || contactSerializedDetails == null) {
                    return
                }

                val identityDetails = runCatching {
                    engine.jsonObjectMapper.readValue(
                        contactSerializedDetails,
                        JsonIdentityDetails::class.java
                    )
                }.getOrNull()

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_ADDED_BYTES_GROUP_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_ADDED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_ADDED_CONTACT_IDENTITY_KEY] =
                    ObvIdentity(
                        identity = contactIdentity,
                        identityDetails = identityDetails,
                        keycloakManaged = false,
                        active = true
                    )

                engine.postEngineNotification(
                    EngineNotifications.PENDING_GROUP_MEMBER_ADDED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_GROUP_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY) as? Identity?
                val contactSerializedDetails =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_REMOVED_CONTACT_SERIALIZED_DETAILS_KEY) as? String?
                if (groupUid == null || ownedIdentity == null || contactIdentity == null || contactSerializedDetails == null) {
                    return
                }

                val identityDetails = runCatching {
                    engine.jsonObjectMapper.readValue(
                        contactSerializedDetails,
                        JsonIdentityDetails::class.java
                    )
                }.getOrNull()

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_BYTES_GROUP_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_REMOVED_CONTACT_IDENTITY_KEY] =
                    ObvIdentity(
                        identity = contactIdentity,
                        identityDetails = identityDetails,
                        keycloakManaged = false,
                        active = true
                    )

                engine.postEngineNotification(
                    EngineNotifications.PENDING_GROUP_MEMBER_REMOVED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED -> {
                val groupUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_GROUP_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_CONTACT_IDENTITY_KEY) as? Identity?
                val declined =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_PENDING_GROUP_MEMBER_DECLINED_TOGGLED_DECLINED_KEY) as? Boolean?
                if (groupUid == null || ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_GROUP_UID_KEY] =
                    groupUid
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED_DECLINED_KEY] = declined

                engine.postEngineNotification(
                    EngineNotifications.PENDING_GROUP_MEMBER_DECLINE_TOGGLED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET -> {
                val groupOwnerAndUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_OWNED_IDENTITY_KEY) as? Identity?
                val version =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_VERSION_KEY) as? Int?
                val isTrusted =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_GROUP_PHOTO_SET_IS_TRUSTED_KEY) as? Boolean?
                if (ownedIdentity == null || groupOwnerAndUid == null || isTrusted == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_GROUP_PHOTO_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.NEW_GROUP_PHOTO_BYTES_GROUP_OWNER_AND_UID_KEY] =
                    groupOwnerAndUid
                engineInfo[EngineNotifications.NEW_GROUP_PHOTO_VERSION_KEY] = version
                engineInfo[EngineNotifications.NEW_GROUP_PHOTO_IS_TRUSTED_KEY] = isTrusted

                engine.postEngineNotification(EngineNotifications.NEW_GROUP_PHOTO, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS_OWNED_IDENTITY_KEY) as? Identity?
                val groupOwnerAndUid =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_GROUP_PUBLISHED_DETAILS_GROUP_OWNER_AND_UID_KEY) as? ByteArray?
                if (ownedIdentity == null || groupOwnerAndUid == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS_BYTES_GROUP_OWNER_AND_UID_KEY] = groupOwnerAndUid

                engine.postEngineNotification(
                    EngineNotifications.NEW_GROUP_PUBLISHED_DETAILS,
                    engineInfo
                )
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
