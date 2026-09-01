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
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.engine.types.EngineNotifications
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.notification.NotificationManager

class NotificationListenerIdentity(private val engine: Engine) : NotificationListener {

    fun registerToNotifications(notificationManager: NotificationManager) {
        for (notificationName in arrayOf(
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_LIST_UPDATED,
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED,
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY,
            IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED,
            IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED,
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE,
            IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED,
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS,
            IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET,
            IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED,
            IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED,
            IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED,
            IdentityNotifications.NOTIFICATION_CONTACT_REVOKED,
            IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED,
            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS,
            IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED,
            IdentityNotifications.NOTIFICATION_OWN_CAPABILITIES_UPDATED,
            IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED,
            IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED,
            IdentityNotifications.NOTIFICATION_OWNED_DEVICE_LIST_CHANGED,
        )) {
            notificationManager.addListener(notificationName, this)
        }
    }

    override fun callback(notificationName: String?, userInfo: Map<String, @JvmSuppressWildcards Any>?) {
        when (notificationName) {
            IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY -> {
                try {
                    engine.getSession().use { engineSession ->
                        val contactIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_CONTACT_IDENTITY_KEY) as? Identity?
                        val ownedIdentity =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_OWNED_IDENTITY_KEY) as? Identity?
                        val keycloakManaged =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_KEYCLOAK_MANAGED_KEY) as? Boolean?
                        val active =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_ACTIVE_KEY) as? Boolean?
                        val oneToOne =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_ONE_TO_ONE_KEY) as? Boolean?
                        val trustLevel =
                            userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_TRUST_LEVEL_KEY) as? Int?
                        if (contactIdentity == null || ownedIdentity == null || keycloakManaged == null || active == null || oneToOne == null || trustLevel == null) {
                            return
                        }

                        // skip device discovery if the current device has not been registered on the server yet (e.g. after a transfer)
                        // it will be triggered later, once push notification registration is confirmed
                        if (engine.identityManager.isCurrentDeviceNeverRegistered(
                                engineSession.session,
                                ownedIdentity)) {
                            Logger.i("Skip discovery because device is not registered yet")
                        } else {
                            engine.protocolManager.startDeviceDiscoveryProtocol(
                                ownedIdentity,
                                contactIdentity
                            )
                        }

                        val engineInfo = HashMap<String, Any?>()
                        val contactDetails =
                            engine.identityManager.getContactIdentityTrustedDetails(
                                engineSession.session,
                                ownedIdentity,
                                contactIdentity
                            )

                        engineInfo[EngineNotifications.NEW_CONTACT_OWNED_IDENTITY_KEY] =
                            ownedIdentity.getBytes()
                        engineInfo[EngineNotifications.NEW_CONTACT_CONTACT_IDENTITY_KEY] =
                            ObvIdentity(contactIdentity, contactDetails, keycloakManaged, active)
                        engineInfo[EngineNotifications.NEW_CONTACT_ONE_TO_ONE_KEY] = oneToOne
                        engineInfo[EngineNotifications.NEW_CONTACT_TRUST_LEVEL_KEY] = trustLevel
                        engineInfo[EngineNotifications.NEW_CONTACT_HAS_UNTRUSTED_PUBLISHED_DETAILS_KEY] =
                            engine.identityManager.contactHasUntrustedPublishedDetails(
                                engineSession.session,
                                ownedIdentity,
                                contactIdentity
                            )
                        engine.postEngineNotification(EngineNotifications.NEW_CONTACT, engineInfo)
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED -> {
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_CONTACT_IDENTITY_KEY) as? Identity?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_OWNED_IDENTITY_KEY) as? Identity?
                val trustLevel =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_TRUST_LEVEL_KEY) as? TrustLevel?
                if (contactIdentity == null || ownedIdentity == null || trustLevel == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED_TRUST_LEVEL_KEY] =
                    trustLevel.major

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_TRUST_LEVEL_INCREASED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED -> {
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_CONTACT_IDENTITY_KEY) as? Identity?
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_OWNED_IDENTITY_KEY) as? Identity?
                if (contactIdentity == null || ownedIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_DELETED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_DELETED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(EngineNotifications.CONTACT_DELETED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_DEVICE_CONTACT_IDENTITY_KEY) as? Identity?
                if (contactIdentity == null || ownedIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_DEVICES_UPDATED_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_DEVICES_UPDATED_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_DEVICES_UPDATED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_DEVICES_CHANGED_CONTACT_IDENTITY_KEY) as? Identity?
                if (contactIdentity == null || ownedIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_DEVICES_UPDATED_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_DEVICES_UPDATED_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_DEVICES_UPDATED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS_CONTACT_IDENTITY_KEY) as? Identity?
                if (ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.NEW_CONTACT_PUBLISHED_DETAILS,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_LIST_UPDATED -> {
                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_LIST_UPDATED,
                    HashMap()
                )
            }

            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                val identityDetails =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_PUBLISHED_DETAILS_UPDATED_IDENTITY_DETAILS_KEY) as? JsonIdentityDetailsWithVersionAndPhoto?
                if (ownedIdentity == null || identityDetails == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_IDENTITY_DETAILS_KEY] =
                    identityDetails.getIdentityDetails()
                engineInfo[EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED_PHOTO_URL_KEY] =
                    identityDetails.getPhotoUrl()

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_DETAILS_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_CONTACT_IDENTITY_KEY) as? Identity?
                val version =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_VERSION_KEY) as? Int?
                val isTrusted =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_IS_TRUSTED_KEY) as? Boolean?
                if (ownedIdentity == null || contactIdentity == null || version == null || isTrusted == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.NEW_CONTACT_PHOTO_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.NEW_CONTACT_PHOTO_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.NEW_CONTACT_PHOTO_VERSION_KEY] = version
                engineInfo[EngineNotifications.NEW_CONTACT_PHOTO_IS_TRUSTED_KEY] = isTrusted

                engine.postEngineNotification(EngineNotifications.NEW_CONTACT_PHOTO, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_CONTACT_IDENTITY_KEY) as? Identity?
                val identityDetails =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_IDENTITY_DETAILS_KEY) as? JsonIdentityDetailsWithVersionAndPhoto?
                if (ownedIdentity == null || contactIdentity == null || identityDetails == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED_IDENTITY_DETAILS_KEY] =
                    identityDetails

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_PUBLISHED_DETAILS_TRUSTED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_CONTACT_IDENTITY_KEY) as? Identity?
                val keycloakManaged =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_KEYCLOAK_MANAGED_KEY) as? Boolean?
                if (ownedIdentity == null || contactIdentity == null || keycloakManaged == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED_KEYCLOAK_MANAGED_KEY] =
                    keycloakManaged

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_KEYCLOAK_MANAGED_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_CONTACT_IDENTITY_KEY) as? Identity?
                val active =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_ACTIVE_KEY) as? Boolean?
                if (ownedIdentity == null || contactIdentity == null || active == null) {
                    return
                }

                if (active) {
                    try {
                        engine.getSession().use { engineSession ->
                            // skip device discovery if the current device has not been registered on the server yet (e.g. after a transfer)
                            if (engine.identityManager.isCurrentDeviceNeverRegistered(
                                    engineSession.session,
                                    ownedIdentity
                                )
                            ) {
                                Logger.i("Skip discovery because device is not registered yet")
                            } else {
                                engine.protocolManager.startDeviceDiscoveryProtocol(
                                    ownedIdentity,
                                    contactIdentity
                                )
                            }
                        }
                    } catch (_: Exception) { }
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_ACTIVE_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_ACTIVE_CHANGED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_ACTIVE_CHANGED_ACTIVE_KEY] = active

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_ACTIVE_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_REVOKED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_REVOKED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_REVOKED_CONTACT_IDENTITY_KEY) as? Identity?
                if (ownedIdentity == null || contactIdentity == null) {
                    return
                }

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_REVOKED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_REVOKED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engine.postEngineNotification(EngineNotifications.CONTACT_REVOKED, engineInfo)
            }

            IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                val hasUnpublished =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_LATEST_OWNED_IDENTITY_DETAILS_UPDATED_HAS_UNPUBLISHED_KEY) as? Boolean?
                if (ownedIdentity == null || hasUnpublished == null) {
                    return
                }
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED_HAS_UNPUBLISHED_KEY] =
                    hasUnpublished

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_LATEST_DETAILS_UPDATED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_OWNED_IDENTITY_KEY) as? Identity?
                val active =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_IDENTITY_CHANGED_ACTIVE_STATUS_ACTIVE_KEY) as? Boolean?
                if (ownedIdentity == null || active == null) {
                    return
                }
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED_ACTIVE_KEY] =
                    active

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_ACTIVE_STATUS_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_CAPABILITIES_UPDATED_CONTACT_IDENTITY_KEY) as? Identity?
                if (ownedIdentity == null || contactIdentity == null) {
                    return
                }
                try {
                    val capabilities = engine.identityManager.getContactCapabilities(
                        ownedIdentity,
                        contactIdentity
                    )

                    val engineInfo = HashMap<String, Any?>()
                    engineInfo[EngineNotifications.CONTACT_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY] =
                        ownedIdentity.getBytes()
                    engineInfo[EngineNotifications.CONTACT_CAPABILITIES_UPDATED_BYTES_CONTACT_IDENTITY_KEY] =
                        contactIdentity.getBytes()
                    engineInfo[EngineNotifications.CONTACT_CAPABILITIES_UPDATED_CAPABILITIES] =
                        capabilities

                    engine.postEngineNotification(
                        EngineNotifications.CONTACT_CAPABILITIES_UPDATED,
                        engineInfo
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            IdentityNotifications.NOTIFICATION_OWN_CAPABILITIES_UPDATED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWN_CAPABILITIES_UPDATED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return
                try {
                    val capabilities = engine.identityManager.getOwnCapabilities(ownedIdentity)

                    val engineInfo = HashMap<String, Any?>()
                    engineInfo[EngineNotifications.OWN_CAPABILITIES_UPDATED_BYTES_OWNED_IDENTITY_KEY] =
                        ownedIdentity.getBytes()
                    engineInfo[EngineNotifications.OWN_CAPABILITIES_UPDATED_CAPABILITIES] =
                        capabilities

                    engine.postEngineNotification(
                        EngineNotifications.OWN_CAPABILITIES_UPDATED,
                        engineInfo
                    )
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_CONTACT_IDENTITY_KEY) as? Identity?
                val oneToOne =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY) as? Boolean?

                if (ownedIdentity == null || contactIdentity == null || oneToOne == null) {
                    return
                }
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY] = oneToOne

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_ONE_TO_ONE_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                val contactIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_CONTACT_IDENTITY_KEY) as? Identity?
                val recentlyOnline =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_RECENTLY_ONLINE_KEY) as? Boolean?

                if (ownedIdentity == null || contactIdentity == null || recentlyOnline == null) {
                    return
                }
                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_BYTES_CONTACT_IDENTITY_KEY] =
                    contactIdentity.getBytes()
                engineInfo[EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED_RECENTLY_ONLINE_KEY] =
                    recentlyOnline

                engine.postEngineNotification(
                    EngineNotifications.CONTACT_RECENTLY_ONLINE_CHANGED,
                    engineInfo
                )
            }

            IdentityNotifications.NOTIFICATION_OWNED_DEVICE_LIST_CHANGED -> {
                val ownedIdentity =
                    userInfo?.get(IdentityNotifications.NOTIFICATION_OWNED_DEVICE_LIST_CHANGED_OWNED_IDENTITY_KEY) as? Identity?
                        ?: return

                val engineInfo = HashMap<String, Any?>()
                engineInfo[EngineNotifications.OWNED_IDENTITY_DEVICE_LIST_CHANGED_BYTES_OWNED_IDENTITY_KEY] =
                    ownedIdentity.getBytes()

                engine.postEngineNotification(
                    EngineNotifications.OWNED_IDENTITY_DEVICE_LIST_CHANGED,
                    engineInfo
                )
            }

            else -> Logger.w("Received notification $notificationName but no handler is set.")
        }
    }
}
