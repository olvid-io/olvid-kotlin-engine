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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import java.util.UUID


class SendChannelInfo private constructor(
    @JvmField val channelType: Int, // only null if toIdentities is non null
    @JvmField val toIdentity: Identity?, // never null
    @JvmField val fromIdentity: Identity?, // if toIdentities is non-null, this corresponds to 1 device per toIdentity. If an UID is null, send to all devices, otherwise send to the given deviceUid
    @JvmField val remoteDeviceUids: Array<UID?>? = null,
    @JvmField val necessarilyConfirmed: Boolean? = null,
    @JvmField val dialogType: DialogType? = null,
    @JvmField val dialogUuid: UUID? = null,
    @JvmField val serverQueryType: ServerQuery.Type? = null, // only null if toIdentity is non null
    @JvmField val toIdentities: Array<Identity?>? = null
) {
    companion object {
        const val LOCAL_TYPE: Int = 0
        const val OBLIVIOUS_CHANNEL_TYPE: Int = 1
        const val ASYMMETRIC_CHANNEL_TYPE: Int = 2
        const val ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE: Int = 3
        const val ASYMMETRIC_BROADCAST_CHANNEL_TYPE: Int = 4
        const val USER_INTERFACE_TYPE: Int = 5
        const val SERVER_QUERY_TYPE: Int = 6
        const val ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE: Int = 7
        const val OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE: Int = 8

        @JvmStatic
        fun createLocalChannelInfo(ownedIdentity: Identity?): SendChannelInfo? {
            if (ownedIdentity == null) {
                return null
            }
            return SendChannelInfo(LOCAL_TYPE, ownedIdentity, ownedIdentity)
        }

        @JvmStatic
        fun createObliviousChannelInfo(
            toIdentity: Identity?,
            fromIdentity: Identity?,
            remoteDeviceUids: Array<UID?>?,
            necessarilyConfirmed: Boolean?
        ): SendChannelInfo? {
            if (toIdentity == null || fromIdentity == null || remoteDeviceUids == null || necessarilyConfirmed == null) {
                return null
            }
            return SendChannelInfo(
                OBLIVIOUS_CHANNEL_TYPE,
                toIdentity,
                fromIdentity,
                remoteDeviceUids,
                necessarilyConfirmed,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createObliviousChannelOrPreKeyInfo(
            toIdentity: Identity?,
            fromIdentity: Identity?,
            remoteDeviceUids: Array<UID?>?,
            necessarilyConfirmed: Boolean?
        ): SendChannelInfo? {
            if (toIdentity == null || fromIdentity == null || remoteDeviceUids == null || necessarilyConfirmed == null) {
                return null
            }
            return SendChannelInfo(
                OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE,
                toIdentity,
                fromIdentity,
                remoteDeviceUids,
                necessarilyConfirmed,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAsymmetricChannelInfo(
            toIdentity: Identity?,
            fromIdentity: Identity?,
            remoteDeviceUids: Array<UID?>?
        ): SendChannelInfo? {
            if (toIdentity == null || fromIdentity == null || remoteDeviceUids == null) {
                return null
            }
            return SendChannelInfo(
                ASYMMETRIC_CHANNEL_TYPE,
                toIdentity,
                fromIdentity,
                remoteDeviceUids,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic
        fun createAllConfirmedObliviousChannelsOrPreKeysInfo(
            toIdentity: Identity?,
            fromIdentity: Identity?
        ): SendChannelInfo? {
            if (toIdentity == null || fromIdentity == null) {
                return null
            }
            return SendChannelInfo(
                ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE,
                null,
                fromIdentity,
                arrayOfNulls<UID>(1),
                null,
                null,
                null,
                null,
                arrayOf<Identity?>(toIdentity)
            )
        }


        @JvmStatic
        fun createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
            toIdentities: Array<Identity>,
            fromIdentity: Identity?
        ): Array<SendChannelInfo?>? {
            return createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                toIdentities,
                arrayOfNulls<UID>(toIdentities.size),
                fromIdentity
            )
        }

        @JvmStatic
        fun createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
            toIdentities: Array<Identity>?,
            toDeviceUids: Array<UID?>,
            fromIdentity: Identity?
        ): Array<SendChannelInfo?>? {
            if (toIdentities.isNullOrEmpty() || fromIdentity == null) {
                return null
            }
            val map = HashMap<String?, MutableList<Identity?>?>()
            val deviceUidsMap = HashMap<Identity?, UID?>()
            for (i in toIdentities.indices) {
                val server = toIdentities[i].server
                var serverIdentityList = map[server]
                if (serverIdentityList == null) {
                    serverIdentityList = ArrayList()
                    map[server] = serverIdentityList
                }
                serverIdentityList.add(toIdentities[i])
                if (toDeviceUids[i] != null) {
                    deviceUidsMap[toIdentities[i]] = toDeviceUids[i]
                }
            }
            val sendChannelInfos = arrayOfNulls<SendChannelInfo>(map.size)
            var i = 0
            for (server in map.keys) {
                val serverIdentityList = map.get(server)
                if (serverIdentityList != null && !serverIdentityList.isEmpty()) {
                    val identities = arrayOfNulls<Identity>(serverIdentityList.size)
                    val deviceUids = arrayOfNulls<UID>(serverIdentityList.size)
                    var j = 0
                    for (identity in serverIdentityList) {
                        identities[j] = identity
                        deviceUids[j] = deviceUidsMap.get(identity)
                        j++
                    }

                    sendChannelInfos[i] = SendChannelInfo(
                        ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE,
                        null,
                        fromIdentity,
                        deviceUids,
                        null,
                        null,
                        null,
                        null,
                        identities
                    )
                } else {
                    sendChannelInfos[i] = null
                }
                i++
            }
            return sendChannelInfos
        }


        @JvmStatic
        fun createAllOwnedConfirmedObliviousChannelsOrPreKeysInfo(ownedIdentity: Identity?): SendChannelInfo? {
            if (ownedIdentity == null) {
                return null
            }
            return SendChannelInfo(
                ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE,
                ownedIdentity,
                ownedIdentity
            )
        }

        @JvmStatic
        fun createAsymmetricBroadcastChannelInfo(
            toIdentity: Identity?,
            fromIdentity: Identity?
        ): SendChannelInfo? {
            if (toIdentity == null || fromIdentity == null) {
                return null
            }
            return SendChannelInfo(ASYMMETRIC_BROADCAST_CHANNEL_TYPE, toIdentity, fromIdentity)
        }

        @JvmStatic
        fun createUserInterfaceChannelInfo(
            ownedIdentity: Identity?,
            dialogType: DialogType?,
            dialogUuid: UUID?
        ): SendChannelInfo? {
            if (ownedIdentity == null || dialogType == null || dialogUuid == null) {
                return null
            }
            return SendChannelInfo(
                USER_INTERFACE_TYPE,
                ownedIdentity,
                ownedIdentity,
                null,
                null,
                dialogType,
                dialogUuid,
                null,
                null
            )
        }

        @JvmStatic
        fun createServerQueryChannelInfo(
            ownedIdentity: Identity?,
            serverQueryType: ServerQuery.Type?
        ): SendChannelInfo? {
            if (ownedIdentity == null || serverQueryType == null) {
                return null
            }
            return SendChannelInfo(
                SERVER_QUERY_TYPE,
                ownedIdentity,
                ownedIdentity,
                null,
                null,
                null,
                null,
                serverQueryType,
                null
            )
        }
    }
    fun getChannelType(): Int = channelType
    fun getToIdentity(): Identity? = toIdentity
    fun getFromIdentity(): Identity? = fromIdentity
    fun getRemoteDeviceUids(): Array<UID?>? = remoteDeviceUids
    fun getNecessarilyConfirmed(): Boolean? = necessarilyConfirmed
    fun getDialogType(): DialogType? = dialogType
    fun getDialogUuid(): UUID? = dialogUuid
    fun getServerQueryType(): ServerQuery.Type? = serverQueryType
    fun getToIdentities(): Array<Identity?>? = toIdentities
}
