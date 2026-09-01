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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Arrays

enum class ObvCapability {
    WEBRTC_CONTINUOUS_ICE,
    ONE_TO_ONE_CONTACTS,
    GROUPS_V2;

    override fun toString(): String {
        return when (this) {
            ObvCapability.WEBRTC_CONTINUOUS_ICE -> "webrtc_continuous_ice"
            ObvCapability.ONE_TO_ONE_CONTACTS -> "one_to_one_contacts"
            ObvCapability.GROUPS_V2 -> "groups_v2"
        }
    }

    companion object {
        @JvmField val currentCapabilities: MutableList<ObvCapability> = mutableListOf(
            ObvCapability.ONE_TO_ONE_CONTACTS,
            ObvCapability.GROUPS_V2
        )

        @JvmStatic fun fromString(stringRepresentation: String): ObvCapability? {
            when (stringRepresentation) {
                "webrtc_continuous_ice" -> return ObvCapability.WEBRTC_CONTINUOUS_ICE
                "groups_v2" -> return ObvCapability.GROUPS_V2
                "one_to_one_contacts" -> return ObvCapability.ONE_TO_ONE_CONTACTS
            }
            return null
        }

        fun getAll(): MutableList<ObvCapability> {
            return entries.toMutableList()
        }

        fun capabilityListToStringArray(capabilities: List<ObvCapability>): Array<String> {
            val capabilityStrings = ArrayList<String>()
            for (capability in capabilities) {
                capabilityStrings.add(capability.toString())
            }
            return capabilityStrings.toTypedArray()
        }

        fun serializeRawDeviceCapabilities(rawDeviceCapabilities: Array<String>?): ByteArray? {
            var serializedDeviceCapabilities: ByteArray?
            if (rawDeviceCapabilities == null) {
                serializedDeviceCapabilities = null
            } else if (rawDeviceCapabilities.size == 0) {
                serializedDeviceCapabilities = ByteArray(0)
            } else {
                // sort the array before serializing to ensure consistent serialization
                Arrays.sort(rawDeviceCapabilities)
                try {
                    ByteArrayOutputStream().use { baos ->
                        var first = true
                        for (capabilityString in rawDeviceCapabilities) {
                            if (!first) {
                                baos.write(byteArrayOf(0))
                            }
                            first = false
                            baos.write(capabilityString.toByteArray(StandardCharsets.UTF_8))
                        }
                        serializedDeviceCapabilities = baos.toByteArray()
                    }
                } catch (_: IOException) {
                    serializedDeviceCapabilities = null
                }
            }

            return serializedDeviceCapabilities
        }

        fun deserializeDeviceCapabilities(serializedDeviceCapabilities: ByteArray?): MutableList<ObvCapability>? {
            if (serializedDeviceCapabilities == null) {
                return null
            }

            val capabilities: MutableList<ObvCapability> = ArrayList()
            var startPos = 0
            for (i in serializedDeviceCapabilities.indices) {
                if (serializedDeviceCapabilities[i].toInt() == 0) {
                    val capabilityString = String(
                        serializedDeviceCapabilities.copyOfRange(startPos, i),
                        StandardCharsets.UTF_8
                    )
                    startPos = i + 1

                    val capability: ObvCapability? = fromString(capabilityString)
                    if (capability != null) {
                        capabilities.add(capability)
                    }
                }
            }
            if (startPos != serializedDeviceCapabilities.size) {
                val capabilityString = String(
                    serializedDeviceCapabilities.copyOfRange(startPos, serializedDeviceCapabilities.size), StandardCharsets.UTF_8
                )
                val capability: ObvCapability? = fromString(capabilityString)
                if (capability != null) {
                    capabilities.add(capability)
                }
            }
            return capabilities
        }

        fun deserializeRawDeviceCapabilities(serializedDeviceCapabilities: ByteArray?): Array<String> {
            if (serializedDeviceCapabilities == null) {
                return emptyArray()
            }

            val rawCapabilities: MutableList<String> = ArrayList()
            var startPos = 0
            for (i in serializedDeviceCapabilities.indices) {
                if (serializedDeviceCapabilities[i].toInt() == 0) {
                    rawCapabilities.add(
                        String(
                            serializedDeviceCapabilities.copyOfRange(startPos, i), StandardCharsets.UTF_8
                        )
                    )
                    startPos = i + 1
                }
            }
            if (startPos != serializedDeviceCapabilities.size) {
                rawCapabilities.add(
                    String(
                        serializedDeviceCapabilities.copyOfRange(startPos, serializedDeviceCapabilities.size), StandardCharsets.UTF_8
                    )
                )
            }
            return rawCapabilities.toTypedArray()
        }
    }
}
