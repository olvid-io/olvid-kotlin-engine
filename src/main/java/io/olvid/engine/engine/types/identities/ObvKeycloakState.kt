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
package io.olvid.engine.engine.types.identities

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.IdBased
import io.olvid.engine.engine.types.identities.ObvKeycloakAuthType.OpenIdConnect
import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.lang.JoseException


class ObvKeycloakState(// non-null
    @JvmField val keycloakServer: String?,
    @JvmField val supportedAuthenticationMethods: List<ObvKeycloakAuthType?>, // non-null --> only set to null when sending to app and deserialization failed
    @JvmField val jwks: JsonWebKeySet?, // non-null --> only set to null when sending to app and deserialization failed
    @JvmField val signatureKey: JsonWebKey?, // device dependant --> do not share with other devices
    @JvmField val serializedAuthState: String?,
    @JvmField val transferRestricted: Boolean, // not included in the serialized version
    @JvmField val ownApiKey: String?, // not included in the serialized version
    @JvmField val latestRevocationListTimestamp: Long, // not included in the serialized version
    @JvmField val latestGroupUpdateTimestamp: Long
) {
    fun encode(): Encoded {
        val dict = HashMap<DictionaryKey, Encoded>()
        if (keycloakServer != null) {
            dict.put(DictionaryKey("ks"), Encoded.of(keycloakServer))
        }
        for (authType in supportedAuthenticationMethods) {
            if (authType is IdBased) {
                dict.put(DictionaryKey("ida"), Encoded.of(true))
            } else if (authType is OpenIdConnect) {
                val clientId = authType.clientId
                val clientSecret = authType.clientSecret
                if (clientId != null) {
                    dict.put(DictionaryKey("ci"), Encoded.of(clientId))
                }
                if (clientSecret != null) {
                    dict.put(DictionaryKey("cs"), Encoded.of(clientSecret))
                }
            }
        }
        if (jwks != null) {
            dict.put(DictionaryKey("jwks"), Encoded.of(jwks.toJson()))
        }
        if (signatureKey != null) {
            dict.put(DictionaryKey("sk"), Encoded.of(signatureKey.toJson()))
        }
        if (serializedAuthState != null) {
            dict.put(DictionaryKey("sas"), Encoded.of(serializedAuthState))
        }
        if (transferRestricted) {
            dict.put(DictionaryKey("tr"), Encoded.of(transferRestricted))
        }
        return Encoded.of(dict)
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): ObvKeycloakState {
            val keycloakServer: String?
            val supportedAuthenticationMethods: MutableList<ObvKeycloakAuthType?> =
                ArrayList<ObvKeycloakAuthType?>()
            var jwks: JsonWebKeySet?
            var signatureKey: JsonWebKey?
            val serializedAuthState: String?
            val transferRestricted: Boolean

            val dict: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
            var key = DictionaryKey("ks")
            var encodedValue = dict.get(key)
            if (encodedValue != null) {
                keycloakServer = encodedValue.decodeString()
            } else {
                keycloakServer = null
            }
            key = DictionaryKey("ci")
            encodedValue = dict.get(key)
            if (encodedValue != null) {
                val clientId = encodedValue.decodeString()

                key = DictionaryKey("cs")
                encodedValue = dict.get(key)
                val clientSecret = if (encodedValue != null) encodedValue.decodeString() else null

                supportedAuthenticationMethods.add(OpenIdConnect(clientId, clientSecret))
            }
            key = DictionaryKey("ida")
            encodedValue = dict.get(key)
            if (encodedValue != null && encodedValue.decodeBoolean()) {
                supportedAuthenticationMethods.add(IdBased())
            }
            key = DictionaryKey("jwks")
            encodedValue = dict.get(key)
            if (encodedValue != null) {
                try {
                    jwks = JsonWebKeySet(encodedValue.decodeString())
                } catch (_: JoseException) {
                    jwks = null
                }
            } else {
                jwks = null
            }
            key = DictionaryKey("sk")
            encodedValue = dict.get(key)
            if (encodedValue != null) {
                try {
                    signatureKey = JsonWebKey.Factory.newJwk(encodedValue.decodeString())
                } catch (_: JoseException) {
                    signatureKey = null
                }
            } else {
                signatureKey = null
            }
            key = DictionaryKey("sas")
            encodedValue = dict.get(key)
            if (encodedValue != null) {
                serializedAuthState = encodedValue.decodeString()
            } else {
                serializedAuthState = null
            }
            key = DictionaryKey("tr")
            encodedValue = dict.get(key)
            if (encodedValue != null) {
                transferRestricted = encodedValue.decodeBoolean()
            } else {
                transferRestricted = false
            }
            return ObvKeycloakState(
                keycloakServer,
                supportedAuthenticationMethods,
                jwks,
                signatureKey,
                serializedAuthState,
                transferRestricted,
                null,
                0,
                0
            )
        }
    }
}
