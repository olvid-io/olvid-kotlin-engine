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

package io.olvid.engine.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.DecodingException
import java.nio.charset.StandardCharsets

class Identity : Comparable<Identity> {
    @JvmField val server: String
    @JvmField val serverAuthenticationPublicKey: ServerAuthenticationPublicKey
    @JvmField val encryptionPublicKey: EncryptionPublicKey
    private var identityBytes: ByteArray? = null

    constructor(
        server: String,
        serverAuthenticationPublicKey: ServerAuthenticationPublicKey,
        encryptionPublicKey: EncryptionPublicKey
    ) {
        this.server = server
        this.serverAuthenticationPublicKey = serverAuthenticationPublicKey
        this.encryptionPublicKey = encryptionPublicKey
        this.identityBytes = null
    }

    private constructor(
        server: String,
        serverAuthenticationPublicKey: ServerAuthenticationPublicKey,
        encryptionPublicKey: EncryptionPublicKey,
        identityBytes: ByteArray
    ) {
        this.server = server
        this.serverAuthenticationPublicKey = serverAuthenticationPublicKey
        this.encryptionPublicKey = encryptionPublicKey
        this.identityBytes = identityBytes
    }

    fun getBytes(): ByteArray {
        var bytes = identityBytes
        if (bytes == null) {
            val serverBytes = server.toByteArray(StandardCharsets.UTF_8)
            val serverAuthenticationPublicKeyBytes = serverAuthenticationPublicKey.compactKey
            val anonAuthPublicKeyBytes = encryptionPublicKey.compactKey
            val result = ByteArray(serverBytes.size + 1 + serverAuthenticationPublicKeyBytes.size + anonAuthPublicKeyBytes.size)
            System.arraycopy(serverBytes, 0, result, 0, serverBytes.size)
            result[serverBytes.size] = 0x00.toByte()
            System.arraycopy(serverAuthenticationPublicKeyBytes, 0, result, serverBytes.size + 1, serverAuthenticationPublicKeyBytes.size)
            System.arraycopy(anonAuthPublicKeyBytes, 0, result, serverBytes.size + 1 + serverAuthenticationPublicKeyBytes.size, anonAuthPublicKeyBytes.size)
            identityBytes = result
            bytes = result
        }
        return bytes
    }

    fun computeUniqueUid(): UID {
        val sha256 = Suite.getHash(Hash.SHA256)
        return UID(sha256.digest(getBytes()))
    }

    override fun hashCode(): Int {
        return getBytes().contentHashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Identity) return false
        return getBytes().contentEquals(other.getBytes())
    }

    override fun toString(): String {
        return server + "@" + Logger.toHexString(serverAuthenticationPublicKey.compactKey) + "-" + Logger.toHexString(encryptionPublicKey.compactKey)
    }

    override fun compareTo(other: Identity): Int {
        val me = getBytes()
        val otherBytes = other.getBytes()

        if (me.size != otherBytes.size) {
            return me.size - otherBytes.size
        }
        for (i in me.indices) {
            if (me[i] != otherBytes[i]) {
                return (me[i].toInt() and 0xff) - (otherBytes[i].toInt() and 0xff)
            }
        }
        return 0
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(identityBytes: ByteArray): Identity {
            var pos = -1
            for (i in identityBytes.indices) {
                if (identityBytes[i] == 0.toByte()) {
                    pos = i
                    break
                }
            }
            if (pos == -1) {
                throw DecodingException()
            }
            val server = String(identityBytes.copyOfRange(0, pos), StandardCharsets.UTF_8)

            pos += 1
            if (pos >= identityBytes.size) {
                throw DecodingException()
            }
            val serverPkLength = ServerAuthenticationPublicKey.getCompactKeyLength(identityBytes[pos])
            if (serverPkLength < 0 || pos + serverPkLength > identityBytes.size) {
                throw DecodingException()
            }
            val serverAuthenticationPublicKey = ServerAuthenticationPublicKey.of(identityBytes.copyOfRange(pos, pos + serverPkLength))

            pos += serverPkLength
            if (pos >= identityBytes.size) {
                throw DecodingException()
            }
            val anonAuthPkLength = EncryptionPublicKey.getCompactKeyLength(identityBytes[pos])
            if (anonAuthPkLength < 0 || pos + anonAuthPkLength > identityBytes.size) {
                throw DecodingException()
            }
            val encryptionPublicKey = EncryptionPublicKey.of(identityBytes.copyOfRange(pos, pos + anonAuthPkLength))

            return Identity(server, serverAuthenticationPublicKey, encryptionPublicKey, identityBytes)
        }
    }
}
