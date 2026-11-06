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

package io.olvid.engine.channel.coordinators

import io.olvid.engine.Logger
import io.olvid.engine.channel.datatypes.ChannelManagerSession
import io.olvid.engine.channel.datatypes.ChannelManagerSessionFactory
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import io.olvid.engine.metamanager.NetworkFetchDelegate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.io.File
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.sql.SQLException

/**
 * An unchecked exception while unwrapping a received message's key used to escape
 * ChannelCoordinator.decryptAndProcess, so the message was never deleted and was retried forever. It must now be
 * treated as an undecryptable message, while SQLExceptions still keep the message for a later retry.
 */
class ChannelCoordinatorUnwrapTest {
    private lateinit var dbFile: File
    private lateinit var ownedIdentity: Identity
    private val undecryptable = mutableListOf<UID?>()

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        dbFile = File.createTempFile("channel_coordinator_test_", ".sqlite")
        dbFile.deleteOnExit()

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))
        ownedIdentity = Identity(
            "test.olvid.io",
            ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng).publicKey as ServerAuthenticationPublicKey,
            EncryptionEciesCurve25519KeyPair.generate(prng).publicKey as EncryptionPublicKey,
        )
    }

    @After
    fun tearDown() {
        dbFile.delete()
    }

    private inline fun <reified T> stub(crossinline handler: (Method, Array<Any?>) -> Any?): T {
        return Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
            when (method.name) {
                "toString" -> T::class.java.simpleName
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.get(0)
                else -> handler(method, args ?: emptyArray())
            }
        } as T
    }

    // A coordinator whose only working channel is the asymmetric one, with the given unwrap behaviour
    private fun coordinator(unwrap: () -> AuthEncKey?): ChannelCoordinator {
        val encryptionForIdentityDelegate = stub<EncryptionForIdentityDelegate> { method, _ ->
            if (method.name == "unwrap") unwrap() else throw UnsupportedOperationException(method.name)
        }
        val networkFetchDelegate = stub<NetworkFetchDelegate> { method, args ->
            if (method.name == "messageCannotBeDecrypted") {
                undecryptable.add(args[2] as UID?)
                null
            } else {
                throw UnsupportedOperationException(method.name)
            }
        }
        return ChannelCoordinator(object : ChannelManagerSessionFactory {
            override val session: ChannelManagerSession
                get() = ChannelManagerSession(
                    Session.getSession(dbFile.absolutePath, null),
                    null, networkFetchDelegate, null, null, encryptionForIdentityDelegate, null, null, null, null
                )
        })
    }

    private fun message(uidByte: Int): NetworkReceivedMessage {
        // a wrapped key shorter than a KeyId: the oblivious channel declines it, and there is no pre-key delegate
        return NetworkReceivedMessage(
            UID(ByteArray(UID.UID_LENGTH) { uidByte.toByte() }),
            0,
            EncryptedBytes(ByteArray(0)),
            NetworkReceivedMessage.Header(ownedIdentity, EncryptedBytes(ByteArray(10))),
            false
        )
    }

    @Test
    fun uncheckedExceptionWhileUnwrapping_messageIsDeletedAsUndecryptable() {
        val exceptions = listOf(NullPointerException(), ClassCastException(), IllegalArgumentException(), ArrayIndexOutOfBoundsException())
        for ((i, exception) in exceptions.withIndex()) {
            val msg = message(i)
            coordinator { throw exception }.decryptAndProcess(msg)
            assertEquals(exception.javaClass.simpleName, listOf(msg.getMessageUid()), undecryptable)
            assertFalse("write lock released after ${exception.javaClass.simpleName}", Session.globalWriteLock.isLocked)
            undecryptable.clear()
        }
    }

    @Test
    fun unwrapReturnsNull_messageIsDeletedAsUndecryptable() {
        val msg = message(1)
        coordinator { null }.decryptAndProcess(msg)
        assertEquals(listOf(msg.getMessageUid()), undecryptable)
    }

    @Test
    fun sqlExceptionWhileUnwrapping_messageIsKeptForRetry() {
        coordinator { throw SQLException("database is locked") }.decryptAndProcess(message(1))
        assertEquals(emptyList<UID?>(), undecryptable)
        assertFalse(Session.globalWriteLock.isLocked)
    }
}
