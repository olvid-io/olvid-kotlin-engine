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

package io.olvid.engine.protocol

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.PRNGHmacSHA256
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.protocol_engine.ConcreteProtocol
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.InvocationTargetException
import java.util.UUID

/**
 * Guardrail: every ConcreteProtocolMessage registered in a protocol's
 * getMessageClass() must be constructible from a ReceivedMessage without an
 * UNCONDITIONAL NullPointerException.
 *
 * Message constructors are invoked reflectively by
 * ConcreteProtocol.getConcreteProtocolMessage(), which swallows every failure
 * and silently drops the protocol message. A constructor that NPEs for every
 * possible input (e.g. the `encodedResponse != null!!` corruption fixed in
 * f0976d3b, which silently broke profile photo publication) is therefore
 * invisible at runtime. Data-dependent rejections (wrong input count, wrong
 * Encoded type) are expected and accepted; a constructor that NPEs on EVERY
 * synthetic input shape is reported as a defect.
 */
class ProtocolMessageConstructionTest {

    // A private, deterministic PRNGService: the shared Suite.getDefaultPRNGService(0)
    // singleton must not be consumed here — SymmetricCryptoUnitTest asserts exact
    // output vectors on it, and its auto-reseed counter is phase-sensitive to any
    // prior use in the same JVM fork.
    private class TestPrngService(seed: Seed) : PRNGService, PRNG by PRNGHmacSHA256(seed) {
        override fun reseed(seed: Seed?) {
            // deterministic test PRNG, never reseeded
        }
    }

    private val prng: PRNGService = TestPrngService(Seed(ByteArray(32)))

    private val identity: Identity = run {
        val serverAuthKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        Identity(
            "test.olvid.com",
            serverAuthKeyPair.publicKey as ServerAuthenticationPublicKey,
            encKeyPair.publicKey as EncryptionPublicKey
        )
    }

    private val protocolIds =
        (0..30) + ConcreteProtocol.LEGACY_KEYCLOAK_BINDING_AND_UNBINDING_PROTOCOL_ID
    private val messageIds = 0..63

    @Test
    fun everyRegisteredMessageIsConstructibleWithoutUnconditionalNpe() {
        val defects = mutableListOf<String>()
        var messageClassesChecked = 0

        for (protocolId in protocolIds) {
            val protocol = runCatching {
                ConcreteProtocol.getConcreteProtocolInInitialState(
                    null, protocolId, UID(prng), identity, prng, ObjectMapper()
                )
            }.getOrNull() ?: continue

            val getMessageClass = generateSequence<Class<*>>(protocol.javaClass) { it.superclass }
                .firstNotNullOf { clazz ->
                    runCatching {
                        clazz.getDeclaredMethod("getMessageClass", Int::class.javaPrimitiveType)
                    }.getOrNull()
                }
                .apply { isAccessible = true }

            for (messageId in messageIds) {
                val messageClass = getMessageClass.invoke(protocol, messageId) as Class<*>? ?: continue
                messageClassesChecked++

                val constructor = runCatching {
                    messageClass.getConstructor(ReceivedMessage::class.java)
                }.getOrNull()
                if (constructor == null) {
                    defects.add(
                        "${messageClass.simpleName} (protocol $protocolId, message $messageId): " +
                                "registered in getMessageClass() but has no (ReceivedMessage) constructor — " +
                                "getConcreteProtocolMessage() can never build it"
                    )
                    continue
                }

                val npes = mutableListOf<String>()
                var variants = 0
                for (receivedMessage in syntheticReceivedMessages(protocolId, messageId)) {
                    variants++
                    try {
                        constructor.newInstance(receivedMessage)
                    } catch (e: InvocationTargetException) {
                        val cause = e.cause
                        if (cause is NullPointerException) {
                            npes.add(cause.stackTrace.firstOrNull()?.toString() ?: "?")
                        }
                        // any other exception is a legitimate data-dependent rejection
                    }
                }
                if (npes.size == variants) {
                    defects.add(
                        "${messageClass.simpleName} (protocol $protocolId, message $messageId): " +
                                "constructor throws NPE for ALL $variants input shapes — " +
                                "unconditional crash, at ${npes.first()}"
                    )
                }
            }
        }

        // the harness must actually have swept something
        assertTrue(
            "only $messageClassesChecked message classes found — enumeration is broken",
            messageClassesChecked > 100
        )
        assertTrue(
            "unconditionally unconstructible protocol messages:\n" + defects.joinToString("\n"),
            defects.isEmpty()
        )
    }

    // A spread of input shapes: counts 0..6 of homogeneous payloads of each
    // Encoded flavor, with and without an encodedResponse, with and without a
    // dialog uuid. A correct constructor accepts at least one shape or rejects
    // bad shapes with something other than NPE.
    private fun syntheticReceivedMessages(protocolId: Int, messageId: Int): List<ReceivedMessage> {
        val flavors = listOf(
            Encoded.of(ByteArray(32)),
            Encoded.of("olvid-test"),
            Encoded.of(42L),
            Encoded.of(emptyArray<Encoded>()),
            Encoded.of(identity),
            Encoded.of(UID(prng)),
        )
        val messages = mutableListOf<ReceivedMessage>()
        for (flavor in flavors) {
            for (count in 0..6) {
                messages.add(receivedMessage(protocolId, messageId, Array(count) { flavor }, null, null))
            }
        }
        // server-query response shapes
        messages.add(receivedMessage(protocolId, messageId, emptyArray(), Encoded.of(ByteArray(16)), null))
        messages.add(receivedMessage(protocolId, messageId, emptyArray(), Encoded.of(emptyArray<Encoded>()), null))
        // dialog-response shapes
        messages.add(receivedMessage(protocolId, messageId, emptyArray(), null, UUID.randomUUID()))
        messages.add(receivedMessage(protocolId, messageId, arrayOf(Encoded.of(true)), null, UUID.randomUUID()))
        return messages
    }

    private fun receivedMessage(
        protocolId: Int,
        messageId: Int,
        inputs: Array<Encoded>,
        encodedResponse: Encoded?,
        userDialogUuid: UUID?,
    ): ReceivedMessage = ReceivedMessage(
        null,
        identity,
        inputs,
        userDialogUuid,
        encodedResponse,
        UID(prng),
        messageId,
        protocolId,
        ReceptionChannelInfo.createLocalChannelInfo(),
        System.currentTimeMillis(),
        0L,
        prng
    )
}
