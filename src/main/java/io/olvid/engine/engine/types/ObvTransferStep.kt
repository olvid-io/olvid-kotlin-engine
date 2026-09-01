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

import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

abstract class ObvTransferStep {
    abstract fun getStep(): Step?
    abstract fun getEncodedParts(): Array<Encoded>?


    fun encode(): Encoded {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(getStep()!!.value.toLong()),
                Encoded.of(getEncodedParts()!!),
            )
        )
    }


    enum class Step(value: Int) {
        FAIL(1000),
        SOURCE_WAIT_FOR_SESSION_NUMBER(0),
        SOURCE_DISPLAY_SESSION_NUMBER(1),
        TARGET_SESSION_NUMBER_INPUT(2),
        ONGOING_PROTOCOL(3),
        SOURCE_SAS_INPUT(4),
        TARGET_SHOW_SAS(5),
        SOURCE_SNAPSHOT_SENT(6),
        TARGET_SNAPSHOT_RECEIVED(7),
        TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF(8);

        val value: Int

        init {
            this.value = value
        }

        companion object {
            private val valueMap: MutableMap<Int?, Step> = HashMap<Int?, Step>()

            init {
                for (step in entries) {
                    valueMap.put(step.value, step)
                }
            }

            fun fromIntValue(value: Int): Step? {
                return valueMap.get(value)
            }
        }
    }

    class SourceWaitForSessionNumberStep : ObvTransferStep {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override fun getStep(): Step {
            return Step.SOURCE_WAIT_FOR_SESSION_NUMBER
        }

        override fun getEncodedParts(): Array<Encoded> {
            return emptyArray<Encoded>()
        }
    }

    class SourceDisplaySessionNumber : ObvTransferStep {
        @JvmField val sessionNumber: Long

        constructor(sessionNumber: Long) {
            this.sessionNumber = sessionNumber
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.sessionNumber = encodedParts[0].decodeLong()
        }

        override fun getStep(): Step {
            return Step.SOURCE_DISPLAY_SESSION_NUMBER
        }

        override fun getEncodedParts(): Array<Encoded> {
            return arrayOf<Encoded>(
                Encoded.of(sessionNumber),
            )
        }
    }

    class Fail : ObvTransferStep {
        @JvmField val failReason: Int

        constructor(failReason: Int) {
            this.failReason = failReason
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.failReason = encodedParts[0].decodeLong().toInt()
        }

        override fun getStep(): Step {
            return Step.FAIL
        }

        override fun getEncodedParts(): Array<Encoded> {
            return arrayOf<Encoded>(
                Encoded.of(failReason.toLong()),
            )
        }

        companion object {
            const val FAIL_REASON_NETWORK_ERROR: Int = 1
            const val FAIL_REASON_TRANSFERRED_IDENTITY_ALREADY_EXISTS: Int = 2
            const val FAIL_REASON_INVALID_RESPONSE: Int = 3
            const val FAIL_REASON_TRANSFER_RESTRICTED_AND_NO_OIDC: Int = 4
        }
    }

    class TargetSessionNumberInput : ObvTransferStep {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override fun getStep(): Step {
            return Step.TARGET_SESSION_NUMBER_INPUT
        }

        override fun getEncodedParts(): Array<Encoded> {
            return emptyArray<Encoded>()
        }
    }

    class OngoingProtocol : ObvTransferStep {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override fun getStep(): Step {
            return Step.ONGOING_PROTOCOL
        }

        override fun getEncodedParts(): Array<Encoded> {
            return emptyArray<Encoded>()
        }
    }

    class SourceSasInput : ObvTransferStep {
        @JvmField val correctSas: String
        @JvmField val targetDeviceName: String

        constructor(correctSas: String, targetDeviceName: String) {
            this.correctSas = correctSas
            this.targetDeviceName = targetDeviceName
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 2) {
                throw DecodingException()
            }
            this.correctSas = encodedParts[0].decodeString()
            this.targetDeviceName = encodedParts[1].decodeString()
        }

        override fun getStep(): Step {
            return Step.SOURCE_SAS_INPUT
        }

        override fun getEncodedParts(): Array<Encoded> {
            return arrayOf<Encoded>(
                Encoded.of(correctSas),
                Encoded.of(targetDeviceName),
            )
        }
    }

    class TargetShowSas : ObvTransferStep {
        @JvmField val sas: String

        constructor(sas: String) {
            this.sas = sas
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.sas = encodedParts[0].decodeString()
        }

        override fun getStep(): Step {
            return Step.TARGET_SHOW_SAS
        }

        override fun getEncodedParts(): Array<Encoded> {
            return arrayOf<Encoded>(
                Encoded.of(sas),
            )
        }
    }

    class SourceSnapshotSent : ObvTransferStep {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override fun getStep(): Step {
            return Step.SOURCE_SNAPSHOT_SENT
        }

        override fun getEncodedParts(): Array<Encoded> {
            return emptyArray<Encoded>()
        }
    }

    class TargetRequestsKeycloakAuthenticationProof : ObvTransferStep {
        @JvmField val keycloakServerUrl: String
        @JvmField val clientId: String
        @JvmField val fullSas: String
        @JvmField val sessionNumber: Long
        @JvmField val clientSecret: String? // may be null

        constructor(
            keycloakServerUrl: String,
            clientId: String,
            clientSecret: String?,
            fullSas: String,
            sessionNumber: Long
        ) {
            this.keycloakServerUrl = keycloakServerUrl
            this.clientId = clientId
            this.clientSecret = clientSecret
            this.fullSas = fullSas
            this.sessionNumber = sessionNumber
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 5 && encodedParts.size != 4) {
                throw DecodingException()
            }
            this.keycloakServerUrl = encodedParts[0].decodeString()
            this.clientId = encodedParts[1].decodeString()
            this.fullSas = encodedParts[2].decodeString()
            this.sessionNumber = encodedParts[3].decodeLong()
            if (encodedParts.size == 5) {
                this.clientSecret = encodedParts[4].decodeString()
            } else {
                this.clientSecret = null
            }
        }

        override fun getStep(): Step {
            return Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF
        }

        override fun getEncodedParts(): Array<Encoded> {
            if (clientSecret == null) {
                return arrayOf<Encoded>(
                    Encoded.of(keycloakServerUrl),
                    Encoded.of(clientId),
                    Encoded.of(fullSas),
                    Encoded.of(sessionNumber),
                )
            } else {
                return arrayOf<Encoded>(
                    Encoded.of(keycloakServerUrl),
                    Encoded.of(clientId),
                    Encoded.of(fullSas),
                    Encoded.of(sessionNumber),
                    Encoded.of(clientSecret),
                )
            }
        }
    }


    class TargetSnapshotReceived : ObvTransferStep {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override fun getStep(): Step {
            return Step.TARGET_SNAPSHOT_RECEIVED
        }

        override fun getEncodedParts(): Array<Encoded> {
            return emptyArray<Encoded>()
        }
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): ObvTransferStep {
            val list: Array<Encoded> = encoded.decodeList()
            if (list.size != 2) {
                throw DecodingException()
            }
            val id = list[0].decodeLong().toInt()
            val encodedParts: Array<Encoded> = list[1].decodeList()
            val step: Step? = Step.fromIntValue(id)
            if (step == null) {
                throw DecodingException()
            }
            when (step) {
                Step.FAIL -> return Fail(encodedParts)
                Step.SOURCE_WAIT_FOR_SESSION_NUMBER -> return SourceWaitForSessionNumberStep(
                    encodedParts
                )

                Step.SOURCE_DISPLAY_SESSION_NUMBER -> return SourceDisplaySessionNumber(encodedParts)
                Step.TARGET_SESSION_NUMBER_INPUT -> return TargetSessionNumberInput(encodedParts)
                Step.ONGOING_PROTOCOL -> return OngoingProtocol(encodedParts)
                Step.SOURCE_SAS_INPUT -> return SourceSasInput(encodedParts)
                Step.TARGET_SHOW_SAS -> return TargetShowSas(encodedParts)
                Step.SOURCE_SNAPSHOT_SENT -> return SourceSnapshotSent(encodedParts)
                Step.TARGET_SNAPSHOT_RECEIVED -> return TargetSnapshotReceived(encodedParts)
                Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF -> return TargetRequestsKeycloakAuthenticationProof(
                    encodedParts
                )
            }
        }
    }
}

