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

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import java.util.UUID

class ObvDialog @JvmOverloads constructor(
    uuid: UUID,
    encodedElements: Encoded?,
    bytesOwnedIdentity: ByteArray,
    category: Category,
    // strictly incrementing version of this UI dialog (= its creation timestamp). 0 means unknown/legacy.
    // @JvmOverloads keeps the pre-1.1.0 4-arg constructor available to Java consumers (e.g. desktop, iOS),
    // which do not honor Kotlin default parameters; the 4-arg overload defaults version to 0.
    version: Long = 0
) {
    @JvmField val uuid: UUID
    @JvmField val encodedElements: Encoded?
    @JvmField val bytesOwnedIdentity: ByteArray
    @JvmField val category: Category
    @JvmField val version: Long
    @JvmField var encodedResponse: Encoded?

    fun getUuid(): UUID {
        return uuid
    }

    fun getVersion(): Long {
        return version
    }

    fun getEncodedElements(): Encoded? {
        return encodedElements
    }

    fun getBytesOwnedIdentity(): ByteArray {
        return bytesOwnedIdentity
    }

    fun getEncodedResponse(): Encoded? {
        return encodedResponse
    }

    fun getCategory(): Category {
        return category
    }

    init {
        this.uuid = uuid
        this.encodedElements = encodedElements
        this.bytesOwnedIdentity = bytesOwnedIdentity
        this.category = category
        this.version = version
        this.encodedResponse = null
    }

    fun encode(jsonObjectMapper: ObjectMapper): Encoded {
        // The version is appended as an optional 5th element so that already-persisted (4-element)
        // dialogs and older decoders keep working (see Companion.of which accepts size 4 or 5).
        return Encoded.of(
            arrayOf(
                Encoded.of(uuid),
                encodedElements!!,
                Encoded.of(bytesOwnedIdentity),
                category.encode(jsonObjectMapper),
                Encoded.of(version)
            )
        )
    }

    // region Dialog response setters
    @Throws(Exception::class)
    fun setResponseToAcceptInvite(acceptInvite: Boolean) {
        if (this.category.id == Category.ACCEPT_INVITE_DIALOG_CATEGORY) {
            encodedResponse = Encoded.of(acceptInvite)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setResponseToSasExchange(otherSas: ByteArray) {
        if (this.category.id == Category.SAS_EXCHANGE_DIALOG_CATEGORY) {
            encodedResponse = Encoded.of(otherSas)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setResponseToAcceptMediatorInvite(acceptInvite: Boolean) {
        if (this.category.id == Category.ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY) {
            encodedResponse = Encoded.of(acceptInvite)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setResponseToAcceptGroupInvite(acceptInvite: Boolean) {
        if (this.category.id == Category.ACCEPT_GROUP_INVITE_DIALOG_CATEGORY || this.category.id == Category.GROUP_V2_INVITATION_DIALOG_CATEGORY || (this.category.id == Category.GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY && !acceptInvite)) {
            encodedResponse = Encoded.of(acceptInvite)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setAbortOneToOneInvitationSent(abort: Boolean) {
        if (this.category.id == Category.ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY) {
            encodedResponse = Encoded.of(abort)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setResponseToAcceptOneToOneInvitation(acceptInvitation: Boolean) {
        if (this.category.id == Category.ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY) {
            encodedResponse = Encoded.of(acceptInvitation)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setAbortTransfer() {
        if (this.category.id == Category.TRANSFER_DIALOG_CATEGORY) {
            encodedResponse = null
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setTransferSessionNumber(sessionNumber: Long) {
        if (this.category.id == Category.TRANSFER_DIALOG_CATEGORY && this.category.obvTransferStep!!.getStep() == ObvTransferStep.Step.TARGET_SESSION_NUMBER_INPUT) {
            encodedResponse = Encoded.of(sessionNumber)
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setTransferSasAndDeviceUid(sas: String, deviceUidToKeepActive: ByteArray?) {
        if (this.category.id == Category.TRANSFER_DIALOG_CATEGORY && this.category.obvTransferStep!!.getStep() == ObvTransferStep.Step.SOURCE_SAS_INPUT) {
            if (deviceUidToKeepActive == null) {
                encodedResponse = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(sas),
                    )
                )
            } else {
                encodedResponse = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(sas),
                        Encoded.of(deviceUidToKeepActive),
                    )
                )
            }
        } else {
            throw Exception()
        }
    }

    @Throws(Exception::class)
    fun setTransferAuthenticationProof(signature: String, serializedAuthState: String) {
        if (this.category.id == Category.TRANSFER_DIALOG_CATEGORY && this.category.obvTransferStep!!.getStep() == ObvTransferStep.Step.TARGET_REQUESTS_KEYCLOAK_AUTHENTICATION_PROOF) {
            encodedResponse = Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(signature),
                    Encoded.of(serializedAuthState),
                )
            )
        } else {
            throw Exception()
        }
    }


    // endregion
    class Category(
        id: Int,
        bytesContactIdentity: ByteArray?,
        contactDisplayNameOrSerializedDetails: String?,
        sasToDisplay: ByteArray?,
        sasEntered: ByteArray?,
        bytesMediatorOrGroupOwnerIdentity: ByteArray?,
        serializedGroupDetails: String?,
        bytesGroupUid: ByteArray?,
        pendingGroupMemberIdentities: Array<ObvIdentity?>?,
        serverTimestamp: Long?,
        obvGroupV2: ObvGroupV2?,
        obvSyncAtom: ObvSyncAtom?,
        obvTransferStep: ObvTransferStep?
    ) {
        @JvmField val id: Int
        @JvmField val bytesContactIdentity: ByteArray?
        @JvmField val contactDisplayNameOrSerializedDetails: String?
        @JvmField val sasToDisplay: ByteArray?
        @JvmField val sasEntered: ByteArray?
        @JvmField val bytesMediatorOrGroupOwnerIdentity: ByteArray?
        @JvmField val serializedGroupDetails: String?
        @JvmField val bytesGroupUid: ByteArray?
        @JvmField val pendingGroupMemberIdentities: Array<ObvIdentity?>?
        @JvmField val serverTimestamp: Long?
        @JvmField val obvGroupV2: ObvGroupV2?
        @JvmField val obvSyncAtom: ObvSyncAtom?
        @JvmField val obvTransferStep: ObvTransferStep?


        init {
            this.id = id
            this.bytesContactIdentity = bytesContactIdentity
            this.contactDisplayNameOrSerializedDetails = contactDisplayNameOrSerializedDetails
            this.sasToDisplay = sasToDisplay
            this.sasEntered = sasEntered
            this.bytesMediatorOrGroupOwnerIdentity = bytesMediatorOrGroupOwnerIdentity
            this.serializedGroupDetails = serializedGroupDetails
            this.bytesGroupUid = bytesGroupUid
            this.pendingGroupMemberIdentities = pendingGroupMemberIdentities
            this.serverTimestamp = serverTimestamp
            this.obvGroupV2 = obvGroupV2
            this.obvSyncAtom = obvSyncAtom
            this.obvTransferStep = obvTransferStep
        }

        fun getId(): Int {
            return id
        }


        fun getSasToDisplay(): ByteArray? {
            return sasToDisplay
        }

        fun getSerializedGroupDetails(): String? {
            return serializedGroupDetails
        }

        fun getBytesGroupUid(): ByteArray? {
            return bytesGroupUid
        }

        val bytesGroupOwnerAndUid: ByteArray?
            get() {
                if (bytesMediatorOrGroupOwnerIdentity == null || bytesGroupUid == null) return null
                val out = ByteArray(bytesMediatorOrGroupOwnerIdentity.size + bytesGroupUid.size)
                System.arraycopy(
                    bytesMediatorOrGroupOwnerIdentity,
                    0,
                    out,
                    0,
                    bytesMediatorOrGroupOwnerIdentity.size
                )
                System.arraycopy(
                    bytesGroupUid,
                    0,
                    out,
                    bytesMediatorOrGroupOwnerIdentity.size,
                    bytesGroupUid.size
                )
                return out
            }

        fun getContactDisplayNameOrSerializedDetails(): String? {
            return contactDisplayNameOrSerializedDetails
        }

        fun getBytesMediatorOrGroupOwnerIdentity(): ByteArray? {
            return bytesMediatorOrGroupOwnerIdentity
        }

        fun getBytesContactIdentity(): ByteArray? {
            return bytesContactIdentity
        }

        fun getPendingGroupMemberIdentities(): Array<ObvIdentity?>? {
            return pendingGroupMemberIdentities
        }

        fun getObvGroupV2(): ObvGroupV2? {
            return obvGroupV2
        }

        fun getObvSyncItem(): ObvSyncAtom? {
            return obvSyncAtom
        }

        fun getObvTransferStep(): ObvTransferStep? {
            return obvTransferStep
        }

        internal fun encode(jsonObjectMapper: ObjectMapper): Encoded {
            var encodedVars: Encoded? = null
            when (id) {
                INVITE_SENT_DIALOG_CATEGORY, INVITE_ACCEPTED_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                        )
                    )
                }

                ACCEPT_INVITE_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                            Encoded.of(serverTimestamp!!),
                        )
                    )
                }

                SAS_EXCHANGE_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                            Encoded.of(sasToDisplay!!),
                            Encoded.of(serverTimestamp!!),
                        )
                    )
                }

                SAS_CONFIRMED_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                            Encoded.of(sasToDisplay!!),
                            Encoded.of(sasEntered!!),
                        )
                    )
                }

                ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                            Encoded.of(bytesMediatorOrGroupOwnerIdentity!!),
                            Encoded.of(serverTimestamp!!),
                        )
                    )
                }

                MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY -> {
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesContactIdentity!!),
                            Encoded.of(contactDisplayNameOrSerializedDetails!!),
                            Encoded.of(bytesMediatorOrGroupOwnerIdentity!!),
                        )
                    )
                }

                ACCEPT_GROUP_INVITE_DIALOG_CATEGORY -> {
                    val pendingEncodedList = ArrayList<Encoded>(pendingGroupMemberIdentities!!.size)
                    var i = 0
                    while (i < pendingGroupMemberIdentities.size) {
                        try {
                            pendingEncodedList.add(
                                pendingGroupMemberIdentities[i]!!.encode(jsonObjectMapper)
                            )
                        } catch (e: Exception) {
                            Logger.x(e)
                            break
                        }
                        i++
                    }
                    encodedVars = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(serializedGroupDetails!!),
                            Encoded.of(bytesGroupUid!!),
                            Encoded.of(bytesMediatorOrGroupOwnerIdentity!!),
                            Encoded.of(pendingEncodedList.toTypedArray<Encoded>()),
                            Encoded.of(serverTimestamp!!),
                        )
                    )
                }

                ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY -> encodedVars = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(bytesContactIdentity!!),
                    )
                )

                ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY -> encodedVars = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(bytesContactIdentity!!),
                        Encoded.of(serverTimestamp!!),
                    )
                )

                GROUP_V2_INVITATION_DIALOG_CATEGORY, GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY -> encodedVars =
                    Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(bytesMediatorOrGroupOwnerIdentity!!),
                            obvGroupV2!!.encode(),
                        )
                    )

                SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY -> encodedVars = Encoded.of(
                    arrayOf<Encoded>(
                        obvSyncAtom!!.encode()!!,
                    )
                )

                TRANSFER_DIALOG_CATEGORY -> encodedVars = Encoded.of(
                    arrayOf<Encoded>(
                        obvTransferStep!!.encode(),
                    )
                )
            }
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(id.toLong()),
                    encodedVars!!
                )
            )
        }

        companion object {
            val UNKNOWN_DIALOG_CATEGORY: Int = -1 // used when deserializing to avoid crash

            const val INVITE_SENT_DIALOG_CATEGORY: Int = 0
            const val ACCEPT_INVITE_DIALOG_CATEGORY: Int = 1
            const val SAS_EXCHANGE_DIALOG_CATEGORY: Int = 2
            const val SAS_CONFIRMED_DIALOG_CATEGORY: Int = 3

            //public static final int MUTUAL_TRUST_CONFIRMED_DIALOG_CATEGORY = 4;
            const val INVITE_ACCEPTED_DIALOG_CATEGORY: Int = 5
            const val ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY: Int = 6
            const val MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY: Int = 7
            const val ACCEPT_GROUP_INVITE_DIALOG_CATEGORY: Int = 8

            //        public static final int INCREASE_MEDIATOR_TRUST_LEVEL_DIALOG_CATEGORY = 9;
            //        public static final int INCREASE_GROUP_OWNER_TRUST_LEVEL_DIALOG_CATEGORY = 10;
            //        public static final int AUTO_CONFIRMED_CONTACT_INTRODUCTION_DIALOG_CATEGORY = 11;
            //        public static final int GROUP_JOINED_DIALOG_CATEGORY = 12;
            const val ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY: Int = 13
            const val ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY: Int = 14
            const val GROUP_V2_INVITATION_DIALOG_CATEGORY: Int = 15
            const val GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY: Int = 16
            const val SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY: Int = 17
            const val TRANSFER_DIALOG_CATEGORY: Int = 18


            @Throws(Exception::class)
            internal fun of(encoded: Encoded, jsonObjectMapper: ObjectMapper?): Category {
                val list: Array<Encoded> = encoded.decodeList()
                if (list.size != 2) {
                    throw DecodingException()
                }
                var id = list[0].decodeLong().toInt()
                var bytesContactIdentity: ByteArray? = null
                var contactDisplayNameOrSerializedDetails: String? = null
                var sasToDisplay: ByteArray? = null
                var sasEntered: ByteArray? = null
                var bytesMediatorOrGroupOwnerIdentity: ByteArray? = null
                var serializedGroupDetails: String? = null
                var bytesGroupUid: ByteArray? = null
                var pendingGroupMemberIdentities: Array<ObvIdentity?>? = null
                var serverTimestamp: Long? = null
                var obvGroupV2: ObvGroupV2? = null
                var obvSyncAtom: ObvSyncAtom? = null
                var obvTransferStep: ObvTransferStep? = null

                val vars: Array<Encoded> = list[1].decodeList()
                when (id) {
                    ACCEPT_INVITE_DIALOG_CATEGORY -> {
                        if (vars.size != 3) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                        serverTimestamp = vars[2].decodeLong()
                    }

                    SAS_EXCHANGE_DIALOG_CATEGORY -> {
                        if (vars.size != 4) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                        sasToDisplay = vars[2].decodeBytes()
                        serverTimestamp = vars[3].decodeLong()
                    }

                    SAS_CONFIRMED_DIALOG_CATEGORY -> {
                        if (vars.size != 4) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                        sasToDisplay = vars[2].decodeBytes()
                        sasEntered = vars[3].decodeBytes()
                    }

                    ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY -> {
                        if (vars.size != 4) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                        bytesMediatorOrGroupOwnerIdentity = vars[2].decodeBytes()
                        serverTimestamp = vars[3].decodeLong()
                    }

                    MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY -> {
                        if (vars.size != 3) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                        bytesMediatorOrGroupOwnerIdentity = vars[2].decodeBytes()
                    }

                    ACCEPT_GROUP_INVITE_DIALOG_CATEGORY -> {
                        if (vars.size != 5) {
                            throw DecodingException()
                        }
                        serializedGroupDetails = vars[0].decodeString()
                        bytesGroupUid = vars[1].decodeBytes()
                        bytesMediatorOrGroupOwnerIdentity = vars[2].decodeBytes()
                        val pendingEncodeds: Array<Encoded> = vars[3].decodeList()
                        pendingGroupMemberIdentities =
                            arrayOfNulls<ObvIdentity>(pendingEncodeds.size)
                        var i = 0
                        while (i < pendingEncodeds.size) {
                            pendingGroupMemberIdentities[i] =
                                ObvIdentity.of(pendingEncodeds[i], jsonObjectMapper!!)
                            i++
                        }
                        serverTimestamp = vars[4].decodeLong()
                    }

                    ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY -> {
                        if (vars.size != 1) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                    }

                    ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY -> {
                        if (vars.size != 2) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        serverTimestamp = vars[1].decodeLong()
                    }

                    GROUP_V2_INVITATION_DIALOG_CATEGORY, GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY -> {
                        if (vars.size != 2) {
                            throw DecodingException()
                        }
                        bytesMediatorOrGroupOwnerIdentity = vars[0].decodeBytes()
                        obvGroupV2 = ObvGroupV2.of(vars[1])
                    }

                    SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY -> {
                        if (vars.size != 1) {
                            throw DecodingException()
                        }
                        obvSyncAtom = ObvSyncAtom.of(vars[0])
                    }

                    TRANSFER_DIALOG_CATEGORY -> {
                        if (vars.size != 1) {
                            throw DecodingException()
                        }
                        obvTransferStep = ObvTransferStep.of(vars[0])
                    }

                    INVITE_SENT_DIALOG_CATEGORY, INVITE_ACCEPTED_DIALOG_CATEGORY -> {
                        if (vars.size != 2) {
                            throw DecodingException()
                        }
                        bytesContactIdentity = vars[0].decodeBytes()
                        contactDisplayNameOrSerializedDetails = vars[1].decodeString()
                    }

                    else -> {
                        Logger.e("Found an UI dialog with unknown category " + id)
                        id = UNKNOWN_DIALOG_CATEGORY
                    }
                }
                return ObvDialog.Category(
                    id,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    sasToDisplay,
                    sasEntered,
                    bytesMediatorOrGroupOwnerIdentity,
                    serializedGroupDetails,
                    bytesGroupUid,
                    pendingGroupMemberIdentities,
                    serverTimestamp,
                    obvGroupV2,
                    obvSyncAtom,
                    obvTransferStep
                )
            }

            fun createInviteSent(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?
            ): Category {
                return ObvDialog.Category(
                    INVITE_SENT_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                )
            }

            fun createAcceptInvite(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?,
                serverTimestamp: Long?
            ): Category {
                return ObvDialog.Category(
                    ACCEPT_INVITE_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    serverTimestamp,
                    null,
                    null,
                    null
                )
            }

            fun createSasExchange(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?,
                sasToDisplay: ByteArray?,
                serverTimestamp: Long?
            ): Category {
                return ObvDialog.Category(
                    SAS_EXCHANGE_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    sasToDisplay,
                    null,
                    null,
                    null,
                    null,
                    null,
                    serverTimestamp,
                    null,
                    null,
                    null
                )
            }

            fun createSasConfirmed(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?,
                sasToDisplay: ByteArray?,
                sasEntered: ByteArray?
            ): Category {
                return ObvDialog.Category(
                    SAS_CONFIRMED_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    sasToDisplay,
                    sasEntered,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                )
            }

            fun createInviteAccepted(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?
            ): Category {
                return ObvDialog.Category(
                    INVITE_ACCEPTED_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                )
            }

            fun createAcceptMediatorInvite(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?,
                bytesMediatorIdentity: ByteArray?,
                serverTimestamp: Long?
            ): Category {
                return ObvDialog.Category(
                    ACCEPT_MEDIATOR_INVITE_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    null,
                    null,
                    bytesMediatorIdentity,
                    null,
                    null,
                    null,
                    serverTimestamp,
                    null,
                    null,
                    null
                )
            }

            fun createMediatorInviteAccepted(
                bytesContactIdentity: ByteArray?,
                contactDisplayNameOrSerializedDetails: String?,
                bytesMediatorIdentity: ByteArray?
            ): Category {
                return ObvDialog.Category(
                    MEDIATOR_INVITE_ACCEPTED_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    contactDisplayNameOrSerializedDetails,
                    null,
                    null,
                    bytesMediatorIdentity,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                )
            }

            fun createAcceptGroupInvite(
                serializedGroupDetails: String?,
                groupId: ByteArray?,
                bytesGroupOwnerIdentity: ByteArray?,
                pendingGroupMemberIdentities: Array<ObvIdentity?>,
                serverTimestamp: Long?
            ): Category {
                return ObvDialog.Category(
                    ACCEPT_GROUP_INVITE_DIALOG_CATEGORY,
                    null,
                    null,
                    null,
                    null,
                    bytesGroupOwnerIdentity,
                    serializedGroupDetails,
                    groupId,
                    pendingGroupMemberIdentities,
                    serverTimestamp,
                    null,
                    null,
                    null
                )
            }

            fun createOneToOneInvitationSent(bytesContactIdentity: ByteArray): Category {
                return ObvDialog.Category(
                    ONE_TO_ONE_INVITATION_SENT_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null
                )
            }

            fun createAcceptOneToOneInvitation(
                bytesContactIdentity: ByteArray?,
                serverTimestamp: Long?
            ): Category {
                return ObvDialog.Category(
                    ACCEPT_ONE_TO_ONE_INVITATION_DIALOG_CATEGORY,
                    bytesContactIdentity,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    serverTimestamp,
                    null,
                    null,
                    null
                )
            }

            fun createGroupV2Invitation(
                bytesInviterIdentity: ByteArray?,
                obvGroupV2: ObvGroupV2?
            ): Category {
                return ObvDialog.Category(
                    GROUP_V2_INVITATION_DIALOG_CATEGORY,
                    null,
                    null,
                    null,
                    null,
                    bytesInviterIdentity,
                    null,
                    null,
                    null,
                    null,
                    obvGroupV2,
                    null,
                    null
                )
            }

            fun createGroupV2FrozenInvitation(
                bytesInviterIdentity: ByteArray?,
                obvGroupV2: ObvGroupV2?
            ): Category {
                return ObvDialog.Category(
                    GROUP_V2_FROZEN_INVITATION_DIALOG_CATEGORY,
                    null,
                    null,
                    null,
                    null,
                    bytesInviterIdentity,
                    null,
                    null,
                    null,
                    null,
                    obvGroupV2,
                    null,
                    null
                )
            }

            fun createSyncItemToApply(obvSyncAtom: ObvSyncAtom?): Category {
                return ObvDialog.Category(
                    SYNC_ITEM_TO_APPLY_DIALOG_CATEGORY,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    obvSyncAtom,
                    null
                )
            }

            fun createTransferDialog(obvTransferStep: ObvTransferStep?): Category {
                return ObvDialog.Category(
                    TRANSFER_DIALOG_CATEGORY,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    obvTransferStep
                )
            }
        }
    }

    companion object {
        @JvmStatic
        @Throws(Exception::class)
        fun of(encoded: Encoded, jsonObjectMapper: ObjectMapper?): ObvDialog {
            val list: Array<Encoded> = encoded.decodeList()
            // size 4 = legacy dialog (no version), size 5 = version-aware dialog
            if (list.size != 4 && list.size != 5) {
                throw DecodingException()
            }
            val version = if (list.size == 5) list[4].decodeLong() else 0
            return ObvDialog(
                list[0].decodeUuid(),
                list[1],
                list[2].decodeBytes(),
                Category.of(list[3], jsonObjectMapper),
                version
            )
        }
    }
}
