/*
 * Copyright @ 2026 CloudMeet contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.jitsi.nlj.srtp

import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import org.jitsi.nlj.PacketInfo
import org.jitsi.nlj.resources.logging.StdoutLogger
import org.jitsi.nlj.resources.srtp_samples.SrtpSample
import org.jitsi.rtp.rtp.RtpPacket
import org.jitsi.srtp.SrtpErrorStatus
import org.jitsi.srtp.SrtpPolicy

class SrtpUtilSm4Test : ShouldSpec() {
    init {
        context("SM4-GCM protection profile") {
            should("map the private profile and its keying parameters") {
                val profile = SrtpUtil.getSrtpProtectionProfileFromName("SRTP_SM4_GCM")
                profile shouldBe SrtpUtil.SRTP_SM4_GCM

                val info = SrtpUtil.getSrtpProfileInformationFromSrtpProtectionProfile(profile)
                info.cipherKeyLength shouldBe 16
                info.cipherSaltLength shouldBe 12
                info.cipherName shouldBe SrtpPolicy.SM4GCM_ENCRYPTION
                info.authFunctionName shouldBe SrtpPolicy.NULL_AUTHENTICATION
                info.rtpAuthTagLength shouldBe 16
                info.rtcpAuthTagLength shouldBe 16
            }

            should("encrypt and decrypt an RTP packet through JVB transformers") {
                val profile = SrtpUtil.getSrtpProfileInformationFromSrtpProtectionProfile(
                    SrtpUtil.SRTP_SM4_GCM
                )
                val keyingMaterial = ByteArray(2 * (profile.cipherKeyLength + profile.cipherSaltLength)) { it.toByte() }
                val client = SrtpUtil.initializeTransformer(
                    profile,
                    keyingMaterial,
                    TlsRole.CLIENT,
                    cryptex = false,
                    StdoutLogger()
                )
                val server = SrtpUtil.initializeTransformer(
                    profile,
                    keyingMaterial,
                    TlsRole.SERVER,
                    cryptex = false,
                    StdoutLogger()
                )

                try {
                    val original = SrtpSample.outgoingUnencryptedRtpPacket.clone()
                    val originalBytes = original.buffer.copyOfRange(
                        original.offset,
                        original.offset + original.length
                    )
                    val encryptedInfo = PacketInfo(original)
                    client.srtpEncryptTransformer.transform(encryptedInfo) shouldBe SrtpErrorStatus.OK

                    val encrypted = encryptedInfo.packet
                    val decryptInfo = PacketInfo(
                        RtpPacket(encrypted.buffer, encrypted.offset, encrypted.length)
                    )
                    server.srtpDecryptTransformer.transform(decryptInfo) shouldBe SrtpErrorStatus.OK
                    decryptInfo.packet.buffer.copyOfRange(
                        decryptInfo.packet.offset,
                        decryptInfo.packet.offset + decryptInfo.packet.length
                    ) shouldBe originalBytes
                } finally {
                    client.close()
                    server.close()
                }
            }
        }
    }
}
