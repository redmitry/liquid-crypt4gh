/*
 * Copyright (C) 2025 ELIXIR ES, Spanish National Bioinformatics Institute (INB)
 * and Barcelona Supercomputing Center (BSC)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package es.bsc.inb.ga4gh.jcrypt4gh;

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghX25519HeaderPacketV1 extends Crypt4ghX25519HeaderPacket {

        
    public Crypt4ghX25519HeaderPacketV1(Crypt4ghEncryptedPacketData packet, 
            XECPrivateKey sk, XECPublicKey pk, XECPublicKey rpk) {
        super(packet, sk, pk, rpk);
    }
    
    /**
     * Header packet constructor
     * 
     * @param sk 
     * @param pk 
     * @param rpk
     * 
     * @throws java.security.GeneralSecurityException 
     */
    public Crypt4ghX25519HeaderPacketV1(XECPrivateKey sk, 
            XECPublicKey pk, XECPublicKey rpk) throws GeneralSecurityException {  
        super(sk, pk, rpk);
    }
    
    @Override
    public int size() {
        // Packet Length + Encryption Method + Writer’s Public Key + ...
        return Integer.BYTES + Integer.BYTES + KEY_SIZE + NONCE_SIZE + packet.size() + MAC_SIZE;
    }
    
    @Override
    public void write(WritableByteChannel ch) throws IOException {
        Crypt4ghHeaherElement.writeUnsignedInt(ch, size());
        Crypt4ghHeaherElement.writeUnsignedInt(ch, X25519_CHACHA20_IETF_POLY1305.CODE);
        
        // we are the writer, so it's our public key to be written
        final byte[] key = Crypt4ghPublicKey.getKey(pk);
        Crypt4ghHeaherElement.write(ch, ByteBuffer.wrap(key));
        
        final byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        Crypt4ghHeaherElement.write(ch, ByteBuffer.wrap(nonce));
        
        final byte[] payload = packet.getPayload();
        
        try {
            final byte[] encrypted = encrypt(nonce, payload, sk, pk, rpk);
            Crypt4ghHeaherElement.write(ch, ByteBuffer.wrap(encrypted)); // payload + MAC
        } catch (GeneralSecurityException ex) {
            throw new IOException("Crypt4gh encryption error");
        }
    }
}
