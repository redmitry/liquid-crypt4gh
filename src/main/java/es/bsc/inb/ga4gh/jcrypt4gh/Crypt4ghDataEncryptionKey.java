/*
 * Copyright (C) 2024 ELIXIR ES, Spanish National Bioinformatics Institute (INB)
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

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghDataPacketType.DATA_ENCRYPTION_KEY;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305_WITH_AD;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghDataEncryptionKey extends Crypt4ghEncryptedPacketData {

    public final Crypt4ghHeaderEncryptionMethod method;
    public final SecretKey secretKey;
    public final long initial_sequence_number;

    public Crypt4ghDataEncryptionKey() throws GeneralSecurityException {
        this(X25519_CHACHA20_IETF_POLY1305);
    }
    
    public Crypt4ghDataEncryptionKey(Crypt4ghHeaderEncryptionMethod method) throws GeneralSecurityException {
        super(DATA_ENCRYPTION_KEY);
        
        this.method = method;
        
        final byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        
        secretKey = new SecretKeySpec(key, "ChaCha20");
        initial_sequence_number = 0;
    }

    public Crypt4ghDataEncryptionKey(ReadableByteChannel ch) 
            throws IOException {
        super(DATA_ENCRYPTION_KEY);
        
        method = Crypt4ghHeaderEncryptionMethod.read(ch);

        final byte[] key = Crypt4ghHeaherElement.readNBytes(ch, method.KEY_SIZE);
        secretKey = new SecretKeySpec(key, "ChaCha20");
        
        if (method == X25519_CHACHA20_IETF_POLY1305) {
            initial_sequence_number = 0;
        } else {
            final ByteBuffer b = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
            ch.read(b);
            initial_sequence_number = b.getLong(0);
        }
    }
    
    /**
     * Return the "data encryption key packet" size.
     * (packet type + encryption method + encryption key = 40 bytes)
     * 
     * @return the size
     */
    @Override
    public int size() {
        int size = Integer.BYTES + Integer.BYTES + secretKey.getEncoded().length;
        if (method == X25519_CHACHA20_IETF_POLY1305_WITH_AD) {
            size += Long.BYTES;
        }
        return size;
    }
    
    @Override
    public byte[] getPayload() {
        final byte[] payload = new byte[size()];
        ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(DATA_ENCRYPTION_KEY.TYPE)
                .putInt(method.CODE)
                .put(secretKey.getEncoded());
        return payload;
        
    }
}
