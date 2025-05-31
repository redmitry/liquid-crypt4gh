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

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;

/**
 * @author Dmitry Repchevsky
 * 
 * @param <T> private key type
 * @param <V> public key type
 */

public abstract class Crypt4ghHeaderPacket<T extends PrivateKey, V extends PublicKey>
        implements Crypt4ghHeaherElement {

    public final T sk;
    public final V pk;
    public final V rpk;
    
    public final Crypt4ghEncryptedPacketData packet;
    
    public Crypt4ghHeaderPacket(Crypt4ghEncryptedPacketData packet, 
            T sk, V pk, V rpk) {
        
        this.packet = packet;
        
        this.sk = sk;
        this.pk = pk;
        this.rpk = rpk;
    }
    
    public abstract int size();
    
    public abstract void write(WritableByteChannel ch) throws IOException;
    
    public static Crypt4ghHeaderPacket create(ReadableByteChannel ch,
            PrivateKey sk) throws IOException {
        
        final int length = Crypt4ghHeaherElement.readUnsignedInt(ch);
        final int method = Crypt4ghHeaherElement.readUnsignedInt(ch);
        if (method != X25519_CHACHA20_IETF_POLY1305.CODE) {
            throw new IOException("unsupported crypt4gh encryption method");
        }
        
        final byte[] data = Crypt4ghHeaherElement.readNBytes(ch, length - 8);
        
        if (sk instanceof XECPrivateKey x25519) {
            return Crypt4ghX25519HeaderPacket.create(data, x25519);
        }
        
        throw new IOException("unsupported private key type: " + sk.getFormat());
    }
}
