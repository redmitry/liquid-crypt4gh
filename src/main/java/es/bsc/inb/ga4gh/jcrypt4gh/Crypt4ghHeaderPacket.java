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

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghX25519HeaderPacket.KEY_SIZE;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import static java.security.spec.NamedParameterSpec.X25519;
import java.security.spec.XECPublicKeySpec;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    
    public static XECPublicKey readPublicWriterKey(ReadableByteChannel ch) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        
        final Crypt4ghHeaderEncryptionMethod encryption = Crypt4ghHeaderEncryptionMethod.read(ch);
        if (encryption == null) {
            throw new IOException("unsupported crypt4gh encryption method");
        }
        
        final byte[] key = Crypt4ghHeaherElement.readNBytes(ch, KEY_SIZE);

        final KeyFactory keyFactory = KeyFactory.getInstance(X25519.getName());
        for (int i = 0, n = key.length; i < n; key[i] ^= key[--n], key[n] ^= key[i], key[i++] ^= key[n]) {}

        Logger.getLogger(Crypt4ghX25519HeaderPacketV1.class.getName())
                .log(Level.FINE, "Crypt4gh peer writerPublicKey: {0}" , HexFormat.of().formatHex(key).toUpperCase());

        return (XECPublicKey)keyFactory.generatePublic(
                new XECPublicKeySpec(new NamedParameterSpec(X25519.getName()), new BigInteger(key)));
    }
    
    public static Crypt4ghHeaderPacket create(ReadableByteChannel ch,
            PrivateKey sk, XECPublicKey kpw) 
            throws IOException {
        
        if (sk instanceof XECPrivateKey x25519) {
            try {
                return Crypt4ghX25519HeaderPacket.create(ch, x25519, kpw);
            } catch (GeneralSecurityException ex) {
                return null;
            }
        }
        
        throw new IOException("unsupported private key type: " + sk.getFormat());
    }
}
