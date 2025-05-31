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

import com.rfksystems.blake2b.security.Blake2b512Digest;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import static java.security.spec.NamedParameterSpec.X25519;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghX25519HeaderPacket 
        extends Crypt4ghHeaderPacket<XECPrivateKey, XECPublicKey> {
    
    public final static int KEY_SIZE = 32;
    public final static int NONCE_SIZE = 12;
    public final static int MAC_SIZE = 16;
    
    private Crypt4ghX25519HeaderPacket(Crypt4ghEncryptedPacketData packet,
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
    public Crypt4ghX25519HeaderPacket(XECPrivateKey sk, XECPublicKey pk, XECPublicKey rpk) 
            throws GeneralSecurityException {
                
        super(new Crypt4ghDataEncryptionKey(), sk, pk, rpk);
    }
    
    @Override
    public int size() {
        return 4 + 4 + KEY_SIZE + NONCE_SIZE + packet.size() + MAC_SIZE;
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
    
    public static Crypt4ghX25519HeaderPacket create(byte[] data, XECPrivateKey sk)
            throws IOException {

        try {
            final XECPublicKey pk = Crypt4ghKeys.getPublicKey(sk);

            final KeyFactory keyFactory = KeyFactory.getInstance(X25519.getName());
            final byte[] key = Arrays.copyOf(data, KEY_SIZE);
            for (int i = 0, n = key.length; i < n; key[i] ^= key[--n], key[n] ^= key[i], key[i++] ^= key[n]) {}
            
            Logger.getLogger(Crypt4ghX25519HeaderPacket.class.getName())
                    .log(Level.FINE, "Crypt4gh peer writerPublicKey: {0}" , HexFormat.of().formatHex(key).toUpperCase());
            
            final XECPublicKey rpk = (XECPublicKey)keyFactory.generatePublic(
                    new XECPublicKeySpec(new NamedParameterSpec(X25519.getName()), new BigInteger(key)));

            final byte[] nonce = Arrays.copyOfRange(data, KEY_SIZE, KEY_SIZE + NONCE_SIZE);
            final byte[] payload = Arrays.copyOfRange(data, KEY_SIZE + NONCE_SIZE, data.length);
            final byte[] decrypted = decrypt(nonce, payload, sk, pk, rpk);
            final ReadableByteChannel packetData = Channels.newChannel(new ByteArrayInputStream(decrypted));
            final Crypt4ghEncryptedPacketData packet = Crypt4ghEncryptedPacketData.create(packetData);
            return new Crypt4ghX25519HeaderPacket(packet, sk, pk, rpk);
        } catch (NoSuchAlgorithmException ex) {
            throw new IOException(ex.getMessage());
        } catch (GeneralSecurityException ex) {
            return null;
        }
    }

    private static byte[] decrypt(byte[] nonce, byte[] payload, XECPrivateKey sk, 
            XECPublicKey pk, XECPublicKey rpk) throws GeneralSecurityException {
        return transform(false, nonce, payload, sk, pk, rpk);
    }
    
    private static byte[] encrypt(byte[] nonce, byte[] payload, XECPrivateKey sk, 
            XECPublicKey pk, XECPublicKey rpk) throws GeneralSecurityException {
        return transform(true, nonce, payload, sk, pk, rpk);
    }

    private static byte[] transform(boolean encrypt, byte[] nonce, byte[] payload, 
            XECPrivateKey sk, XECPublicKey pk, XECPublicKey rpk) throws GeneralSecurityException {        
        final SecretKey sharedKey = getSharedKey(sk, pk, rpk);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(nonce));
        
        return cipher.doFinal(payload);
    }

    public static SecretKey getSharedKey(XECPrivateKey sk, XECPublicKey pk, XECPublicKey rpk) 
            throws GeneralSecurityException {
        
        final KeyAgreement keyAgreement = KeyAgreement.getInstance(X25519.getName());
        keyAgreement.init(sk);
        keyAgreement.doPhase(rpk, true);

        final byte[] dh = keyAgreement.generateSecret();
        final byte[] pw = pk.getEncoded();
        final byte[] pr = rpk.getEncoded();
        final byte[] input = ByteBuffer.allocate(dh.length + 32 + 32)
                .put(dh)
                .put(Arrays.copyOfRange(pw, pw.length - 32, pw.length))
                .put(Arrays.copyOfRange(pr, pr.length - 32, pr.length))
                .array();
        
        final byte[] digest = new Blake2b512Digest().digest(input);
        return new SecretKeySpec(Arrays.copyOf(digest, 32), "ChaCha20");
    }
}
