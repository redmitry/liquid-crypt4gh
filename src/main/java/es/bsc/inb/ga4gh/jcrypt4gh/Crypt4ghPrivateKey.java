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

import es.bsc.inb.ga4gh.jcrypt4gh.security.ScryptKey;
import es.bsc.inb.ga4gh.jcrypt4gh.security.ScryptKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/**
 * Implementation of the Crypt4GH private key.
 * 
 * @author Dmitry Repchevsky
 */

public class Crypt4ghPrivateKey implements XECPrivateKey {

    private static final byte[] MAGIC = {'c', '4', 'g', 'h', '-', 'v', '1'};
    
    private final String passphrase;
    private final String kdfname;
    private String cifername;
    private int rounds;
    private byte[] salt;
    private final byte[] key;
    
    public Crypt4ghPrivateKey(byte[] key, String kdfname, String passphrase)
            throws GeneralSecurityException {
        
        switch(kdfname) {
            case "pbkdf2_hmac_sha256":
            case "scrypt":
                if (passphrase == null) {
                    throw new GeneralSecurityException("no encryption password provided");
                }
            case "none":
                break;
            default:
                throw new GeneralSecurityException(String.format("unsupported kdfname: %s", kdfname));
        }

        this.key = key;
        
        this.kdfname = kdfname;
        this.passphrase = passphrase;
        this.cifername = "chacha20_poly1305";
        this.rounds = 600000; // OWASP
        new SecureRandom().nextBytes(salt = new byte[16]);
    }
    
    public Crypt4ghPrivateKey(byte[] data, String passphrase)
            throws GeneralSecurityException {

        if (Arrays.compare(MAGIC, 0, MAGIC.length, data, 0, MAGIC.length) != 0) {
            throw new GeneralSecurityException("not a c4gh-v1 key");
        }
        
        this.passphrase = passphrase;

        key = new byte[32];
        
        final ByteBuffer buf = ByteBuffer.wrap(data, MAGIC.length, data.length - MAGIC.length);

        kdfname = new String(data, buf.position() + 2, len(buf), StandardCharsets.US_ASCII);
        
        if ("none".equals(kdfname)) {
            rounds = 0;
            salt = null;
            cifername = null;
            System.arraycopy(data, buf.position() + 2, key, 0, key.length);
        } else if (passphrase == null || passphrase.isBlank()) {
            throw new GeneralSecurityException("no passphrase for encrypted c4gh-v1 key");
        } else {
            rounds = buf.getInt(buf.position() + 2);
            salt = new byte[len(buf) - Integer.BYTES]; // rounds | salt
            buf.get(buf.position() - salt.length, salt);
            
            cifername = new String(data, buf.position() + 2, len(buf), StandardCharsets.US_ASCII);
            if (!"chacha20_poly1305".equals(cifername)) {
                throw new GeneralSecurityException("unsupported cifername: " + cifername);
            }
            
            final byte[] encrypted = new byte[len(buf)];
            buf.get(buf.position() - encrypted.length, encrypted);

            final SecretKey sk;
            switch(kdfname) {
                case "pbkdf2_hmac_sha256":
                    final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    final PBEKeySpec pbe_spec = new PBEKeySpec(
                                     passphrase.toCharArray(), salt, rounds, key.length);
                    sk = f.generateSecret(pbe_spec);
                    break;
                case "scrypt":
                    // default params taken from crypt4gh kdf.py
                    final ScryptKeySpec scrypt_spec = 
                            new ScryptKeySpec(passphrase, salt, 16384, 8, 1, key.length);
                    sk = new ScryptKey(scrypt_spec);
                    break;
                default:
                    throw new GeneralSecurityException("unsupported kdfname: " + kdfname);
            }
            
            final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(encrypted, 0, 12));
            cipher.doFinal(encrypted, 12, encrypted.length - 12, key);
        }
    }
    
    @Override
    public NamedParameterSpec getParams() {
        return null; // TODO
    }
    
    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "Crypt4GH";
    }

    @Override
    public byte[] getEncoded() {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            encode(out);
        } catch (IOException | GeneralSecurityException ex) {
            return null;
        }
        return out.toByteArray();
    }
    
    @Override
    public Optional<byte[]> getScalar() {
        return Optional.of(Arrays.copyOf(key, key.length));
    }

    private void encode(OutputStream out) throws IOException, GeneralSecurityException {
        out.write(MAGIC);
        
        out.write(kdfname.length() >>> 8 & 0xFF);
        out.write(kdfname.length() & 0xFF);        
        out.write(kdfname.getBytes(StandardCharsets.US_ASCII));

        if ("none".equals(kdfname)) {
            out.write("none".length() >>> 8 & 0xFF);
            out.write("none".length() & 0xFF);
            out.write("none".getBytes(StandardCharsets.US_ASCII));
            
            out.write(key.length >>> 8 & 0xFF);
            out.write(key.length & 0xFF);
            out.write(key);
        } else {
            final int rsl = salt.length + Integer.BYTES;
            out.write(rsl >>> 8 & 0xFF);
            out.write(rsl & 0xFF);

            // 4 big-endian bytes 
            out.write(rounds >>> 24 & 0xFF);
            out.write(rounds >>> 16 & 0xFF);
            out.write(rounds >>> 8 & 0xFF);
            out.write(rounds & 0xFF);
            
            out.write(salt);
            
            out.write(cifername.length() >>> 8 & 0xFF);
            out.write(cifername.length() & 0xFF);
            out.write(cifername.getBytes(StandardCharsets.US_ASCII));
            
            final SecretKey sk;
            switch(kdfname) {
                case "pbkdf2_hmac_sha256":
                    final PBEKeySpec pbe_spec = new PBEKeySpec(
                                     passphrase.toCharArray(), salt, rounds, key.length);

                    final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    sk = f.generateSecret(pbe_spec);
                    break;
                case "scrypt":
                    // default params taken from crypt4gh kdf.py
                    final ScryptKeySpec scrypt_spec = 
                            new ScryptKeySpec(passphrase, salt, 16384, 8, 1, key.length);
                    sk = new ScryptKey(scrypt_spec);
                    break;
                default:
                    throw new GeneralSecurityException("unsupported kdfname: " + kdfname);

            }
            
            final byte[] encrypted = new byte[60]; // 12 + 32 + 16 (nonce+key+mac)
            new SecureRandom().nextBytes(encrypted);
            
            final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(encrypted, 0, 12));
            cipher.doFinal(key, 0, key.length, encrypted, 12);
            
            out.write(encrypted.length >>> 8 & 0xFF);
            out.write(encrypted.length & 0xFF);
            out.write(encrypted);
        }
    }

    /**
     * Read the current string length and move position to the next string.
     * 
     * @param buf the buffer
     * 
     * @return current position string length
     */
    private static int len(ByteBuffer buf) {
        final int len = buf.getShort();
        buf.position(buf.position() + len);
        return len;
    }
}
