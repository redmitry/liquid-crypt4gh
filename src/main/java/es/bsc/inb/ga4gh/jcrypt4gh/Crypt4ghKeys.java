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

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PASSPHRASE_PROPERTY;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY;
import es.bsc.inb.ga4gh.jcrypt4gh.security.EdwardsCurve;
import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Crypt4GH keys loader.
 * 
 * It supports Curve25519 keys in PKCS#8 and Crypt4GH formats.
 * 
 * @author Dmitry Repchevsky
 */

public final class Crypt4ghKeys {
    
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    
    public static final String BEGIN_ENCRYPTED_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    public static final String END_ENCRYPTED_PRIVATE_KEY = "-----END ENCRYPTED PRIVATE KEY-----";
    
    public static final String BEGIN_CRYPT4GH_PUBLIC_KEY = "-----BEGIN CRYPT4GH PUBLIC KEY-----";
    public static final String END_CRYPT4GH_PUBLIC_KEY = "-----END CRYPT4GH PUBLIC KEY-----";
    
    public static final String BEGIN_CRYPT4GH_PRIVATE_KEY = "-----BEGIN CRYPT4GH PRIVATE KEY-----";
    public static final String END_CRYPT4GH_PRIVATE_KEY = "-----END CRYPT4GH PRIVATE KEY-----";
    
    private static volatile Map.Entry<Crypt4ghConfig, Crypt4ghKeys> instance;
            
    public final XECPrivateKey SK;
    public final XECPublicKey PK;
    public final XECPublicKey RPK;

    /**
     * Initialize Crypt4GH keys from X25519 private key (e.g. @see Crypt4ghPrivateKey).
     * The reader's public key is generated from the private key.
     * 
     * @param sk the private key used to encrypt the header packets
     * 
     * @throws GeneralSecurityException 
     */
    public Crypt4ghKeys(XECPrivateKey sk)
            throws GeneralSecurityException {
        SK = sk;
        PK = getPublicKey(SK);
        RPK = PK;
    }
    
    public Crypt4ghKeys(EdECPrivateKey sk)
            throws GeneralSecurityException {
        SK = convert(sk);
        PK = getPublicKey(SK);
        RPK = PK;
    }
    
    public Crypt4ghKeys(XECPrivateKey sk, XECPublicKey rpk)
            throws GeneralSecurityException {
        SK = sk;
        PK = getPublicKey(SK);
        RPK = rpk;
    }
    
    public Crypt4ghKeys(EdECPrivateKey sk, EdECPublicKey rpk)
            throws GeneralSecurityException {
        SK = convert(sk);
        PK = getPublicKey(SK);
        RPK = convert(rpk);
    }
    
    private Crypt4ghKeys(String sk, String rpk, String passphrase)
            throws Crypt4ghException, GeneralSecurityException {
        
        final Key sec = loadKey(sk, passphrase);
        
        if (sec instanceof EdECPrivateKey ed25519sk) {
            SK = convert(ed25519sk);
        } else {
            throw new Crypt4ghException(
                    String.format("error: invalid secret key algorithm (%s) ", 
                            sec.getAlgorithm()));
        }
        
        PK = getPublicKey(SK);
        
        if (rpk == null) {
           RPK = null;
        } else if (rpk.isEmpty()) {
            RPK = PK;
        } else {
            final Key pub = loadKey(rpk, passphrase);
            if (pub instanceof EdECPublicKey ed25519pk) {
                RPK = convert(ed25519pk);
            } else {
                throw new Crypt4ghException(
                        String.format("error: invalid public key algorithm (%s) ", 
                                pub.getAlgorithm()));
            }
        }
    }

    public static synchronized Crypt4ghKeys instance() 
            throws Crypt4ghException, GeneralSecurityException {
        final Crypt4ghConfig cfg = Crypt4ghConfig.load();
        if (cfg == null) {
            instance = null;
        } else if (instance == null || !cfg.equals(instance.getKey())) {
            instance = new SimpleImmutableEntry(cfg, 
                    new Crypt4ghKeys(cfg.private_key_file, 
                            cfg.public_key_file, cfg.passphrase));
        }
        
        return instance != null ? instance.getValue() : null;
    }
    
    public static Crypt4ghKeys load()
            throws Crypt4ghException, GeneralSecurityException {
        
        String sk = System.getProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY);
        if (sk == null) {
            sk = System.getenv(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY);
        }
        
        if (sk == null) {
            throw new Crypt4ghException(
                    String.format("error: no secret key provided ('%s' property)", 
                            CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY));
        }
        
        final String passphrase = System.getProperty(CRYPT4GH_PASSPHRASE_PROPERTY);
        
        String pk = System.getProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);
        if (pk == null) {
            pk = System.getenv(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);
        }

        return new Crypt4ghKeys(sk, pk, passphrase);
    }
    
    /**
     * Read the key (public or private) from the path.
     * Supports Crypt4GH and PKCS#8 public or private (including encrypted) keys.
     * 
     * 
     * @param path path to the key file
     * @param passphrase password to decrypt the key or null
     * 
     * @return loaded cryptographic key
     * 
     * @throws es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghException
     * @throws java.security.GeneralSecurityException
     */
    
    public static Key loadKey(String path, String passphrase) 
            throws Crypt4ghException, GeneralSecurityException {
        
        final Path file;
        try {
            file = Paths.get(path);
        } catch (InvalidPathException ex) {
            throw new Crypt4ghException(String.format("error: invalid file path (%s)", path));
        }
        
        final Predicate<String> p = Predicate.not(Pattern.compile("-----(.*?)-----").asPredicate());
        
        final String begin;
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            begin = reader.readLine();
            
            final String encodedKey = reader.lines().filter(p).collect(Collectors.joining());
            final byte[] key = Base64.getDecoder().decode(encodedKey);
            
            if (BEGIN_PRIVATE_KEY.equals(begin)) {
                final KeyFactory kf = KeyFactory.getInstance("Ed25519");
                return kf.generatePrivate(new PKCS8EncodedKeySpec(key));
            }
            
            if (BEGIN_ENCRYPTED_PRIVATE_KEY.equals(begin)) {
                if (passphrase == null) {
                    throw new Crypt4ghException("error: encrypted private key (no password provided)");
                }
                final EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(key);
                final AlgorithmParameters algParams = keyInfo.getAlgParameters();
                
                final PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase.toCharArray());
                final SecretKeyFactory secFac = SecretKeyFactory.getInstance(algParams.toString());
                final SecretKey pbeKey = secFac.generateSecret(pbeKeySpec);
                
                final Cipher cipher = Cipher.getInstance(secFac.getAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
                final PKCS8EncodedKeySpec pkcs8KeySpec = keyInfo.getKeySpec(cipher);
                if (!"Ed25519".equals(pkcs8KeySpec.getAlgorithm())) {
                    throw new Crypt4ghException(String.format(
                            "error: not ed25519 key (%s)", pkcs8KeySpec.getAlgorithm()));
                }
                final KeyFactory kf = KeyFactory.getInstance("Ed25519");
                return kf.generatePrivate(pkcs8KeySpec);
            }
            
            if (BEGIN_PUBLIC_KEY.equals(begin)) {
                final KeyFactory kf = KeyFactory.getInstance("Ed25519");
                return kf.generatePublic(new X509EncodedKeySpec(key));
            }
            
            if (BEGIN_CRYPT4GH_PRIVATE_KEY.equals(begin)) {    
                return new Crypt4ghPrivateKey(key, passphrase);
            }
            
            if (BEGIN_CRYPT4GH_PUBLIC_KEY.equals(begin)) {
                return new Crypt4ghPublicKey(key);
            }
        }
        catch (NoSuchFileException ex) {
            throw new Crypt4ghException(String.format("error: no file found (%s)", path));
        } catch (IOException ex) {
            throw new Crypt4ghException(String.format("error: reading file (%s)", path));
        }
        
        throw new Crypt4ghException(
                String.format("error: invalid key format (%s)", 
                        begin.substring(0, Math.min(32, begin.length()))));
    }
    
    static EdECPublicKey getPublicKey(EdECPrivateKey sk) {
        final byte[] key = sk.getBytes().get();
        
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ed25519");
            keyPairGenerator.initialize(NamedParameterSpec.ED25519, 
                    new SecureRandom() {
                        @Override
                        public void nextBytes(byte[] bytes) {
                            System.arraycopy(key, 0, bytes, 0, key.length);
                        }
                    });
        
            return (EdECPublicKey)keyPairGenerator.generateKeyPair().getPublic();

        } catch (GeneralSecurityException ex) {
            Logger.getLogger(Crypt4ghKeys.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static XECPublicKey getPublicKey(XECPrivateKey sk) {
        if (sk != null) {
            final byte[] key = sk.getScalar().get();

            try {
                final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
                keyPairGenerator.initialize(NamedParameterSpec.X25519, 
                        new SecureRandom(){
                            @Override
                            public void nextBytes(byte[] bytes) {
                                System.arraycopy(key, 0, bytes, 0, key.length);
                            }
                        });
                return (XECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
            } catch (GeneralSecurityException ex) {
                Logger.getLogger(Crypt4ghKeys.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    /**
     * Convert 25519 Edwards to the 25519 Montgomery curve.
     * 
     * @param ed25519 Edwards Curve public key
     * @return x25519 Montgomery public key
     * 
     * @throws java.security.GeneralSecurityException
     */
    protected static XECPublicKey convert(EdECPublicKey ed25519)
            throws GeneralSecurityException {

        final BigInteger y = ed25519.getPoint().getY();
        final byte[] key = y.toByteArray();
        for (int i = 0, n = key.length; i < n; key[i] ^= key[--n], key[n] ^= key[i], key[i++] ^= key[n]) {}

        Logger.getLogger(Crypt4ghKeys.class.getName()).log(Level.FINEST, 
                String.format("ed25519 public key (y): %s", HexFormat.of().formatHex(key).toUpperCase()));

        
        final byte[] u = EdwardsCurve.convertPublicKey(key);
        
        Logger.getLogger(Crypt4ghKeys.class.getName()).log(Level.FINEST, 
                String.format("x25519 public key (u): %s", HexFormat.of().formatHex(u).toUpperCase()));

        for (int i = 0, n = u.length; i < n; u[i] ^= u[--n], u[n] ^= u[i], u[i++] ^= u[n]) {}

        final XECPublicKeySpec keySpec = 
                new XECPublicKeySpec(new NamedParameterSpec("X25519"), new BigInteger(u));
        final KeyFactory kf = KeyFactory.getInstance("XDH");

        return (XECPublicKey)kf.generatePublic(keySpec);
    }
    
    /**
     * Convert 25519 Edwards to the 25519 Montgomery curve.
     * 
     * @param ed25519 Edwards Curve private key
     * @return x25519 Montgomery private key
     * 
     * @throws java.security.GeneralSecurityException
     */
    public static XECPrivateKey convert(EdECPrivateKey ed25519)
            throws GeneralSecurityException {

        byte[] ed25519PrivateKeyBytes = ed25519.getBytes().get();
        final MessageDigest md = MessageDigest.getInstance("SHA-512");
        final byte[] key = Arrays.copyOf(md.digest(ed25519PrivateKeyBytes), 32);
        
        key[0] &= 0xF8;
        key[31] &= 0x7F;
        key[31] |= 0x40;

        final XECPrivateKeySpec keySpec = 
                new XECPrivateKeySpec(NamedParameterSpec.X25519, key);
        final KeyFactory kf = KeyFactory.getInstance("XDH");

        return (XECPrivateKey)kf.generatePrivate(keySpec);
    }
}
