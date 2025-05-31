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

import es.bsc.inb.ga4gh.jcrypt4gh.fs.Crypt4ghFileChannel;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Command line Liquid Crypt4GH utility.
 * 
 * @author Dmitry Repchevsky
 */

public class Crypt4gh {
    
    private final static String HELP = 
"""
liquid-crypt4gh command [params]

command:
  -k (--keygen)     - generate PKCS8 private/public key pair or derive a public key
  -c (--convert)    - convert PKCS8 keys (ed255519) into the Crypt4gh ones (x25519)
  -e (--encrypt)    - encrypt file
  -d (--decrypt)    - decrypt file
params:
  -sk               - secret key
  -pk               - public key
  -p (--password)   - password for encrypted private key
  -o (--output)     - output file
examples:
  java -jar liquid-crypt4gh.jar -k -o alice
  java -jar liquid-crypt4gh.jar -k -sk alice.p8 -pk alice.pem
  java -jar liquid-crypt4gh.jar --keygen pub -sk alice.p8 -pk alice.pem
  java -jar liquid-crypt4gh.jar -c alice.p8 -p alice
  java -jar liquid-crypt4gh.jar -e myfile.txt -sk alice.p8
  java -jar liquid-crypt4gh.jar --encrypt myfile.txt -sk alice.p8 -pk bob.pem
  java -jar liquid-crypt4gh.jar --decrypt myfile.c4gh -sk bob.p8 -o myfile.txt
""";
    
    public static void main(String[] args) {

        final Map<String, List<String>> params = parameters(args);
        
        if (params.isEmpty()) {
            System.out.println(HELP);
            System.exit(0);
        }

        try {
            final String keygen = getParameter(params, "-k", "--keygen", true);
            final String convert = getParameter(params, "-c", "--convert", false);
            final String encode = getParameter(params, "-e", "--encrypt", false);
            final String decode = getParameter(params, "-d", "--decrypt", false);
            
            if (keygen == null && convert == null && encode == null && decode == null) {
                throw new Crypt4ghException("error: no command for execution.");
            }
            
            final String sk = getParameter(params, "-sk", "", false);
            final String pk = getParameter(params, "-pk", "", false);
            final String password = getParameter(params, "-p", "--password", false);
            final String output = getParameter(params, "-o", "--output", false);
            
            if (keygen != null && convert == null && encode == null && decode == null) {
                if ("pub".equalsIgnoreCase(keygen)) {
                    genpub(sk, pk, password);
                } else if (sk == null && output == null) {
                    throw new Crypt4ghException("error: missed private key name ('-pk')");
                } else if ((sk != null || pk != null) && output != null) {
                    throw new Crypt4ghException("error: either '-o' or '-pk' must be specified");
                } else {
                    keygen(sk != null ? sk : output, pk, password);
                }
            } else if (convert != null && keygen == null && encode == null && decode == null) {
                convert(convert, password, output);
            } else if (encode != null && decode != null || keygen != null || convert != null) {
                throw new Crypt4ghException("error: more than one command for execution.");
            } else if (sk == null) {
                throw new Crypt4ghException("error: no private key for encryption.");      
            } else if (encode != null) {
                encode(encode, sk, pk, password, output);
            } else {
                decode(decode, sk, password, output);
            }
        } catch(Crypt4ghException | GeneralSecurityException | IOException ex) {
            System.err.println(ex.getMessage());
            System.exit(0);
        }
    }

    /**
     * Generates public key from a private one.
     * 
     * @param sk private key file
     * @param pk public key file (may be null)
     * @param password password to decrypt encrypted private key (may be null)
     * 
     * @throws Crypt4ghException
     * @throws GeneralSecurityException
     * @throws IOException 
     */
    private static void genpub(String sk, String pk, String password)
            throws Crypt4ghException, GeneralSecurityException, IOException {
        
        if (sk == null) {
            throw new Crypt4ghException("error: missed private key name ('-sk')");
        }

        final Key key = Crypt4ghKeys.loadKey(sk, password);
        if (key instanceof Crypt4ghPrivateKey crypt4gh) {
            if (pk == null) {
                pk = sk.endsWith(".sk") ? 
                        sk.substring(0, sk.length() - 2) + "pub" : sk + ".pub";
            }

            final XECPublicKey x25519 = Crypt4ghKeys.getPublicKey(crypt4gh);
            final Crypt4ghPublicKey c4gh = new Crypt4ghPublicKey(x25519.getU());
            write(c4gh, pk);
        } else if (key instanceof EdECPrivateKey ed25519) {
            if (pk == null) {
                pk = sk.endsWith(".p8") ? 
                        sk.substring(0, sk.length() - 2) + "pem" : sk + ".pem";
            }
            final EdECPublicKey pub = Crypt4ghKeys.getPublicKey(ed25519);
            write(pub, pk);
        } else if (key instanceof XECPrivateKey x25519) {
            if (pk == null) {
                pk = sk.endsWith(".p8") ? 
                        sk.substring(0, sk.length() - 2) + "pem" : sk + ".pem";
            }
            final XECPublicKey pub = Crypt4ghKeys.getPublicKey(x25519);
            write(pub, pk);
        } else {
            throw new Crypt4ghException(
                    String.format("error: unsupported private key format (%s)", key.getFormat()));
        }
    }
    
    /**
     * Generate PKCS#8 ed25519 key pair
     * 
     * @param sk private key file
     * @param pk public key file (may be null)
     * @param password password to encrypt the private key
     * 
     * @throws Crypt4ghException
     * @throws GeneralSecurityException
     * @throws IOException 
     */
    private static void keygen(String sk, String pk, String password) 
            throws Crypt4ghException, GeneralSecurityException, IOException {

        if (sk.indexOf('.') < 0 || !sk.endsWith(".p8")) {
            sk += ".p8";
        }
        
        if (pk == null) {
            pk = sk.substring(0, sk.length() - 2) + "pem";
        }
        
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        final KeyPair kp = kpg.generateKeyPair();
        final EdECPrivateKey priv = (EdECPrivateKey)kp.getPrivate();
        final EdECPublicKey pub = (EdECPublicKey)kp.getPublic();
        
        write(priv, sk, password);
        write(pub, pk);
    }
    
    /**
     * Convert ed25519 PKCS#8 keys into Crypt4gh ones
     * 
     * @param file key to be converted
     * @param password password to decrypt the key
     * @param output crypt4gh key file
     * 
     * @throws Crypt4ghException
     * @throws GeneralSecurityException
     * @throws IOException 
     */
    private static void convert(String file, String password, String output) 
            throws Crypt4ghException, GeneralSecurityException, IOException {
        
        final Key key = Crypt4ghKeys.loadKey(file, password);

        if (key instanceof EdECPublicKey ed25519) {
            output = output == null ? file.concat(".pub") : output;
            final XECPublicKey x25519 = Crypt4ghKeys.convert(ed25519);
            final Crypt4ghPublicKey c4gh = new Crypt4ghPublicKey(x25519.getU());
            write(c4gh, output);
        } else if (key instanceof EdECPrivateKey ed25519) {
            output = output == null ? file.concat(".sk") : output;
            final XECPrivateKey x25519 = Crypt4ghKeys.convert(ed25519);
            final Crypt4ghPrivateKey c4gh = new Crypt4ghPrivateKey(
                    x25519.getScalar().get(), password == null ? "none" : "scrypt", password);
            write(c4gh, output);
        } else if (key instanceof Crypt4ghPrivateKey c4gh) {
            output = output == null ? file.concat(".p8") : output;
            final KeyFactory kf = KeyFactory.getInstance("XDH");
            final XECPrivateKeySpec keySpec = 
                    new XECPrivateKeySpec(NamedParameterSpec.X25519, c4gh.getScalar().get());
            write((XECPrivateKey)kf.generatePrivate(keySpec), output, password);
        } else if (key instanceof Crypt4ghPublicKey c4gh) {
            output = output == null ? file.concat(".pem") : output;
            final KeyFactory kf = KeyFactory.getInstance("XDH");
            final XECPublicKeySpec keySpec = 
                    new XECPublicKeySpec(NamedParameterSpec.X25519, c4gh.getU());
            write((XECPublicKey)kf.generatePublic(keySpec), output);
        } else if (key instanceof XECPrivateKey x25519) {
            output = output == null ? file.concat(".sk") : output;
            final Crypt4ghPrivateKey c4gh = new Crypt4ghPrivateKey(
                    x25519.getScalar().get(), password == null ? "none" : "scrypt", password);
            write(c4gh, output);
        } else if (key instanceof XECPublicKey x25519) {
            output = output == null ? file.concat(".pub") : output;
            final Crypt4ghPublicKey c4gh = new Crypt4ghPublicKey(x25519.getU());
            write(c4gh, output);
        }
        else {
            throw new Crypt4ghException(
                    String.format("error: can't convert %s keys", key.getFormat()));
        }
    }
    
    private static void write(PublicKey key, String file)
            throws Crypt4ghException, GeneralSecurityException, IOException {
        
        System.out.println(String.format("writing %s %s %s public key", 
                file, key.getFormat(), key.getAlgorithm()));
        
        try (OutputStream out = Files.newOutputStream(Paths.get(file), 
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            out.write(Crypt4ghKeys.BEGIN_PUBLIC_KEY.getBytes());
            out.write('\n');
            out.write(Base64.getEncoder().encode(key.getEncoded()));
            out.write('\n');
            out.write(Crypt4ghKeys.END_PUBLIC_KEY.getBytes());
        }        
    }
    
    private static void write(PrivateKey key, String file, String password)
        throws Crypt4ghException, GeneralSecurityException, IOException {
        
        System.out.println(String.format("writing %s %s %s private key", 
                file, key.getFormat(), key.getAlgorithm()));
        
        try (OutputStream out = Files.newOutputStream(Paths.get(file), 
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            if (password == null) {
                // write unencrypted pem private key
                out.write(Crypt4ghKeys.BEGIN_PRIVATE_KEY.getBytes(StandardCharsets.ISO_8859_1));
                out.write('\n');
                out.write(Base64.getEncoder().encode(key.getEncoded()));
                out.write('\n');
                out.write(Crypt4ghKeys.END_PRIVATE_KEY.getBytes(StandardCharsets.ISO_8859_1));
            } else {
                final byte[] salt = new byte[32];
                final byte[] iv = new byte[16];

                new SecureRandom().nextBytes(salt);
                new SecureRandom().nextBytes(iv);

                final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                final PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                final PBEParameterSpec pbeParamSpec = new PBEParameterSpec(
                        pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount(), ivSpec);

                final SecretKey pbeKey = f.generateSecret(pbeKeySpec);
                final SecretKeySpec secret = new SecretKeySpec(pbeKey.getEncoded(), "AES");

                final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
                final byte[] encrypted = cipher.doFinal(key.getEncoded());

                final AlgorithmParameters params = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_256");
                params.init(pbeParamSpec);

                // keyInfo doesn't accept 'PBEWithHmacSHA256AndAES_256' as an alorithm!!!
                final AlgorithmParameters pbes2 = AlgorithmParameters.getInstance("PBES2");
                pbes2.init(params.getEncoded());

                final EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(pbes2, encrypted);

                out.write(Crypt4ghKeys.BEGIN_ENCRYPTED_PRIVATE_KEY.getBytes());
                out.write('\n');
                out.write(Base64.getEncoder().encode(keyInfo.getEncoded()));
                out.write('\n');
                out.write(Crypt4ghKeys.END_ENCRYPTED_PRIVATE_KEY.getBytes());
            }
        }
    }
    
    /**
     * Write XECPublicKey as Crypt4GH public key.
     * 
     * @param key x25519 public key
     * @param file file path
     * 
     * @throws Crypt4ghException
     * @throws GeneralSecurityException
     * @throws IOException 
     */
    private static void write(Crypt4ghPublicKey key, String file)
        throws Crypt4ghException, GeneralSecurityException, IOException {
        
        System.out.println(String.format("writing %s Crypt4GH x25519 public key", file));
        
        try (OutputStream out = Files.newOutputStream(Paths.get(file), 
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            
            out.write(Crypt4ghKeys.BEGIN_CRYPT4GH_PUBLIC_KEY.getBytes());
            out.write('\n');
            out.write(Base64.getEncoder().encode(key.getEncoded()));
            out.write('\n');
            out.write(Crypt4ghKeys.END_CRYPT4GH_PUBLIC_KEY.getBytes());
        }
    }

    /**
     * Write Cript4GH private key to the disk.
     * 
     * @param c4gh Cript4GH private key
     * @param file file path
     * 
     * @throws Crypt4ghException
     * @throws GeneralSecurityException
     * @throws IOException 
     */
    private static void write(Crypt4ghPrivateKey c4gh, String file)
        throws Crypt4ghException, GeneralSecurityException, IOException {
        
        System.out.println(String.format("writing %s Crypt4GH x25519 private key", file));
        
        try (OutputStream out = Files.newOutputStream(Paths.get(file), 
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            out.write(Crypt4ghKeys.BEGIN_CRYPT4GH_PRIVATE_KEY.getBytes());
            out.write('\n');
            out.write(Base64.getEncoder().encode(c4gh.getEncoded()));
            out.write('\n');
            out.write(Crypt4ghKeys.END_CRYPT4GH_PRIVATE_KEY.getBytes());
        }
    }

    private static void encode(String file, String sk, String pk, String password, String output) 
            throws Crypt4ghException, GeneralSecurityException, IOException {
        
        final Key secretKey = Crypt4ghKeys.loadKey(sk, password);
        if (secretKey instanceof EdECPrivateKey sk25519) {
            output = output == null ? file.concat(".c4gh") : output;
            final Crypt4ghKeys keys;
            if (pk == null) {
                keys = new Crypt4ghKeys(sk25519);
            } else if (Crypt4ghKeys.loadKey(pk, password) instanceof EdECPublicKey pk25519) {
                keys = new Crypt4ghKeys(sk25519, pk25519);
            } else {
                throw new Crypt4ghException("error: unknown public key format.");
            }
            try (OutputStream out = Channels.newOutputStream(
                    new Crypt4ghFileChannel(keys, Paths.get(output), 
                        Set.of(StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)))) {
                Files.copy(Paths.get(file), out);
            }
        } else {
            throw new Crypt4ghException("error: unknown private key format.");
        }
    }

    private static void decode(String file, String sk, String password, String output)
            throws Crypt4ghException, GeneralSecurityException, IOException {
        
        final Key secretKey = Crypt4ghKeys.loadKey(sk, password);
        if (secretKey instanceof EdECPrivateKey sk25519) {
            if (output == null) {
                output = file.endsWith(".c4gh") ? file.substring(0, file.length() - 5) : file + ".decoded";
            }
            output = output == null ? file.concat(".p8") : output;
            final Crypt4ghKeys keys = new Crypt4ghKeys(sk25519);
            try (InputStream out = Channels.newInputStream(
                    new Crypt4ghFileChannel(keys, Paths.get(file), 
                        Set.of(StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)))) {
                Files.copy(out, Paths.get(output), StandardCopyOption.REPLACE_EXISTING);
            }
        } else {
            throw new Crypt4ghException("error: unknown private key format.");
        }        
    }

    private static String getParameter(Map<String, List<String>> params,
        String shortName, String longName, boolean empty) throws Crypt4ghException {

        List<String> c = params.get(shortName);
        if (c == null) {
            c = params.get(longName);
        } else if (params.containsKey(longName)) {
            throw new Crypt4ghException(
                    String.format("error: %s and %s parameter together.", shortName, longName));
        }
        
        if (c == null) {
            return null;
        }

        if (c.size() > 1) {
            throw new Crypt4ghException(
                String.format("error: %s (%s) parameter must have only one value.", shortName, longName));
        }
        
        if (!c.isEmpty()) {
            return c.get(0);
        } else if (empty) {
            return "";
        }

        throw new Crypt4ghException(
            String.format("error: %s (%s) parameter must have a value.", shortName, longName));
    }
    
    private static Map<String, List<String>> parameters(String[] args) {
        TreeMap<String, List<String>> parameters = new TreeMap();        
        List<String> values = null;
        for (String arg : args) {
            switch(arg) {
                case "-c":
                case "--convert":
                case "-e":
                case "--encrypt":
                case "-d":
                case "--decrypt":
                case "-k":
                case "--keygen":
                case "-p":
                case "--password":
                case "-sk":
                case "-pk":
                case "-o":
                case "--output":
                    values = parameters.get(arg);
                    if (values == null) {
                        values = new ArrayList(); 
                        parameters.put(arg, values);
                    }
                    break;
                default: if (values != null) {
                    values.add(arg);
                }
            }
        }
        return parameters;
    }

}
