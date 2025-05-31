//package es.bsc.inb.ga4gh.jcrypt4gh.test;
//
//import com.goterl.lazysodium.LazySodium;
//import com.goterl.lazysodium.LazySodiumJava;
//import com.goterl.lazysodium.SodiumJava;
//import java.io.BufferedReader;
//import java.io.InputStream;
//import java.io.InputStreamReader;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.KeyFactory;
//import java.security.KeyPairGenerator;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.SecureRandom;
//import java.security.interfaces.EdECPublicKey;
//import java.security.spec.NamedParameterSpec;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.util.Arrays;
//import java.util.Base64;
//import java.util.function.Predicate;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import java.util.regex.Pattern;
//import java.util.stream.Collectors;
//import org.junit.BeforeClass;
//import org.junit.Test;
//
///**
// *
// * @author BULLFROG
// */
//public class Ed25519toX25519ConvertTest {
//
//    // unencrypted private key file
//    private final static String READER_PRIVATE_KEY_FILE = "readerPrivateKey.pem";
//    
//    private static PrivateKey readerPrivateKey;
//    @BeforeClass
//    public static void init() {
//        final Predicate<String> p = Predicate.not(Pattern.compile("-----(.*?)-----").asPredicate());
//        try (InputStream in = Ed25519toX25519ConvertTest.class.getClassLoader().getResourceAsStream(READER_PRIVATE_KEY_FILE);
//             BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
//            final String encodedKey = reader.lines().filter(p).collect(Collectors.joining());
//            final byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
//            final KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
//            readerPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
//        } catch (Exception ex) {
//            Logger.getLogger(Ed25519toX25519ConvertTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }
//
//    @Test
//    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
//        LazySodium lazySodium = new LazySodiumJava(new SodiumJava());
//        byte[] x25519PrivateKeyBytes = new byte[32];
//        byte[] ed25519PrivateKeyBytes = Arrays.copyOfRange(readerPrivateKey.getEncoded(), 16, 48);
//        
//        lazySodium.convertSecretKeyEd25519ToCurve25519(x25519PrivateKeyBytes, ed25519PrivateKeyBytes);
//        
//        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
//        keyPairGenerator.initialize(new NamedParameterSpec("X25519"), 
//                new SecureRandom() {
//                    @Override
//                    public void nextBytes(byte[] bytes) {
//                        System.arraycopy(x25519PrivateKeyBytes, 0, bytes, 0, x25519PrivateKeyBytes.length);
//                    }
//                });
//        
//        PrivateKey pk = keyPairGenerator.generateKeyPair().getPrivate();
//        System.out.println("");
//    }
//}
