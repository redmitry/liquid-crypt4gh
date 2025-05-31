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

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghKeyTest {
    
    // encrypted PCSK#8 private key file
    private final static String ALICE_PRIVATE_KEY_FILE = "alice.p8";
    private final static String ALICE_PUBLIC_KEY_FILE = "alice.pem";
    
    private final static String ALICE_PRIVATE_CRYPT4GH_KEY_FILE = "alice.sk";
    
    @Test
    public void testPrivatePublicKeysPair() {
        
        try {
            final EdECPrivateKey alicePrivateKey = (EdECPrivateKey)Crypt4ghKeys.loadKey(Path.of(
                    URI.create(Crypt4ghKeyTest.class.getClassLoader()
                            .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString(), "alice");
            final EdECPublicKey alicePublicKey = (EdECPublicKey)Crypt4ghKeys.loadKey(Path.of(
                    URI.create(Crypt4ghKeyTest.class.getClassLoader()
                            .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString(), "alice");
            
            final EdECPublicKey pub = Crypt4ghKeys.getPublicKey(alicePrivateKey);

            Assertions.assertArrayEquals(alicePublicKey.getPoint().getY().toByteArray(),
                    pub.getPoint().getY().toByteArray(),
                    "invalid public / private keys pair");
        } catch (Crypt4ghException | GeneralSecurityException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
    
    @Test
    public void testEncryptedCrypt4ghPrivateKey() {
        final String path = Path.of(URI.create(Crypt4ghKeyTest.class.getClassLoader()
                .getResource(ALICE_PRIVATE_CRYPT4GH_KEY_FILE).toString())).toString();
        
        try {
            final Key key = Crypt4ghKeys.loadKey(path, "alice");
            Assertions.assertNotNull(key, String.format("error reading crypt4gh key file %s", 
                    ALICE_PRIVATE_CRYPT4GH_KEY_FILE));
        } catch (Crypt4ghException | GeneralSecurityException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
}
