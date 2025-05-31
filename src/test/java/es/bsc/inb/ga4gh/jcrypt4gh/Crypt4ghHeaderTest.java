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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.channels.Channels;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.interfaces.EdECPrivateKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */
public class Crypt4ghHeaderTest {
    
    private final static String CRYTPT4GH_TEST_FILE = "crypt4gh.c4gh";
    
    // unencrypted private key file
    private final static String BOB_PRIVATE_KEY_FILE = "bob.p8";
    
    
    private static EdECPrivateKey bobSecretKey;
    
    
    @BeforeAll
    public static void init() {
        
        try {
            bobSecretKey = (EdECPrivateKey)Crypt4ghKeys.loadKey(Path.of(
                    URI.create(Crypt4ghKeyTest.class.getClassLoader()
                            .getResource(BOB_PRIVATE_KEY_FILE).toString())).toString(), null);

        } catch (Crypt4ghException | GeneralSecurityException ex) {
            Logger.getLogger(Crypt4ghHeaderTest.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            Assertions.fail(ex.getMessage());
        }
    }

    
    @Test
    public void test() {
        try (InputStream in = Crypt4ghHeaderTest.class.getClassLoader().getResourceAsStream(CRYTPT4GH_TEST_FILE)) {
            Crypt4ghHeader.load(Channels.newChannel(in), new Crypt4ghKeys(bobSecretKey));
        } catch (IOException | GeneralSecurityException | Crypt4ghException ex) {
            Logger.getLogger(Crypt4ghHeaderTest.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            Assertions.fail(ex.getMessage());
        }
    }
}
