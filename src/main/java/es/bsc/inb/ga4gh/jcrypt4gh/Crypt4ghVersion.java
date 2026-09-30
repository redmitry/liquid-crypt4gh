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
import java.nio.channels.ReadableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public enum Crypt4ghVersion {
    
    VERSION_1(1),
    VERSION_2(2);
    
    public final int VERSION;
    
    Crypt4ghVersion(final int version) {
        VERSION = version;
    }
    
    public static Crypt4ghVersion read(ReadableByteChannel ch) throws IOException {
        return getCrypt4ghVersion(Crypt4ghHeaherElement.readUnsignedInt(ch));
    }
    
    public static Crypt4ghVersion getCrypt4ghVersion(int version) {
        switch (version) {
            case 1: return VERSION_1;
            case 2: return VERSION_2;
        }
        return null;
    }
}
