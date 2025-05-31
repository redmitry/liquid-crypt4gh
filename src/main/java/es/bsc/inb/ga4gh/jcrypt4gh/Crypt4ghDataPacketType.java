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

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public enum Crypt4ghDataPacketType {
    
    DATA_ENCRYPTION_KEY(0),
    DATA_EDIT_LIST(1);
    
    public final int TYPE;
    
    Crypt4ghDataPacketType(int type) {
        TYPE = type;
    }
    
    public final static Crypt4ghDataPacketType read(ReadableByteChannel ch) 
            throws IOException {
        final int packet_type = Crypt4ghHeaherElement.readUnsignedInt(ch);
        switch(packet_type) {
            case 0: return DATA_ENCRYPTION_KEY;
            case 1: return DATA_EDIT_LIST;
        }
        throw new IOException("invalid packet type");
    }
}
