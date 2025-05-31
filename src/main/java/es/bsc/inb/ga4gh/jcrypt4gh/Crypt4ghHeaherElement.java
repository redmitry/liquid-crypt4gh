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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public interface Crypt4ghHeaherElement {

    static ByteBuffer read(ReadableByteChannel ch, ByteBuffer buf) throws IOException {
        do {
            if (ch.read(buf) < 0) {
                throw new EOFException();
            }
        } while(buf.hasRemaining());
        return buf;
    }

    static byte[] readNBytes(ReadableByteChannel ch, int len) throws IOException {
        final byte[] arr = new byte[len];
        read(ch, ByteBuffer.wrap(arr));
        return arr;
    }
    
    static int readUnsignedInt(ReadableByteChannel ch) throws IOException {
        final ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        return read(ch, buf).rewind().getInt();
    }
    
    static void write(WritableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }
    
    static void writeUnsignedInt(WritableByteChannel ch, int i) throws IOException {
        write(ch, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(i).rewind());
    }
}
