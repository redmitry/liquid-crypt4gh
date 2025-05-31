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

package es.bsc.inb.ga4gh.jcrypt4gh.fs;

import java.io.IOException;
import java.nio.channels.FileLock;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghFileLock extends FileLock {

    private final FileLock proxy;
    
    public Crypt4ghFileLock(FileLock proxy, Crypt4ghFileChannel channel, 
            long position, long size, boolean shared) {
        super(channel, position, size, shared);
        this.proxy = proxy;
    }

    @Override
    public boolean isValid() {
        return proxy.isValid();
    }

    @Override
    public void release() throws IOException {
        proxy.release();
    }
    
}
