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

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

/**
 * @author Dmitry Repchevsky
 * 
 * @param <T> generic FileAttributes type
 */

public class Crypt4ghBasicFileAttributes<T extends BasicFileAttributes>
        implements BasicFileAttributes {
    
    protected final T proxy;
    private final long size;
    
    public Crypt4ghBasicFileAttributes(T proxy, long size) {
        this.proxy = proxy;
        this.size = size;
    }

    @Override
    public FileTime lastModifiedTime() {
        return proxy.lastAccessTime();
    }

    @Override
    public FileTime lastAccessTime() {
        return proxy.lastAccessTime();
    }

    @Override
    public FileTime creationTime() {
        return proxy.creationTime();
    }

    @Override
    public boolean isRegularFile() {
        return proxy.isRegularFile();
    }

    @Override
    public boolean isDirectory() {
        return proxy.isDirectory();
    }

    @Override
    public boolean isSymbolicLink() {
        return proxy.isSymbolicLink();
    }

    @Override
    public boolean isOther() {
        return proxy.isOther();
    }

    @Override
    public long size() {
        return proxy.isRegularFile() ? size : proxy.size();
    }

    @Override
    public Object fileKey() {
        return proxy.fileKey();
    }
}
