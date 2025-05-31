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
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;

/**
 * Custom Crypt4GH BasicFileAttributeView.
 * 
 * 
 * @author Dmitry Repchevsky
 * 
 * @param <T>
 */

public class Crypt4ghBasicFileAttributeView<T extends BasicFileAttributeView>
        implements BasicFileAttributeView {
    
    public final T proxy;
    public final long size;
    
    public Crypt4ghBasicFileAttributeView(T proxy, long size) {
        this.proxy = proxy;
        this.size = size;
    }

    @Override
    public String name() {
        return proxy.name();
    }

    @Override
    public BasicFileAttributes readAttributes() throws IOException {
         final BasicFileAttributes attr = proxy.readAttributes();
         if (attr instanceof PosixFileAttributes posix) {
             return new Crypt4ghPosixFileAttributes(posix, size);
         }
         if (attr instanceof DosFileAttributes dos) {
             return new Crypt4ghDosFileAttributes(dos, size);
         }
         if (attr instanceof BasicFileAttributes) {
             return new Crypt4ghBasicFileAttributes(attr, size);
         }

         return null; // todo
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
        proxy.setTimes(lastModifiedTime, lastAccessTime, createTime);
    }
}
