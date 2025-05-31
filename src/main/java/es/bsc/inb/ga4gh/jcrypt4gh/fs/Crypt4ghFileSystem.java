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
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Set;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghFileSystem extends FileSystem {

    public final FileSystem proxy;
    public final Crypt4ghFileSystemProvider provider;
    
    public Crypt4ghFileSystem(FileSystem proxy, 
            Crypt4ghFileSystemProvider provider) {
        this.proxy = proxy;
        this.provider = provider;
    }
    
    @Override
    public Crypt4ghFileSystemProvider provider() {
        return provider;
    }

    @Override
    public void close() throws IOException {
        proxy.close();
    }

    @Override
    public boolean isOpen() {
        return proxy.isOpen();
    }

    @Override
    public boolean isReadOnly() {
        return proxy.isReadOnly();
    }

    @Override
    public String getSeparator() {
        return proxy.getSeparator();
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        return proxy.getRootDirectories();
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        return proxy.getFileStores();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return proxy.supportedFileAttributeViews();
    }

    @Override
    public Path getPath(String first, String... more) {
        return new Crypt4ghPath(proxy.getPath(first, more), provider.getFileSystem());
    }

    @Override
    public PathMatcher getPathMatcher(String syntaxAndPattern) {
        return proxy.getPathMatcher(syntaxAndPattern);
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return proxy.getUserPrincipalLookupService();
    }

    @Override
    public WatchService newWatchService() throws IOException {
        return proxy.newWatchService();
    }
    
}
