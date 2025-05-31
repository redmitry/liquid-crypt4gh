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
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghPath implements Path {

    public final Path proxy;
    private final Crypt4ghFileSystem fs;
    
    public Crypt4ghPath(Path proxy, Crypt4ghFileSystem fs) {
        this.proxy = proxy;
        this.fs = fs;
    }

    @Override
    public FileSystem getFileSystem() {
        return fs;
    }

    @Override
    public boolean isAbsolute() {
        return proxy.isAbsolute();
    }

    @Override
    public Path getRoot() {
        final Path root = proxy.getRoot();
        if (root == null) {
            return null;
        }
        return new Crypt4ghPath(root, fs);
    }

    @Override
    public Path getFileName() {
        final Path filename = proxy.getFileName();
        if (filename == null) {
            return filename;
        }
        return new Crypt4ghPath(filename, fs);
    }

    @Override
    public Path getParent() {
        final Path parent = proxy.getParent();
        if (parent == null) {
            return null;
        }
        return new Crypt4ghPath(parent, fs);
    }

    @Override
    public int getNameCount() {
        return proxy.getNameCount();
    }

    @Override
    public Path getName(int index) {
        final Path name = proxy.getName(index);
        if (name == null) {
            return null;
        }
        return new Crypt4ghPath(name, fs);
    }

    @Override
    public Path subpath(int beginIndex, int endIndex) {
        final Path subpath = proxy.subpath(beginIndex, endIndex);
        if (subpath == null) {
            return null;
        }
        return new Crypt4ghPath(subpath, fs);
    }

    @Override
    public boolean startsWith(Path other) {
        if (other instanceof Crypt4ghPath p) {
            return proxy.startsWith(p.proxy);
        }
        return proxy.startsWith(other);
    }

    @Override
    public boolean endsWith(Path other) {
        if (other instanceof Crypt4ghPath p) {
            return proxy.endsWith(p.proxy);
        }
        return proxy.endsWith(other);
    }

    @Override
    public Path normalize() {
        return new Crypt4ghPath(proxy.normalize(), fs);
    }

    @Override
    public Path resolve(Path other) {
        if (other instanceof Crypt4ghPath p) {
            other = p.proxy;
        }
        final Path resolved = proxy.resolve(other);
        if (resolved == null) {
            return null;
        }
        return new Crypt4ghPath(resolved, fs);
    }

    @Override
    public Path relativize(Path other) {
        if (other instanceof Crypt4ghPath p) {
            other = p.proxy;
        }
        final Path relative = proxy.relativize(other);
        if (relative == null) {
            return null;
        }
        return new Crypt4ghPath(relative, fs);
    }

    @Override
    public URI toUri() {
        return proxy.toUri();
    }

    @Override
    public Path toAbsolutePath() {
        return new Crypt4ghPath(proxy.toAbsolutePath(), fs);
    }

    @Override
    public Path toRealPath(LinkOption... options) throws IOException {
        final Path real = proxy.toRealPath(options);
        if (real == null) {
            return null;
        }
        return new Crypt4ghPath(real, fs);
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) throws IOException {
        return proxy.register(watcher, events, modifiers);
    }

    @Override
    public int compareTo(Path other) {
        if (other instanceof Crypt4ghPath p) {
            return proxy.compareTo(p.proxy);
        }
        return proxy.compareTo(other);
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Crypt4ghPath p) {
            return proxy.equals(p.proxy);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return proxy.hashCode();
    }

    @Override
    public String toString() {
        return proxy.toString();
    }
    
    static Path unwrap(Path path) {
        if (path instanceof Crypt4ghPath p) {
            return p.proxy;
        }
        return path;
    }
}
