## Getting the C toolchain

    npm install -g xpm
    xpm install
    export PATH=$PWD/xpacks/.bin:$PATH

## How to build Mumu

    ./configure \
        --host=aarch64-none-elf \
        --enable-mumujs \
        --with-devkits=mumu,mumujs \
        --with-devkit-symbol-scope=original
    make
    export MUMUJS_DEVKIT_DIR=$PWD/build/bindings/mumujs/devkit

## Building

    export PATH=$PWD/xpacks/.bin:$PATH
    export CC_aarch64_unknown_none=aarch64-none-elf-gcc
    export AR_aarch64_unknown_none=aarch64-none-elf-ar
    export RANLIB_aarch64_unknown_none=aarch64-none-elf-ranlib

## Development loop

    export MIRU_BAREBONE_CONFIG=$PWD/etc/xnu.json
    cargo build --release && make -C ~/src/miru-python && killall -9 qemu-system-aarch64 && sleep 2 && miru -D barebone -p 0

## Speeding up loop

    ./configure \
        -- \
        -Dmiru-core:compat=disabled \
        -Dmiru-core:local_backend=disabled \
        -Dmiru-core:fruity_backend=disabled \
        -Dmiru-core:droidy_backend=disabled \
        -Dmiru-core:socket_backend=disabled \
        -Dmiru-core:compiler_backend=disabled \
        -Dmiru-core:gadget=disabled \
        -Dmiru-core:server=disabled \
        -Dmiru-core:portal=disabled \
        -Dmiru-core:inject=disabled \
        -Dmiru-core:tests=enabled
