# binhlock - simple screen locker

simple screen locker utility for X.

## Requirements

In order to build binhlock you need the Xlib header files.

## Installation

Edit `build.zig` and `Makefile` to match your local setup (binhlock is installed into
the `/usr/local` namespace by default).

Afterwards enter the following command to build and install binhlock
(if necessary as root):

```sh
make clean install
```

## Running binhlock

Simply invoke the 'binhlock' command. To get out of it, enter your password.
