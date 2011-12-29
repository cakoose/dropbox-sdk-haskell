The beginnings of a Dropbox API for Haskell.  Incomplete and not
officially maintained by Dropbox.

-------------------------
Dependencies:

Cabal 1.10+
GHC 7+  (might work with earlier versions, but I haven't tested)

-------------------------
To Build:

First, install all the depencies listed in dropbox-sdk.cabal

Then:
$ cabal configure
$ cabal build

-------------------------
To Run Examples:

$ cabal install  (install the library, so the example can use it)
$ cd Examples
$ cabal build
$ ./dist/build/simple/simple <app-key> <app-secret>
