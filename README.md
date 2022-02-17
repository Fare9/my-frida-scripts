# my-frida-scripts
A collection of my stupid and some useful frida scripts

## multidex\_dumper

First script I do with frida, these hooks are intended to dump the files decrypted **on disk** by those samples which are using the *multidex* trick to load the **MAIN** Activity as another *APK* or *DEX*, instead of having it inside of the *classes.dex*. This trick is done in order to avoid static analysis of interesting code, and it's being common in some current samples.
