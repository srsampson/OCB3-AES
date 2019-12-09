##### Compiling ocb-test.c from command line
To run this quick test by linking the dynamic library, use the following command:

```
c99 ocb-test.c -o ocb-test -L/home/name/github/OCB3-AES -Wl,-rpath=/home/name/github/OCB3-AES -I../headers -locb
```

Which assumes your github repository is in /home/name/github/OCB3-AES and "name" is your login name.
