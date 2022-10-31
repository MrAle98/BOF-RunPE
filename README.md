# BOF PROCESS HERPADERPING
Beacon Object File partial implementation of process herpaderping technique. Original project available here: https://github.com/jxy-s/herpaderping
### Compilation
Executed on debian:
```
$ cd herpaderping
$ x86_64-w64-mingw32-gcc -c HerpaDerp.c -o herpaderp.x64.o
```


### Execution
Tested in sliver.

Load extension in sliver client:
```
$ mkdir ~/.sliver-client/extensions/herpaderping
$ cp extension.json ~/.sliver-client/extensions/herpaderping
$ cp herpaderp.x64.o ~/.sliver-client/extensions/herpaderping
```

Start sliver client and try extension.
![immagine](https://user-images.githubusercontent.com/74059030/199053135-f27c441d-5053-462e-8095-c47fb0d0a40c.png)
