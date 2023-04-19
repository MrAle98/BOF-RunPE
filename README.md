# BOF-runPE
Beacon Object File executing arbitrary PE inside a sacrificial process through partial implementation of process herpaderping technique. All credits goes to `jxy-s` for his original project available here: https://github.com/jxy-s/herpaderping .
The BOF takes as input a .exe filename on the remote machine and and a PE on the local machine and perform process herpaderping in order to execute the PE. It creates the file specified as first parameter. It uses pattern `{'\x82', '\x7f', '\x76', '\x7c'}` for overwriting the file content.

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
$ mkdir ~/.sliver-client/extensions/herpaderp
$ cp extension.json ~/.sliver-client/extensions/herpaderping
$ cp herpaderp.x64.o ~/.sliver-client/extensions/herpaderping
```

Start sliver client and try extension.
![immagine](https://user-images.githubusercontent.com/74059030/199059760-f0353823-972d-4ae2-95e4-9365763adf46.png)
![immagine](https://user-images.githubusercontent.com/74059030/199059898-992f9604-5027-4e66-855c-37b95cfafb2a.png)
