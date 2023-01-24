# ThreadDoctor
An injection a day keeps the SOC away.

## Usage
```
Usage: ThreadDoctor.exe <-t Injection-Type> <-p Payload> [-f DLLPath] {-n ProcessName|-d ProcessID}
  -t <type>          Injection type (1: RemoteThread, 2: DLLPath, 3: ThreadHijack, 4: QueueAPC)
  -p <payload>       x64 payload to use (1: Calculator, 2: Commandline, 3: GreedyLooter)
  -i                 try to enable SEDebugPrivilege
  -d <PID>           PID of target process
  -n <proc-name>     target process name
  -f <DLL Path>      Path of DLL file, *Required* for DLLPath injection
```
