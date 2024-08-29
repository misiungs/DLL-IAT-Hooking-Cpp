# DLL-IAT-Hooking-Cpp
IAT Hooking implemented in DLL for injection purposes. <br/>
DLL when injected into a process performs IAT Hooking by searching for and overwriting MessageBoxA function address in the IAT table. <br/>
The hooked function extracts MessageBoxA function parameters through base64-encoded query parameters in HTTP GET requests to domain of choice. <br/>
