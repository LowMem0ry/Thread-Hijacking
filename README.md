# What this Thread Execution Hijacking
* Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process. Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL.
# TECHNICAL DETAILS
* Open a handle to the process with [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
* Allocate some executable memory in the target process with [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* Write shellcode we want to inject into the memory using [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
* Find a thread ID of the thread we want to hijack in the target process. In our case, we will fetch the thread ID of the first thread in our target process
* Open a handle to the thread to be hijacked using [OpenThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)
* Suspend the target thread with [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
* Retrieve the target thread's context with [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
* Update the target thread's instruction pointer to point to the shellcode
* Commit the hijacked thread's new context with [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
* Resume the hijacked thread with [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
