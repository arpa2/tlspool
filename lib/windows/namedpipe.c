#include "whoami.h"
#include <stdio.h>
#include <tlspool/starttls.h>
#include <tlspool/commands.h>
#include <winsock2.h>

#define _tprintf printf
pool_handle_t open_named_pipe (LPCTSTR lpszPipename)
{
	HANDLE hPipe;
	//struct tlspool_command chBuf;
	BOOL   fSuccess = FALSE;
	DWORD  dwMode;

	// Try to open a named pipe; wait for it, if necessary.

	while (1)
	{
		hPipe = CreateFile(
			lpszPipename,   // pipe name
			GENERIC_READ |  // read and write access
			GENERIC_WRITE,
			0,              // no sharing
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe
			FILE_FLAG_OVERLAPPED, // overlapped
			NULL);          // no template file

		// Break if the pipe handle is valid.
		if (hPipe != INVALID_POOL_HANDLE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs.
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			_tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
			return INVALID_POOL_HANDLE;
		}

		// All pipe instances are busy, so wait for 20 seconds.
		if (!WaitNamedPipe(lpszPipename, 20000))
		{
			printf("Could not open pipe: 20 second wait timed out.");
			return INVALID_POOL_HANDLE;
		}
	}
	// The pipe connected; change to message-read mode.
	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle
		&dwMode,  // new pipe mode
		NULL,     // don't set maximum bytes
		NULL);    // don't set maximum time
	if (!fSuccess)
	{
		_tprintf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
		return INVALID_POOL_HANDLE;
	}
	ULONG ServerProcessId;
	if (GetNamedPipeServerProcessId(hPipe, &ServerProcessId)) {
		printf("GetNamedPipeServerProcessId: ServerProcessId = %ld\n", ServerProcessId);
	} else {
		_tprintf(TEXT("GetNamedPipeServerProcessId failed. GLE=%d\n"), GetLastError());
	}
	return hPipe;
}


int np_send_command(pool_handle_t poolfd, struct tlspool_command *cmd) {
	DWORD  cbToWrite, cbWritten;
	OVERLAPPED overlapped;
	BOOL fSuccess;

	/* Send the request */
	// Send a message to the pipe server.

	cbToWrite = sizeof (struct tlspool_command);
	_tprintf(TEXT("Sending %d byte cmd\n"), cbToWrite);

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	fSuccess = WriteFile(
		poolfd,                // pipe handle
		cmd,                   // cmd message
		cbToWrite,             // cmd message length
		NULL,                  // bytes written
		&overlapped);          // overlapped

	if (!fSuccess && GetLastError() == ERROR_IO_PENDING )
	{
// printf ("DEBUG: Write I/O pending\n");
		fSuccess = WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0;
	}

	if (fSuccess) {
		fSuccess = GetOverlappedResult(poolfd, &overlapped, &cbWritten, TRUE);
	}

	if (!fSuccess)
	{
		_tprintf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
		return -1;
	} else {
printf ("DEBUG: Wrote %ld bytes to pipe\n", cbWritten);
	}
printf("DEBUG: Message sent to server, receiving reply as follows:\n");
	return 0;
}


int np_recv_command(pool_handle_t poolfd, struct tlspool_command *cmd) {
	DWORD cbToRead, cbRead;
	OVERLAPPED overlapped;
	BOOL fSuccess;

	cbToRead = sizeof (struct tlspool_command);
	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	// Read from the pipe.
	fSuccess = ReadFile(
		poolfd,       // pipe handle
		cmd,          // buffer to receive reply
		cbToRead,     // size of buffer
		NULL,         // number of bytes read
		&overlapped); // not overlapped

	if (!fSuccess && GetLastError() == ERROR_IO_PENDING )
	{
printf ("DEBUG: Read I/O pending\n");
		fSuccess = WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0;
	}

	if (fSuccess) {
		fSuccess = GetOverlappedResult(poolfd, &overlapped, &cbRead, TRUE);
	}

	if (!fSuccess)
	{
		_tprintf(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
		return -1;
	} else {
printf ("DEBUG: Read %ld bytes from pipe\n", cbRead);
	}
	return 0;
}

