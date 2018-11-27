#include <jni.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef TEST
#ifdef _WIN32
#define FILENAME_CRYPT "c:\\tmp\\crypt.txt"
#define FILENAME_PLAIN "c:\\tmp\\plain.txt"
#else /* _WIN32 */
#define FILENAME_CRYPT "/tmp/crypt.txt"
#define FILENAME_PLAIN "/tmp/plain.txt"
#endif /* _WIN32 */
#else /* TEST */
#include <tlspool/starttls.h>

static starttls_t tlsdata_cli = {
        PIOF_STARTTLS_LOCALROLE_CLIENT
        | PIOF_STARTTLS_REMOTEROLE_SERVER,
        0,
        IPPROTO_TCP,
        0,
        "testcli@tlspool.arpa2.lab",
        "testsrv@tlspool.arpa2.lab"
};

#endif /* TEST */

#ifdef __cplusplus
extern "C" {
#endif
	/*
	 * Class:     TlspoolSocket
	 * Method:    startTls0
	 * Signature: ()I
	 */
	JNIEXPORT jint JNICALL Java_TlspoolSocket_startTls0
	(JNIEnv *env, jobject thisObj)
	{
		int rc = 0;
		// Get a reference to this object's class
		jclass thisClass = env->GetObjectClass(thisObj);
#ifdef TEST
		int cryptfd = open(FILENAME_CRYPT, O_CREAT | O_RDWR, S_IREAD | S_IWRITE);
		// Get the Field ID of the instance variable "cryptfd"
		jfieldID fidCryptfd = env->GetFieldID(thisClass, "cryptfd", "I");
		if (NULL == fidCryptfd) return -1;
		// Get the int given the Field ID
		env->SetIntField(thisObj, fidCryptfd, cryptfd);

		int plainfd = open(FILENAME_PLAIN, O_CREAT | O_RDWR, S_IREAD | S_IWRITE);
		jfieldID fidPlainfd = env->GetFieldID(thisClass, "plainfd", "I");
		if (NULL == fidPlainfd) return -1;
		// Get the int given the Field ID
		env->SetIntField(thisObj, fidPlainfd, plainfd);
#else /* TEST */
		int plainfd = -1;
		int soxx [2];
#ifndef WINDOWS_PORT
		rc = socketpair (AF_UNIX, SOCK_STREAM, 0, soxx);
#else /* WINDOWS_PORT */
		rc = dumb_socketpair(soxx, 1);
#endif /* WINDOWS_PORT */
		if (rc == 0) {
			printf("soxx[0] = %d, soxx[1] = %d\n", soxx[0], soxx[1]);
			// Get the Field ID of the instance variable "cryptfd"
			jfieldID fidCryptfd = env->GetFieldID(thisClass, "cryptfd", "I");
			if (NULL == fidCryptfd) return -1;
			printf("fidCryptfd = %d\n", fidCryptfd);
			// Get the int given the Field ID
			env->SetIntField(thisObj, fidCryptfd, soxx[0]);
			rc = tlspool_starttls (soxx[1], &tlsdata_cli, &plainfd, NULL);
			printf("tlspool_starttls: rc = %d\n", rc);
			if (rc == 0) {
				jfieldID fidPlainfd = env->GetFieldID(thisClass, "plainfd", "I");
				if (NULL == fidPlainfd) return -1;
                                printf("fidPlainfd = %d\n", fidPlainfd);
 				// Get the int given the Field ID
				env->SetIntField(thisObj, fidPlainfd, plainfd);				
			} else {
				perror ("Failed to STARTTLS on testcli");
				if (plainfd >= 0) {
					close (plainfd);
				}
			}
		}
#endif /* TEST */
		return rc;
	}

	/*
	 * Class:     TlspoolSocket
	 * Method:    readEncrypted
	 * Signature: ([BII)I
	 */
	JNIEXPORT jint JNICALL Java_TlspoolSocket_readEncrypted
	(JNIEnv *env, jobject thisObj, jbyteArray inJNIArray, jint off, jint len)
	{
		jbyte *inCArray = env->GetByteArrayElements(inJNIArray, NULL);
		if (NULL == inCArray) return 0;
		jsize length = env->GetArrayLength(inJNIArray);
		// Get a reference to this object's class
		jclass thisClass = env->GetObjectClass(thisObj);

		// Get the Field ID of the instance variable "cryptfd"
		jfieldID fidCryptfd = env->GetFieldID(thisClass, "cryptfd", "I");
		if (NULL == fidCryptfd) return 0;
		// Get the int given the Field ID
		int cryptfd = env->GetIntField(thisObj, fidCryptfd);
		printf("readEncrypted: cryptfd = %d\n", cryptfd);
		int bytesread = read(cryptfd, inCArray + off, len);
		printf("readEncrypted: bytesread = %d\n", bytesread);
		env->ReleaseByteArrayElements(inJNIArray, inCArray, 0); // release resources
		return bytesread;
	}
	/*
	 * Class:     TlspoolSocket
	 * Method:    writeEncrypted
	 * Signature: ([BII)I
	 */
	JNIEXPORT jint JNICALL Java_TlspoolSocket_writeEncrypted
	(JNIEnv *env, jobject thisObj, jbyteArray inJNIArray, jint off, jint len)
	{
		jbyte *inCArray = env->GetByteArrayElements(inJNIArray, NULL);
		if (NULL == inCArray) return 0;
		jsize length = env->GetArrayLength(inJNIArray);
		// Get a reference to this object's class
		jclass thisClass = env->GetObjectClass(thisObj);

		// Get the Field ID of the instance variable "cryptfd"
		jfieldID fidCryptfd = env->GetFieldID(thisClass, "cryptfd", "I");
		if (NULL == fidCryptfd) return 0;
		// Get the int given the Field ID
		int cryptfd = env->GetIntField(thisObj, fidCryptfd);
		printf("writeEncrypted: cryptfd = %d\n", cryptfd);
		int byteswritten = write(cryptfd, inCArray + off, len);
		env->ReleaseByteArrayElements(inJNIArray, inCArray, 0); // release resources
		printf("writeEncrypted: byteswritten = %d\n", byteswritten);
		return byteswritten;
	}

#ifdef __cplusplus
}
#endif
