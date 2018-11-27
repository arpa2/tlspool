#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "TlspoolSocket_PlainInputStream.h"   // Generated

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     TlspoolSocket_PlainInputStream
 * Method:    readPlain
 * Signature: ([BII)I
 */
JNIEXPORT jint JNICALL Java_TlspoolSocket_00024PlainInputStream_readPlain
(JNIEnv *env, jobject thisObj, jbyteArray inJNIArray, jint off, jint len)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	// Get the Field ID of the instance variable "fd"
	jfieldID fidFd = env->GetFieldID(thisClass, "fd", "I");
	if (NULL == fidFd) return 0;
	// Get the int given the Field ID
	jint fd = env->GetIntField(thisObj, fidFd);
	jbyte *inCArray = env->GetByteArrayElements(inJNIArray, NULL);
	if (NULL == inCArray) return 0;
	jsize length = env->GetArrayLength(inJNIArray);
	int bytesread = read(fd, inCArray + off, len);
	env->ReleaseByteArrayElements(inJNIArray, inCArray, 0); // release resources
	return bytesread;
}


#ifdef __cplusplus
}
#endif
