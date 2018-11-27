#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "TlspoolSocket_PlainOutputStream.h"   // Generated

#ifdef __cplusplus
extern "C" {
#endif

// https://www3.ntu.edu.sg/home/ehchua/programming/java/JavaNativeInterface.html

/*
 * Class:     TlspoolSocket_PlainOutputStream
 * Method:    writePlain
 * Signature: ([BII)V
 */
JNIEXPORT void JNICALL Java_TlspoolSocket_00024PlainOutputStream_writePlain___3BII
(JNIEnv *env, jobject thisObj, jbyteArray inJNIArray, jint off, jint len)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	// Get the Field ID of the instance variable "fd"
	jfieldID fidFd = env->GetFieldID(thisClass, "fd", "I");
	if (NULL == fidFd) return;
	// Get the int given the Field ID
	jint fd = env->GetIntField(thisObj, fidFd);

	jbyte *inCArray = env->GetByteArrayElements(inJNIArray, NULL);
	if (NULL == inCArray) return;
	jsize length = env->GetArrayLength(inJNIArray);
	int byteswritten = write(fd, inCArray + off, len);
	env->ReleaseByteArrayElements(inJNIArray, inCArray, 0); // release resources
}

#ifdef __cplusplus
}
#endif
