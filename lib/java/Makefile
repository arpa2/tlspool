CC=g++
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
LDFLAGS=-fPIC -shared

SOURCES_DIR=src/main/cpp
TARGET_DIR=target
OBJECTS_DIR=$(TARGET_DIR)/cpp
EXECUTABLE=$(TARGET_DIR)/classes/libtlspooljni.so

CFLAGS=-c -Wall -fPIC -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(OBJECTS_DIR)

OBJECTS=$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.o $(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.o $(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.o
all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.cpp target/TlspoolSocket-1.0-SNAPSHOT.jar
	$(CC) $(CFLAGS) $< -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.cpp target/TlspoolSocket-1.0-SNAPSHOT.jar
	$(CC) $(CFLAGS) $< -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.cpp target/TlspoolSocket-1.0-SNAPSHOT.jar
	$(CC) $(CFLAGS) $< -o $@

$(TARGET_DIR)/TlspoolSocket-1.0-SNAPSHOT.jar: src/main/java/nl/mansoft/tlspoolsocket/TlspoolSocket.java
	mvn package

clean:
	rm -rf $(TARGET_DIR)
