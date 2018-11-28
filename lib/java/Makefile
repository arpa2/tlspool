CC=g++
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
CFLAGS=-c -Wall -fPIC -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
LDFLAGS=-fPIC -shared

SOURCES_DIR=src/main/cpp
OBJECTS_DIR=target/cpp
EXECUTABLE=target/classes/libtlspooljni.so
OBJECTS=$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.o $(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.o $(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.o
all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket.cpp
	$(CC) $(CFLAGS) $< -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainInputStream.cpp
	$(CC) $(CFLAGS) $< -o $@

$(OBJECTS_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.o: $(SOURCES_DIR)/nl_mansoft_tlspoolsocket_TlspoolSocket_PlainOutputStream.cpp
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS_DIR) $(EXECUTABLE)
