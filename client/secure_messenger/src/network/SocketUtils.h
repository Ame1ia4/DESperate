#pragma once

// Platform socket abstraction used by TLSManager's Worker.
// Isolates all OS-specific socket API differences in one place.

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using sock_t = SOCKET;
   static constexpr sock_t kInvalidSock = INVALID_SOCKET;
   static void closeSock(sock_t s)   { ::closesocket(s); }
   static bool sockInvalid(sock_t s) { return s == INVALID_SOCKET; }
   static void setNonBlocking(sock_t s, bool on) {
       u_long mode = on ? 1 : 0;
       ::ioctlsocket(s, FIONBIO, &mode);
   }
   static bool connectInProgress() {
       const int e = WSAGetLastError();
       return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
   }
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#  include <signal.h>
   using sock_t = int;
   static constexpr sock_t kInvalidSock = -1;
   static void closeSock(sock_t s)   { ::close(s); }
   static bool sockInvalid(sock_t s) { return s < 0; }
   static void setNonBlocking(sock_t s, bool on) {
       int flags = ::fcntl(s, F_GETFL, 0);
       ::fcntl(s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
   }
   static bool connectInProgress() { return errno == EINPROGRESS; }
#endif

static constexpr int kConnectTimeoutSecs = 10;
