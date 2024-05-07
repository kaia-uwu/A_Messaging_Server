#include <iostream>

#include <winsock2.h> // needs to be before windows.h
#include <ws2tcpip.h>
#include <windows.h>

#include <thread>
#include <string>

#pragma comment(lib, "ws2_32.lib") // this includes ws2_32.lib

struct server_params {
	
};

DWORD WINAPI server(LPVOID lpParam) {
	server_params* params = (server_params*)lpParam;

	int errcode; // https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
	timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 500'000; // 0,5s

	WSADATA WSA_data;
	errcode = WSAStartup(0b00000010'00000010, &WSA_data);
	if (errcode) {
		std::cout << "[server] Failed to initialize WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}

	std::cout <<
		"[server] WSA startup successfull. Details:\n" <<
		"> iMaxSockets: " << WSA_data.iMaxSockets << "\n" <<
		"> iMaxUdpDg: " << WSA_data.iMaxUdpDg << "\n" <<
		"> szDescription: " << WSA_data.szDescription << "\n" <<
		"> szSystemStatus: " << WSA_data.szSystemStatus << "\n" <<
		"> wHighVersion: " << (WSA_data.wHighVersion & 0b11111111) << "." << ((WSA_data.wHighVersion & 0b11111111'00000000) >> 8) << "\n" <<
		"> wVersion: " << (WSA_data.wVersion & 0b11111111) << "." << ((WSA_data.wVersion & 0b11111111'00000000) >> 8) << "\n";

	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // TCP - STREAM, UDP - DGRAM (datagram)
	if (server_socket == SOCKET_ERROR) {
		std::cout << "[server] Failed to initialize socket. Error code: " << WSAGetLastError() << "\n";
		if (WSACleanup() == SOCKET_ERROR)
			std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}

	std::cout << "[server] Socket of type Internetwork Stream TCP created successfully.\n";

	SOCKADDR_IN server_addr;
	server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5012);
	errcode = bind(server_socket, (SOCKADDR*)&server_addr, sizeof(SOCKADDR_IN));
	if (errcode == SOCKET_ERROR) {
		std::cout << "[server] Failed to bind socket. Error code: " << WSAGetLastError() << "\n";
		if (closesocket(server_socket) == SOCKET_ERROR)
			std::cout << "[server] Failed to close socket. Error code: " << WSAGetLastError() << "\n";
		if (WSACleanup() == SOCKET_ERROR)
			std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}
	std::cout << "[server] Socket bound successfully to Internetwork any:" << 5012 << ".\n";

	errcode = listen(server_socket, SOMAXCONN);
	if (errcode == SOCKET_ERROR) {
		std::cout << "[server] Failed to start listening. Error code: " << WSAGetLastError() << "\n";
		if (closesocket(server_socket) == SOCKET_ERROR)
			std::cout << "[server] Failed to close socket. Error code: " << WSAGetLastError() << "\n";
		if (WSACleanup() == SOCKET_ERROR)
			std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}
	std::cout << "[server] Listening started with max connection queue size.\n";

	SOCKADDR_IN client_addr;
	INT client_addr_size = sizeof(client_addr);

	const int recv_buffer_len = 1024;
	char* buffer = (char*)malloc(recv_buffer_len);
	if (buffer == nullptr) {
		std::cout << "[server] Failed to allocate recieve buffer.\n";
		if (closesocket(server_socket) == SOCKET_ERROR)
			std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
		if (WSACleanup() == SOCKET_ERROR)
			std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}

	WSAPOLLFD accept_poll;
	accept_poll.fd = server_socket;
	accept_poll.events = POLLRDNORM;

	while (1) {
		int poll_result = WSAPoll(&accept_poll, 1, NULL);
		if (poll_result == SOCKET_ERROR) {
			std::cout << "[server] Failed poll for non-blocking read. Error code: " << WSAGetLastError() << "\n";
			free(buffer);
			if (closesocket(server_socket) == SOCKET_ERROR)
				std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
			if (WSACleanup() == SOCKET_ERROR)
				std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
			return EXIT_FAILURE;
		}
		if (!(accept_poll.revents & POLLRDNORM)) {
			std::cout << "[server] Poll for non-blocking read returned false, polling again in 1s.\n";
			Sleep(1000);
			continue;
		}

		/* !SEE IF THIS IS NEEDED!
		 
		int accept_status = select(NULL, &accept_set, NULL, NULL, NULL);
		if (accept_status == SOCKET_ERROR) {
			std::cout << "[server] Failed to get accept status. Error code: " << WSAGetLastError() << "\n";
			free(buffer);
			if (closesocket(server_socket) == SOCKET_ERROR)
				std::cout << "[server] Failed to close socket. Error code: " << WSAGetLastError() << "\n";
			if (WSACleanup() == SOCKET_ERROR)
				std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
			return EXIT_FAILURE;
		}
		if (accept_status == 0) {
			std::cout << "[server] No accepts pending, polling again in 1s.\n";
			Sleep(1000);
			continue;
		}
		 
		// !SEE IF THIS IS NEEDED! */

		SOCKET client_socket = accept(server_socket, (SOCKADDR*)&client_addr, &client_addr_size);
		if (client_socket == SOCKET_ERROR) {
			std::cout << "[server] Failed to accept client. Error code: " << WSAGetLastError() << "\n";
			free(buffer);
			if (closesocket(client_socket) == SOCKET_ERROR)
				std::cout << "[server] Failed to close client socket. Error code: " << WSAGetLastError() << "\n";
			if (closesocket(server_socket) == SOCKET_ERROR)
				std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
			if (WSACleanup() == SOCKET_ERROR)
				std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
			return EXIT_FAILURE;
		}

		char address[16];
		inet_ntop(AF_INET, &client_addr.sin_addr.S_un.S_addr, address, 16);
		std::cout <<
			"[server] Client accepted successfully. Details:\n" <<
			"> Address:" << address << "\n" <<
			"> Port:" << client_addr.sin_port << "\n";

		bool client_alive = true;
		while (client_alive) {
			/* !SEE IF THIS IS NEEDED!
			FD_ZERO(&read_set);
			FD_SET(client_socket, &read_set);
			FD_ZERO(&write_set);
			FD_SET(client_socket, &write_set);
			// !SEE IF THIS IS NEEDED! */

			WSAPOLLFD read_write_poll;
			read_write_poll.fd = client_socket;
			read_write_poll.events = POLLRDNORM | POLLWRNORM;

			std::cout << "[server] Connection alive.\n";

			while (1) {
				int poll_result = WSAPoll(&read_write_poll, 1, NULL);
				if (poll_result == SOCKET_ERROR) {
					std::cout << "[server] Failed poll non-blocking read/write. Error code: " << WSAGetLastError() << "\n";
					free(buffer);
					if (closesocket(client_socket) == SOCKET_ERROR)
						std::cout << "[server] Failed to close client socket. Error code: " << WSAGetLastError() << "\n";
					if (closesocket(server_socket) == SOCKET_ERROR)
						std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
					if (WSACleanup() == SOCKET_ERROR)
						std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
					return EXIT_FAILURE;
				}
				if (read_write_poll.revents & POLLERR) {
					std::cout << "[server] Polled for non-blocking read/write and got error, terminating connection.\n";
					client_alive = false;
					break;
				}
				if (read_write_poll.revents & POLLHUP) {
					std::cout << "[server] Polled for non-blocking read/write and got disconnect/abort, terminating connection.\n";
					client_alive = false;
					break;
				}
				if (read_write_poll.revents & POLLRDNORM) {
					int bytes_to_read = recv(client_socket, buffer, 1, MSG_PEEK); // peeking to see how many bytes are pending
					if (bytes_to_read == SOCKET_ERROR) {
						errcode = WSAGetLastError();
						if (errcode == 10054) {
							std::cout << "[server] Peek failed with WSACONNRESET, terminating connection.\n";
							client_alive = false;
							break;
						}
						std::cout << "[server] Failed to peek data. Error code: " << errcode << ")\n";
					}
					if (bytes_to_read == 0) {
						std::cout << "[server] Peeked no data.\n";
					}
					else {
						memset(buffer, 0, recv_buffer_len);
						int bytes_read = recv(client_socket, buffer, recv_buffer_len - 1, NULL);
						if (bytes_read == SOCKET_ERROR) {
							errcode = WSAGetLastError();
							if (errcode == 10054) {
								std::cout << "[server] Read failed with WSACONNRESET, terminating connection.\n";
								client_alive = false;
								break;
							}
							std::cout << "[server] Failed to recieve data. Error code: " << errcode << "\n";
							free(buffer);
							if (closesocket(client_socket) == SOCKET_ERROR)
								std::cout << "[server] Failed to close client socket. Error code: " << WSAGetLastError() << "\n";
							if (closesocket(server_socket) == SOCKET_ERROR)
								std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
							if (WSACleanup() == SOCKET_ERROR)
								std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
							return EXIT_FAILURE;
						}
						std::cout << "[server] Read " << bytes_read << " bytes.\n";
						if (bytes_read) {
							std::cout << buffer;
						}
					}
				}
				if (read_write_poll.revents & POLLWRNORM) {
					// DEBUG - SENDING SOME HTML
					
					const char* content = 
						"<!DOCTYPE html>\r\n"
						"<html>\r\n"
						"	<head>\r\n"
						"		<title>AMS default HTML response.</title>\r\n"
						"	</head>\r\n"
						"	<body style=\"position:absolute;width:100%;height:100%;margin:0px;background-color:#323232;color:floralwhite;font-family:courier;text-align:center;\">\r\n"
						"		<h1 style=\"margin-top:2rem;color:lightpink;\">Hello from AMS :3</h1>\r\n"
						"		<h3>Im still kind of surprised that this works, nice!</h3>\r\n"
						"		<p>\r\n"
						"			This is a paragraph.<br>\r\n"
						"			I'd put data here but this is just a test and im not doing more strcat_s's.<br>\r\n"
						"			This is just a demonstration of the capability of the AMS socketserver.<br>\r\n"
						"			Really it's not supposed to do this at all...<br>\r\n"
						"			...But I felt like it~"
						"		</p>\r\n"
						"       <div style=\"position:fixed;bottom:1rem;width:100%;\">\r\n"
						"			<hr>\r\n"
						"			<p>[by: me, made with: c++]</p>\r\n"
						"       </div>\r\n"			
						"	</body>\r\n"
						"</html>\r\n";
					
					int result_size = 1024;
					char* result = (char*)malloc(result_size);
					memset(result, 0, result_size);
					strcpy_s(result, result_size, "HTTP/1.1 200 OK\r\nContent-Length: ");
					strcat_s(result, result_size, (std::to_string(strlen(content))).c_str());
					strcat_s(result, result_size, "\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n");
					strcat_s(result, result_size, content);
					
					send(client_socket, result, strlen(result), NULL);
					
					std::cout << "[server] Sent HTML and disconnected client.\n";
					client_alive = false;
					break;
					
					// DEBUG - SENDING SOME HTML			
				}
			}
		}

		errcode = closesocket(client_socket);
		if (errcode == SOCKET_ERROR) {
			std::cout << "[server] Failed to close client socket. Error code: " << WSAGetLastError() << "\n";
			free(buffer);
			if (closesocket(server_socket) == SOCKET_ERROR)
				std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
			if (WSACleanup() == SOCKET_ERROR)
				std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
			return EXIT_FAILURE;
		}
		std::cout << "[server] Closed client socket.\n";
	}
	free(buffer);

	errcode = closesocket(server_socket);
	if (errcode == SOCKET_ERROR) {
		std::cout << "[server] Failed to close server socket. Error code: " << WSAGetLastError() << "\n";
		if (WSACleanup() == SOCKET_ERROR)
			std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}
	std::cout << "[server] Socket closed successfully.\n";

	errcode = WSACleanup();
	if (errcode) {
		std::cout << "[server] Failed to clean up WSA. Error code: " << errcode << "\n";
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main()
{
	HWND hwnd = GetConsoleWindow();
	HANDLE console_in_handle = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE console_out_handle = GetStdHandle(STD_OUTPUT_HANDLE);

	std::cout << "[AMS v1.1, welcome :3]\n";

	SECURITY_ATTRIBUTES server_sec_attr;
	server_sec_attr.bInheritHandle = true;
	server_sec_attr.lpSecurityDescriptor = NULL;
	server_sec_attr.nLength = sizeof(server_sec_attr);
	DWORD server_id;

	server_params params;
	HANDLE server_handle = CreateThread(&server_sec_attr, NULL, server, &params, 0, &server_id);
	if (server_handle == 0) {
		return EXIT_FAILURE;
	}

	DWORD server_exit_code;
	while (1) {
		Sleep(500);
		if (GetExitCodeThread(server_handle, &server_exit_code)) {
			if (server_exit_code != STILL_ACTIVE) {
				std::cout << "Server exited with code: " << server_exit_code << "\n";
				break;
			}
		}
	}
}