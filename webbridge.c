#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <locale.h>
#include <ctype.h>

#define DEFAULT_PORT 8080       // Default port to run the server on
#define CHUNK_SIZE 8192         // Size of the chunk to read from the socket
#define TIMEOUT 10              // Timeout in seconds for receiving data

char base_directory[256] = "."; // Base directory for file storage
int server_port = DEFAULT_PORT; // Server port number
char text_filename[256] = "";   // Name of the text file to display
char *text_file_content = NULL; // Content of the text file to display

// Function prototypes
void print_help();
int hex_to_int(char c);
void url_decode(char *src, char *dest);
void urlencode(const char *src, char *dest, size_t dest_size);
void sanitize_path(char *path);
void send_response(int client_socket, const char *status,
                   const char *content_type, const char *body);
void send_directory_listing(int client_socket, const char *request_path);
void serve_file(int client_socket, const char *request_path);
void handle_text_submission(int client_socket, const char *body, size_t body_length, const char *current_path);
void handle_request(int client_socket);
void handle_file_upload(int client_socket, const char *initial_body,
                        size_t initial_body_length, const char *boundary,
                        int content_length, const char *current_path);
void mkdir_recursive(const char *dir);

// Function to extract filename from the Content-Disposition header
void extract_filename(char *header, char *filename) {
    char *pos = strstr(header, "filename=");
    if (pos) {
        pos += 9;  // Skip 'filename='
        if (*pos == '"' || *pos == '\'') {
            char quote = *pos++;
            char *end = strchr(pos, quote);
            if (end) {
                *end = '\0';
            }
            strncpy(filename, pos, 255);
            filename[255] = '\0';
        } else {
            char *end = strpbrk(pos, ";\r\n");
            if (end) {
                *end = '\0';
            }
            strncpy(filename, pos, 255);
            filename[255] = '\0';
        }
    } else {
        strcpy(filename, "uploaded_file");
    }
}

// Set a timeout for receiving data from the socket
void set_socket_timeout(int socket_fd) {
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               sizeof(timeout));
}

// Function to URL-decode a string
void url_decode(char *src, char *dest) {
    char *pstr = src, *pbuf = dest;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = (char)((hex_to_int(pstr[1]) << 4) | hex_to_int(pstr[2]));
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
}

// Helper function to convert hex character to int
int hex_to_int(char c) {
    c = tolower((unsigned char)c);
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

// Function to URL-encode a string
void urlencode(const char *src, char *dest, size_t dest_size) {
    const char *hex = "0123456789ABCDEF";
    size_t i = 0;
    while (*src && i < dest_size - 1) {
        if (isalnum((unsigned char)*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dest[i++] = *src;
        } else {
            if (i + 3 >= dest_size) break;
            dest[i++] = '%';
            dest[i++] = hex[(*src >> 4) & 0xF];
            dest[i++] = hex[*src & 0xF];
        }
        src++;
    }
    dest[i] = '\0';
}

// Function to sanitize the path to prevent directory traversal attacks
void sanitize_path(char *path) {
    char sanitized[1024] = "";
    char *token;
    char *rest = path;
    while ((token = strtok_r(rest, "/", &rest))) {
        if (strcmp(token, "..") == 0) continue; // Skip parent directory references
        if (strlen(sanitized) + strlen(token) + 2 >= sizeof(sanitized)) break;
        strcat(sanitized, "/");
        strcat(sanitized, token);
    }
    if (strlen(sanitized) == 0) strcpy(sanitized, "/");
    strcpy(path, sanitized);
}

// Function to send an HTTP response
void send_response(int client_socket, const char *status,
                   const char *content_type, const char *body) {
    char response[CHUNK_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n\r\n%s",
             status, content_type, strlen(body), body);
    send(client_socket, response, strlen(response), 0);
}

// Function to create directories recursively
void mkdir_recursive(const char *dir) {
    char tmp[1024];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    }
    mkdir(tmp, S_IRWXU);
}

// Send directory listing as an HTML response with additional features
void send_directory_listing(int client_socket, const char *request_path) {
    DIR *dir;
    struct dirent *entry;

    // Sanitize the request path
    char sanitized_path[1024];
    strncpy(sanitized_path, request_path, sizeof(sanitized_path) - 1);
    sanitized_path[sizeof(sanitized_path) - 1] = '\0';
    sanitize_path(sanitized_path);

    // Build the full directory path
    char directory_path[2048];
    snprintf(directory_path, sizeof(directory_path), "%s%s", base_directory, sanitized_path);

    // Open the directory
    dir = opendir(directory_path);
    if (!dir) {
        send_response(client_socket, "404 Not Found", "text/plain",
                      "Directory not found");
        return;
    }

    // Collect directories and files separately
    struct dirent **namelist;
    int n = scandir(directory_path, &namelist, NULL, alphasort);
    if (n < 0) {
        send_response(client_socket, "500 Internal Server Error", "text/plain",
                      "Failed to read directory");
        closedir(dir);
        return;
    }

    // Calculate the required buffer size
    size_t body_size = CHUNK_SIZE * 5;  // Base size for HTML structure
    if (text_file_content) {
        body_size += strlen(text_file_content);
    }

    // Estimate additional size needed for directory listing
    body_size += 1024 * n;  // Assuming up to 1 KB per entry

    // Allocate body dynamically
    char *body = malloc(body_size);
    if (body == NULL) {
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Memory allocation failed");
        closedir(dir);
        return;
    }

    size_t offset = 0;
offset += snprintf(body + offset, body_size - offset,
                   "<html><head><style>"
                   "body { font-family: Arial, sans-serif;"
                   " background-color: #f4f4f4; padding: 10px; }"
                   "h1, h2 { color: #333; font-size: 18px; margin-bottom: 10px; }"
                   "form { margin-bottom: 15px; padding: 8px;"
                   " background-color: #e9e9e9;"
                   " border-radius: 5px; }"
                   "input[type=file], textarea { padding: 5px; width: 100%%; "
                   " font-size: 14px; }"
                   "input[type=submit] { padding: 6px 12px;"
                   " background-color: #4CAF50; color: white;"
                   " border: none; cursor: pointer;"
                   " margin-top: 8px; font-size: 14px; }"
                   "table { width: 100%%; border-collapse: collapse; }"
                   "th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }"
                   "th { background-color: #f2f2f2; }"
                   "tr:nth-child(even) { background-color: #eaf5ff; }"  // Sky blue for even rows
                   "tr:nth-child(odd) { background-color: whitesmoke; }"   // Silver for odd rows
                   "a { text-decoration: none; color: #333; }"
                   "a:hover { text-decoration: underline; }"
                   "textarea { resize: vertical; min-height: 50px; max-height: 150px;"
                   " font-size: 14px; }"
                   ".directory { font-weight: bold; }"
                   "</style></head><body>");


    // Display the content of the text file if available
    if (text_file_content) {
        offset += snprintf(body + offset, body_size - offset,
                           "<h1>Text Content</h1>"
                           "<textarea readonly rows=\"5\">%s</textarea><hr>",
                           text_file_content);
    }

    // URL-encode the sanitized path for use in form actions
    char encoded_sanitized_path[1024];
    urlencode(sanitized_path, encoded_sanitized_path, sizeof(encoded_sanitized_path));

    // Text area for users to submit text to append to a file
    offset += snprintf(body + offset, body_size - offset,
                       "<h1>Submit Text</h1>"
                       "<form action=\"/submit-text%s\" method=\"post\">"
                       "<textarea name=\"user_text\" rows=\"3\" placeholder=\"Enter text to submit...\"></textarea>"
                       "<input type=\"submit\" value=\"Submit Text\"></form><hr>", encoded_sanitized_path);

    // File upload form
    offset += snprintf(body + offset, body_size - offset,
                       "<h1>File Upload</h1>"
                       "<form action=\"/upload%s\" method=\"post\" "
                       "enctype=\"multipart/form-data\">"
                       "Select files: <input type=\"file\" name=\"files[]\" multiple>"
                       "<input type=\"submit\" value=\"Upload to %s\">"
                       "</form><hr>", encoded_sanitized_path, sanitized_path);

    // Directory listing
    offset += snprintf(body + offset, body_size - offset,
                       "<h2>Files in Directory: %s</h2>"
                       "<table>"
                       "<tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>", sanitized_path);

    // Include '..' to go back to parent directory if not in root
    if (strcmp(sanitized_path, "/") != 0) {
        // Build parent directory path
        char parent_path[1024];
        strncpy(parent_path, sanitized_path, sizeof(parent_path));
        parent_path[sizeof(parent_path) - 1] = '\0';
        char *last_slash = strrchr(parent_path, '/');
        if (last_slash && last_slash != parent_path) {
            *last_slash = '\0';
        } else {
            strcpy(parent_path, "/");
        }

        offset += snprintf(body + offset, body_size - offset,
                           "<tr>"
                           "<td><a href=\"%s\">..</a></td>"
                           "<td></td>"
                           "<td></td>"
                           "</tr>", parent_path);
    }

    // First, list directories
    for (int i = 0; i < n; i++) {
        entry = namelist[i];
        if (entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char full_path[4096];
                snprintf(full_path, sizeof(full_path), "%s/%s", directory_path, entry->d_name);
                struct stat file_stat;
                if (stat(full_path, &file_stat) == 0 && S_ISDIR(file_stat.st_mode)) {
                    // Format modification time
                    char time_str[64];
                    struct tm *tm_info = localtime(&file_stat.st_mtime);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                    // URL-encode the entry name
                    char encoded_name[1024];
                    urlencode(entry->d_name, encoded_name, sizeof(encoded_name));

                    // Build the full URL path
                    char url_path[2048];
                    if (strcmp(sanitized_path, "/") == 0) {
                        snprintf(url_path, sizeof(url_path), "/%s", encoded_name);
                    } else {
                        snprintf(url_path, sizeof(url_path), "%s/%s", sanitized_path, encoded_name);
                    }

                    // Generate the table row
                    offset += snprintf(body + offset, body_size - offset,
                                       "<tr>"
                                       "<td class=\"directory\"><a href=\"%s\">[ %s ]</a></td>"
                                       "<td>-</td>"
                                       "<td>%s</td>"
                                       "</tr>",
                                       url_path,
                                       entry->d_name,
                                       time_str);
                }
            }
        }
    }

    // Then, list files
    for (int i = 0; i < n; i++) {
        entry = namelist[i];
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) {
            char full_path[4096];
            snprintf(full_path, sizeof(full_path), "%s/%s", directory_path, entry->d_name);
            struct stat file_stat;
            if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                // Format file size and modification time
                char time_str[64];
                struct tm *tm_info = localtime(&file_stat.st_mtime);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                // Format file size
                char size_str[32];
                snprintf(size_str, sizeof(size_str), "%'ld bytes", file_stat.st_size);

                // URL-encode the entry name
                char encoded_name[1024];
                urlencode(entry->d_name, encoded_name, sizeof(encoded_name));

                // Build the full URL path
                char url_path[2048];
                if (strcmp(sanitized_path, "/") == 0) {
                    snprintf(url_path, sizeof(url_path), "/%s", encoded_name);
                } else {
                    snprintf(url_path, sizeof(url_path), "%s/%s", sanitized_path, encoded_name);
                }

                // Generate the table row
                offset += snprintf(body + offset, body_size - offset,
                                   "<tr>"
                                   "<td><a href=\"%s\">%s</a></td>"
                                   "<td>%s</td>"
                                   "<td>%s</td>"
                                   "</tr>",
                                   url_path,
                                   entry->d_name,
                                   size_str,
                                   time_str);
            }
        }
    }

    // Free the namelist
    for (int i = 0; i < n; i++) {
        free(namelist[i]);
    }
    free(namelist);
    closedir(dir);

    offset += snprintf(body + offset, body_size - offset, "</table></body></html>");

    send_response(client_socket, "200 OK", "text/html", body);

    // Free allocated memory
    free(body);
}

// Serve the requested file
void serve_file(int client_socket, const char *request_path) {
    // Sanitize the request path
    char sanitized_path[1024];
    strncpy(sanitized_path, request_path, sizeof(sanitized_path) - 1);
    sanitized_path[sizeof(sanitized_path) - 1] = '\0';
    sanitize_path(sanitized_path);

    // Build the full file path
    char file_path[2048];
    snprintf(file_path, sizeof(file_path), "%s%s", base_directory, sanitized_path);

    // Open the file
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        send_response(client_socket, "404 Not Found", "text/plain",
                      "File not found");
        return;
    }

    // Get the file extension to determine the content type
    const char *extension = strrchr(file_path, '.');
    const char *content_type = "application/octet-stream"; // Default content type
    int inline_display = 0; // Flag to determine if file should be displayed inline

    if (extension) {
        if (strcmp(extension, ".html") == 0 || strcmp(extension, ".htm") == 0) {
            content_type = "text/html";
            inline_display = 1;
        } else if (strcmp(extension, ".txt") == 0) {
            content_type = "text/plain";
            inline_display = 1;
        } else if (strcmp(extension, ".css") == 0) {
            content_type = "text/css";
            inline_display = 1;
        } else if (strcmp(extension, ".js") == 0) {
            content_type = "application/javascript";
            inline_display = 1;
        } else if (strcmp(extension, ".png") == 0) {
            content_type = "image/png";
            inline_display = 1;
        } else if (strcmp(extension, ".jpg") == 0 || strcmp(extension, ".jpeg") == 0) {
            content_type = "image/jpeg";
            inline_display = 1;
        } else if (strcmp(extension, ".gif") == 0) {
            content_type = "image/gif";
            inline_display = 1;
        }
    }

    // Send the file as an HTTP response
    struct stat file_stat;
    fstat(file_fd, &file_stat);

    // Build the HTTP response header
    char header[CHUNK_SIZE];
    if (inline_display) {
        // For inline display, set Content-Disposition to inline or omit it
        snprintf(header, sizeof(header),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Length: %ld\r\n"
                 "Content-Type: %s\r\n"
                 "Connection: close\r\n\r\n",
                 file_stat.st_size, content_type);
    } else {
        // For other files, prompt download
        // Extract the filename from the path
        const char *filename = strrchr(file_path, '/');
        if (filename) {
            filename++; // Move past the '/'
        } else {
            filename = file_path; // No '/' found, use the whole path
        }

        // URL-encode the filename for Content-Disposition header
        char encoded_filename[256];
        urlencode(filename, encoded_filename, sizeof(encoded_filename));

        snprintf(header, sizeof(header),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Length: %ld\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "Connection: close\r\n\r\n",
                 file_stat.st_size, content_type, encoded_filename);
    }

    send(client_socket, header, strlen(header), 0);

    // Send file content
    ssize_t bytes_read;
    char file_buffer[CHUNK_SIZE];
    while ((bytes_read = read(file_fd, file_buffer, CHUNK_SIZE)) > 0) {
        send(client_socket, file_buffer, bytes_read, 0);
    }

    close(file_fd);
}

// Function to handle text submission
void handle_text_submission(int client_socket, const char *body, size_t body_length, const char *current_path) {
    // Extract the text from the body
    char *user_text = strstr(body, "user_text=");
    if (!user_text) {
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "No text found in the submission");
        return;
    }
    user_text += strlen("user_text=");

    // URL decode the text
    char decoded_text[CHUNK_SIZE];
    url_decode(user_text, decoded_text);

    // Append the text to a file in the current directory
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s/submitted_text.txt", base_directory, current_path);

    // Ensure the directory exists
    char dir_path[1024];
    snprintf(dir_path, sizeof(dir_path), "%s%s", base_directory, current_path);
    mkdir_recursive(dir_path);

    int file_fd = open(full_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (file_fd < 0) {
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Cannot save submitted text");
        return;
    }
    // Write the text with a preceding \r\n
    write(file_fd, "\r\n", 2);
    write(file_fd, decoded_text, strlen(decoded_text));
    close(file_fd);

    // Send a response back to the user
    send_response(client_socket, "200 OK", "text/plain",
                  "Text submitted successfully");
}

// Function to handle incoming HTTP requests
void handle_request(int client_socket) {
    char buffer[CHUNK_SIZE];
    int bytes_received;
    int total_received = 0;
    int header_received = 0;
    char *header_end;

    // Initialize buffer
    memset(buffer, 0, sizeof(buffer));

    // Read request headers
    while ((bytes_received = recv(client_socket, buffer + total_received,
                                  sizeof(buffer) - total_received - 1, 0)) > 0) {
        total_received += bytes_received;
        buffer[total_received] = '\0'; // Null-terminate
        // Check if we have received the end of headers
        header_end = strstr(buffer, "\r\n\r\n");
        if (header_end) {
            header_received = 1;
            break;
        }
        if (total_received >= sizeof(buffer) - 1) {
            // Buffer overflow
            send_response(client_socket, "400 Bad Request", "text/plain",
                          "Header too large");
            close(client_socket);
            return;
        }
    }

    if (bytes_received <= 0) {
        // Error or connection closed
        close(client_socket);
        return;
    }

    if (!header_received) {
        // Headers not fully received
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "Incomplete headers");
        close(client_socket);
        return;
    }

    // Now we have the headers in buffer
    // Parse the request line
    char method[16], path[256], protocol[16];
    sscanf(buffer, "%s %s %s", method, path, protocol);

    // URL decode the path
    char decoded_path[256];
    url_decode(path, decoded_path);

    // Initialize current_path
    char current_path[256] = "/";

    // Parse headers
    char *headers = buffer;
    char *body = header_end + 4;
    size_t header_length = body - buffer;
    size_t body_length = total_received - header_length;

    // Extract Content-Length header if present
    int content_length = 0;
    char *content_length_str = strstr(headers, "Content-Length:");
    if (content_length_str) {
        content_length_str += strlen("Content-Length:");
        while (*content_length_str == ' ') content_length_str++;
        content_length = atoi(content_length_str);
    }

    // Extract boundary from Content-Type header if present
    char *boundary = NULL;
    char boundary_value[256];
    char *content_type = strstr(headers, "Content-Type:");
    if (content_type) {
        char *boundary_start = strstr(content_type, "boundary=");
        if (boundary_start) {
            boundary_start += strlen("boundary=");
            // Handle optional quotes around boundary value
            if (*boundary_start == '"') {
                boundary_start++;
                char *boundary_end = strchr(boundary_start, '"');
                if (boundary_end) {
                    size_t boundary_length = boundary_end - boundary_start;
                    strncpy(boundary_value, boundary_start, boundary_length);
                    boundary_value[boundary_length] = '\0';
                    boundary = boundary_value;
                }
            } else {
                char *boundary_end = strpbrk(boundary_start, ";\r\n");
                if (boundary_end) {
                    size_t boundary_length = boundary_end - boundary_start;
                    strncpy(boundary_value, boundary_start, boundary_length);
                    boundary_value[boundary_length] = '\0';
                    boundary = boundary_value;
                } else {
                    strcpy(boundary_value, boundary_start);
                    boundary = boundary_value;
                }
            }
        }
    }

    if (strcmp(method, "GET") == 0) {
        // Check if the path corresponds to a directory
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s%s", base_directory, decoded_path);
        struct stat path_stat;
        if (stat(full_path, &path_stat) == 0) {
            if (S_ISDIR(path_stat.st_mode)) {
                // Serve directory listing
                send_directory_listing(client_socket, decoded_path);
            } else {
                // Serve file download
                serve_file(client_socket, decoded_path);
            }
        } else {
            send_response(client_socket, "404 Not Found", "text/plain",
                          "File or directory not found");
        }
    } else if (strcmp(method, "POST") == 0 &&
               strncmp(decoded_path, "/upload", 7) == 0) {
        // Extract current_path from the path after '/upload'
        strcpy(current_path, decoded_path + 7); // Get the path after '/upload'
        if (strlen(current_path) == 0) {
            strcpy(current_path, "/");
        }
        // Sanitize current_path
        sanitize_path(current_path);

        // Handle file upload
        if (!boundary) {
            send_response(client_socket, "400 Bad Request", "text/plain",
                          "Boundary not found");
            close(client_socket);
            return;
        }

        // Pass the client_socket and boundary to the file upload handler
        handle_file_upload(client_socket, body, body_length, boundary,
                           content_length, current_path);
    } else if (strcmp(method, "POST") == 0 &&
               strncmp(decoded_path, "/submit-text", 12) == 0) {
        // Extract current_path from the path after '/submit-text'
        strcpy(current_path, decoded_path + 12); // Get the path after '/submit-text'
        if (strlen(current_path) == 0) {
            strcpy(current_path, "/");
        }
        // Sanitize current_path
        sanitize_path(current_path);

        // Handle text submission
        // Read the remaining body if necessary
        if (content_length > body_length) {
            int remaining = content_length - body_length;
            if (remaining + total_received > sizeof(buffer) - 1) {
                // Buffer overflow
                send_response(client_socket, "400 Bad Request", "text/plain",
                              "Request too large");
                close(client_socket);
                return;
            }
            bytes_received = recv(client_socket, buffer + total_received, remaining, 0);
            if (bytes_received <= 0) {
                // Error or connection closed
                close(client_socket);
                return;
            }
            total_received += bytes_received;
            buffer[total_received] = '\0'; // Null-terminate
            body_length += bytes_received;
            body = header_end + 4; // Recalculate body pointer
        }
        handle_text_submission(client_socket, body, body_length, current_path);
    } else {
        send_response(client_socket, "501 Not Implemented", "text/plain",
                      "Method not supported");
    }

    close(client_socket);
}

void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    const unsigned char *haystack_ptr = haystack;
    const unsigned char *needle_ptr = needle;
    size_t i;
    for (i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(haystack_ptr + i, needle_ptr, needlelen) == 0) {
            return (void *)(haystack_ptr + i);
        }
    }
    return NULL;
}

// Function to handle file uploads
void handle_file_upload(int client_socket, const char *initial_body,
                        size_t initial_body_length, const char *boundary,
                        int content_length, const char *current_path) {
    // Initialize variables
    char buffer[CHUNK_SIZE];
    size_t total_received = initial_body_length;
    //size_t content_remaining = content_length - initial_body_length;
    ssize_t bytes_received;
    int file_fd = -1;
    char filename[256] = "";
    char boundary_str[256];
    char end_boundary_str[256];
    snprintf(boundary_str, sizeof(boundary_str), "--%s", boundary);
    snprintf(end_boundary_str, sizeof(end_boundary_str), "--%s--", boundary);
    size_t boundary_len = strlen(boundary_str);
    size_t end_boundary_len = strlen(end_boundary_str);
    int in_file = 0;

    // Buffer to hold data for processing
    char *data_buffer = malloc(CHUNK_SIZE * 2);
    if (!data_buffer) {
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Memory allocation failed");
        return;
    }
    size_t data_buffer_len = 0;
    size_t data_buffer_capacity = CHUNK_SIZE * 2;

    // Copy initial body data to data_buffer
    memcpy(data_buffer, initial_body, initial_body_length);
    data_buffer_len = initial_body_length;

    // Read remaining data from client
    while (total_received < (size_t)content_length) {
        bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            // Error or connection closed
            if (file_fd != -1) close(file_fd);
            free(data_buffer);
            close(client_socket);
            return;
        }
        total_received += bytes_received;

        // Ensure data_buffer has enough capacity
        if (data_buffer_len + bytes_received > data_buffer_capacity) {
            data_buffer_capacity *= 2;
            char *new_buffer = realloc(data_buffer, data_buffer_capacity);
            if (!new_buffer) {
                send_response(client_socket, "500 Internal Server Error",
                              "text/plain", "Memory allocation failed");
                if (file_fd != -1) close(file_fd);
                free(data_buffer);
                return;
            }
            data_buffer = new_buffer;
        }

        // Append new data to data_buffer
        memcpy(data_buffer + data_buffer_len, buffer, bytes_received);
        data_buffer_len += bytes_received;
    }

    // Process data_buffer
    size_t pos = 0;
    while (pos < data_buffer_len) {
        if (!in_file) {
            // Look for boundary
            char *boundary_pos = memmem(data_buffer + pos, data_buffer_len - pos, boundary_str, boundary_len);
            char *end_boundary_pos = memmem(data_buffer + pos, data_buffer_len - pos, end_boundary_str, end_boundary_len);

            if (boundary_pos) {
                pos = boundary_pos - data_buffer + boundary_len;

                // Check if this is the end boundary
                if (end_boundary_pos && end_boundary_pos - data_buffer == pos - boundary_len) {
                    // Reached the end of multipart data
                    break;
                }

                // Parse headers
                size_t headers_start = pos;
                char *headers_end_ptr = memmem(data_buffer + headers_start, data_buffer_len - headers_start, "\r\n\r\n", 4);
                if (!headers_end_ptr) {
                    // Not enough data
                    break;
                }
                size_t headers_end = headers_end_ptr - data_buffer;
                size_t headers_len = headers_end - headers_start;
                char headers[1024];
                if (headers_len >= sizeof(headers)) {
                    // Headers too large
                    send_response(client_socket, "400 Bad Request",
                                  "text/plain", "Headers too large");
                    if (file_fd != -1) close(file_fd);
                    free(data_buffer);
                    return;
                }
                memcpy(headers, data_buffer + headers_start, headers_len);
                headers[headers_len] = '\0';

                // Extract filename
                filename[0] = '\0';
                char *content_disposition = strstr(headers, "Content-Disposition:");
                if (content_disposition) {
                    extract_filename(content_disposition, filename);
                }

                pos = headers_end + 4; // Move past headers and CRLF

                // Open file if filename is found
                if (filename[0] != '\0') {
                    // Build the full file path
                    char file_path[1024];
                    snprintf(file_path, sizeof(file_path), "%s%s/%s", base_directory, current_path, filename);

                    // Ensure the directory exists
                    char dir_path[1024];
                    snprintf(dir_path, sizeof(dir_path), "%s%s", base_directory, current_path);
                    mkdir_recursive(dir_path);

                    // Open the file for writing
                    file_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (file_fd < 0) {
                        send_response(client_socket, "500 Internal Server Error",
                                      "text/plain", "Cannot save uploaded file");
                        free(data_buffer);
                        return;
                    }
                    in_file = 1;
                }
            } else {
                // Boundary not found, need more data (shouldn't happen)
                break;
            }
        } else {
            // Look for next boundary
            char *next_boundary = memmem(data_buffer + pos, data_buffer_len - pos, boundary_str, boundary_len);
            char *next_end_boundary = memmem(data_buffer + pos, data_buffer_len - pos, end_boundary_str, end_boundary_len);
            char *boundary_ptr = NULL;
            size_t boundary_length = 0;

            if (next_boundary && next_end_boundary) {
                if (next_boundary < next_end_boundary) {
                    boundary_ptr = next_boundary;
                    boundary_length = boundary_len;
                } else {
                    boundary_ptr = next_end_boundary;
                    boundary_length = end_boundary_len;
                }
            } else if (next_boundary) {
                boundary_ptr = next_boundary;
                boundary_length = boundary_len;
            } else if (next_end_boundary) {
                boundary_ptr = next_end_boundary;
                boundary_length = end_boundary_len;
            }

            if (boundary_ptr) {
                size_t data_len = boundary_ptr - (data_buffer + pos) - 2; // Exclude preceding \r\n
                if (data_len > 0 && data_buffer[pos + data_len] == '\r' && data_buffer[pos + data_len + 1] == '\n') {
                    // Write file data
                    write(file_fd, data_buffer + pos, data_len);
                }
                close(file_fd);
                file_fd = -1;
                in_file = 0;
                pos = boundary_ptr - data_buffer + boundary_length;
                if (boundary_length == end_boundary_len) {
                    // End boundary found
                    break;
                }
            } else {
                // Write remaining data
                write(file_fd, data_buffer + pos, data_buffer_len - pos);
                pos = data_buffer_len;
            }
        }
    }

    // Clean up
    if (file_fd != -1) {
        close(file_fd);
    }
    free(data_buffer);

    // Send a response back to the client
    send_response(client_socket, "200 OK", "text/plain",
                  "File(s) uploaded successfully");
}


// Main server loop
int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    // Set locale for number formatting
    setlocale(LC_NUMERIC, "");

    // Process command-line arguments
    if (argc > 1) {
        // Check for help option
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_help();
            return 0;
        }
        // Set base directory
        strncpy(base_directory, argv[1], sizeof(base_directory) - 1);
        base_directory[sizeof(base_directory) - 1] = '\0';
    }

    if (argc > 2) {
        // Set server port
        server_port = atoi(argv[2]);
        if (server_port <= 0 || server_port > 65535) {
            fprintf(stderr, "Invalid port number.\n");
            return 1;
        }
    }

    if (argc > 3) {
        // Set text file name and read its content
        strncpy(text_filename, argv[3], sizeof(text_filename) - 1);
        text_filename[sizeof(text_filename) - 1] = '\0';
        char full_text_path[512];
        snprintf(full_text_path, sizeof(full_text_path), "%s/%s", base_directory, text_filename);
        FILE *text_file = fopen(full_text_path, "r");
        if (text_file) {
            fseek(text_file, 0, SEEK_END);
            long file_size = ftell(text_file);
            fseek(text_file, 0, SEEK_SET);

            // Limit the size of the text file content to prevent buffer overflow
            if (file_size > 102400) {  // Limit to 100 KB
                file_size = 102400;
            }

            text_file_content = malloc(file_size + 1);
            if (text_file_content == NULL) {
                fprintf(stderr, "Memory allocation failed for text file content.\n");
                fclose(text_file);
                exit(EXIT_FAILURE);
            }
            fread(text_file_content, 1, file_size, text_file);
            text_file_content[file_size] = '\0';
            fclose(text_file);
        } else {
            fprintf(stderr, "Failed to open text file: %s\n", full_text_path);
            // Initialize to an empty string to prevent NULL dereference
            text_file_content = malloc(1);
            if (text_file_content == NULL) {
                fprintf(stderr, "Memory allocation failed for text file content.\n");
                exit(EXIT_FAILURE);
            }
            text_file_content[0] = '\0';
        }
    }

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Setting the SO_REUSEADDR option
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt,
                   sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Set up the server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the port
    if (bind(server_socket, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("HTTP server running on port %d, serving directory '%s'\n", server_port, base_directory);

    // Main server loop: accept and handle incoming requests
    while (1) {
        client_socket = accept(server_socket,
                               (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        handle_request(client_socket);
    }

    // Close the server socket
    close(server_socket);

    // Free allocated memory
    if (text_file_content) {
        free(text_file_content);
    }

    return 0;
}

// Function to print help message
void print_help() {
    printf("Usage: simple_http_server [folder_to_share] [port_number] [text_file_name]\n");
    printf("Options:\n");
    printf("  folder_to_share : The directory to share (default is current directory)\n");
    printf("  port_number     : The port number to listen on (default is 8080)\n");
    printf("  text_file_name  : Name of a text file whose content will be displayed on the page\n");
}
