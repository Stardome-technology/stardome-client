#include "serial_port_linux_c_api.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

namespace {

int g_serial_fd = -1;
bool g_tx_in_frame = false;
size_t g_tx_frame_wire_bytes = 0;
bool g_tx_capture_active = false;
bool g_tx_capture_escape = false;
uint8_t g_tx_capture_buf[32] = {0};
size_t g_tx_capture_len = 0;

constexpr uint8_t kFrameByte = 0x7E;
constexpr uint8_t kNackByte = 0x15;
constexpr uint8_t kResetByte = 0x55;
constexpr size_t kSmallFrameMaxWireBytes = 100;
constexpr useconds_t kSmallFrameFlushDelayUs = 30000;

speed_t to_speed(int baudrate) {
    switch (baudrate) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
#ifdef B460800
        case 460800: return B460800;
#endif
        default: return B115200;
    }
}

void serial_reset_tx_frame_state(void) {
    g_tx_in_frame = false;
    g_tx_frame_wire_bytes = 0;
    g_tx_capture_active = false;
    g_tx_capture_escape = false;
    g_tx_capture_len = 0;
}

void serial_trace_control_frame(void) {
    if (g_tx_capture_len == 0u) {
        return;
    }

    const uint8_t type = g_tx_capture_buf[0];
    if (type == kNackByte) {
        fprintf(stderr, "[HOST-WIRE] EVT=NACK_CTRL_TX\n");
    } else if (type == kResetByte) {
        fprintf(stderr, "[HOST-WIRE] EVT=RESET_CTRL_TX\n");
    }
}

void serial_capture_tx_byte(uint8_t byte) {
    if (!g_tx_capture_active) {
        return;
    }

    if (g_tx_capture_escape) {
        g_tx_capture_escape = false;
        if (g_tx_capture_len < sizeof(g_tx_capture_buf)) {
            g_tx_capture_buf[g_tx_capture_len++] = static_cast<uint8_t>(byte ^ 0x20u);
        }
        return;
    }

    if (byte == 0x7Du) {
        g_tx_capture_escape = true;
        return;
    }

    if (g_tx_capture_len < sizeof(g_tx_capture_buf)) {
        g_tx_capture_buf[g_tx_capture_len++] = byte;
    }
}

void serial_note_tx_byte(uint8_t byte) {
    if (byte == kFrameByte) {
        if (!g_tx_in_frame) {
            g_tx_in_frame = true;
            g_tx_frame_wire_bytes = 1;
            g_tx_capture_active = true;
            g_tx_capture_escape = false;
            g_tx_capture_len = 0;
            return;
        }

        ++g_tx_frame_wire_bytes;
        const size_t frame_wire_bytes = g_tx_frame_wire_bytes;
        serial_trace_control_frame();
        serial_reset_tx_frame_state();

        if (g_serial_fd >= 0 && frame_wire_bytes <= kSmallFrameMaxWireBytes) {
            tcdrain(g_serial_fd);
            usleep(kSmallFrameFlushDelayUs);
        }
        return;
    }

    if (g_tx_in_frame) {
        ++g_tx_frame_wire_bytes;
        serial_capture_tx_byte(byte);
    }
}

} // namespace

extern "C" bool serial_open_port(const char* path, int baudrate) {
    if (!path) {
        return false;
    }

    if (g_serial_fd >= 0) {
        serial_close_port();
    }

    serial_reset_tx_frame_state();

    g_serial_fd = open(path, O_RDWR | O_NOCTTY);
    if (g_serial_fd < 0) {
        return false;
    }

    termios tty{};
    if (tcgetattr(g_serial_fd, &tty) != 0) {
        serial_close_port();
        return false;
    }

    cfmakeraw(&tty);
    const speed_t speed = to_speed(baudrate);
    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(g_serial_fd, TCSANOW, &tty) != 0) {
        serial_close_port();
        return false;
    }

    int modem_bits = 0;
    if (ioctl(g_serial_fd, TIOCMGET, &modem_bits) == 0) {
        modem_bits &= ~(TIOCM_DTR | TIOCM_RTS);
        (void)ioctl(g_serial_fd, TIOCMSET, &modem_bits);
    }

    tcflush(g_serial_fd, TCIOFLUSH);
    return true;
}

extern "C" void serial_close_port(void) {
    if (g_serial_fd >= 0) {
        close(g_serial_fd);
        g_serial_fd = -1;
    }
    serial_reset_tx_frame_state();
}

extern "C" bool serial_send_byte(uint8_t byte) {
    if (g_serial_fd < 0) {
        return false;
    }

    for (;;) {
        const ssize_t written = write(g_serial_fd, &byte, 1);
        if (written == 1) {
            serial_note_tx_byte(byte);
            return true;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(g_serial_fd, &writefds);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 20000;
            const int rv = select(g_serial_fd + 1, nullptr, &writefds, nullptr, &tv);
            if (rv > 0) {
                continue;
            }
        }
        return false;
    }
}

extern "C" uint8_t serial_receive_byte(void) {
    uint8_t b = 0;
    if (g_serial_fd < 0) {
        return 0;
    }

    for (;;) {
        const ssize_t read_len = read(g_serial_fd, &b, 1);
        if (read_len == 1) {
            return b;
        }
        if (read_len < 0 && errno == EINTR) {
            continue;
        }
        if (read_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return 0;
    }
}

extern "C" bool serial_rx_available(void) {
    if (g_serial_fd < 0) {
        return false;
    }
    int bytes = 0;
    if (ioctl(g_serial_fd, FIONREAD, &bytes) != 0) {
        return false;
    }
    return bytes > 0;
}

extern "C" void serial_flush_tx(void) {
    if (g_serial_fd >= 0) {
        tcdrain(g_serial_fd);
    }
}

extern "C" uint32_t serial_millis_now(void) {
    static const auto start = std::chrono::steady_clock::now();
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    return static_cast<uint32_t>(elapsed_ms);
}
