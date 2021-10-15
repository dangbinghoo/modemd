import modemd.xymodem;

import core.thread : Thread, msecs;

import core.sys.posix.termios;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;

import core.stdc.stdio;

private termios _normalset;

import std.experimental.logger;

extern (C) {
	void cfmakeraw(termios *termios_p);
}

void get_normal_termflags() {
	tcgetattr(STDIN_FILENO, &_normalset);
}

void set_noblock_termflag() {
	termios _set = _normalset;

	/* not enter endded */
	_set.c_lflag &= ~ICANON;
	_set.c_lflag &= ~ECHO ;
	_set.c_lflag &= ~ISIG ;
	//cfmakeraw(&_set);

	tcsetattr(STDIN_FILENO, TCSANOW, &_set);
}

bool has_input() {
	import core.sys.posix.sys.select : select, fd_set, FD_SET, FD_ZERO, FD_ISSET;
	import core.sys.posix.sys.time : timeval;
	fd_set fds;
	timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);
	select(STDIN_FILENO + 1, &fds, null, null, &tv);
	return FD_ISSET(STDIN_FILENO, &fds);
}

void set_normal_termflag() {
	tcsetattr(STDIN_FILENO, TCSANOW, &_normalset);
}

int modem_get_data(ubyte* buff, size_t len, long timeout)
{
	logger.log("timeout is: ", timeout, " expected len ", len);
	long tries = timeout * 1000;
	int i;
	while (tries--) {
		if (has_input()) {
			const int c = getchar();
			if (c > 0) {
				buff[i] = 0xff & c;
				i++;
			}
		}
		if (i == len) break;
		Thread.sleep(1.msecs);
	}

	logger.log("real read len is : ", i, " data is ", buff[0..i].dup);
	return tries < 1 ? -1 : i;
}

void modem_putchar(ubyte c)
{
	logger.log("putchar ", c);
	putchar(c);
	fflush(stdout);
}

void modem_flush()
{
	logger.log("flush");
	fflush(stdout);
}

__gshared FileLogger logger;

void main()
{
	logger = new FileLogger("/tmp/a1.log");

	get_normal_termflags();

	set_noblock_termflag();
	XYModem modem;
	modem.register(&modem_get_data, &modem_putchar, &modem_flush);
	modem.doXmodemLoad();

	scope(exit) {
		set_normal_termflag();
		logger.log("Program Exit!!!!!");
	}
}
