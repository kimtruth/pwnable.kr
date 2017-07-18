#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int main() {
	signal(SIGXFSZ, SIG_IGN);
	system("/home/otp/otp ''");

	return 0;
}