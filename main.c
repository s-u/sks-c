#include "server.h"
#include "http.h"

int main(int ac, char **av) {
    if (!create_HTTP_server(4301, SRV_LOCAL))
	return 1;
    serverLoop();
    return 0;
}
