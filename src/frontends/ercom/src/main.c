#include "cryptosmartvpn.h"

#include <stdio.h>
#include <signal.h>
#include <errno.h>

int main() {
    configure_logs();

    cryptosmart_vpn_t* csmart_vpn = create_csmart_vpn();
    if (csmart_vpn == NULL) {
        return 1;
    }

    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, NULL);


    while ((sig = sigwaitinfo(&set, NULL)) != -1 || errno == EINTR)
    {
        switch (sig)
        {
            case SIGINT:
            case SIGTERM:
                printf("shutting down...\n");
                // TODO: call :
                //charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL, sig);
                break;
            default:
                continue;
        }
        break;
    }

    return 0;
}
