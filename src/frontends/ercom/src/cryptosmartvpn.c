//
// Created by admlocal on 13/01/25.
//

#include "cryptosmartvpn.h"

#include "config.h" // Needed by strongswan, the file is generated in build/config.h
#include "library.h"
#include "threading/thread.h"
#include "daemon.h"

#include "credentials/auth_cfg.h"
#include "credentials/sets/mem_cred.h"
#include "utils/chunk.h"

#include "utils/debug.h"

#include "processing/jobs/callback_job.h"

extern daemon_t *charon;
extern library_t *lib;

struct cryptosmart_vpn_t {
    auth_cfg_t *auth;
    mem_cred_t *creds;
    ike_sa_t *ike_sa;
    listener_t listener;
};

#define BASE_PATH "/home/admlocal/projects/strongswan/strongswan.linux/"
#define ADD_PLUGIN_PATH(plugin_name) \
    printf("   " plugin_name "\n"); \
    lib->plugins->add_path(lib->plugins, BASE_PATH "src/libstrongswan/plugins/" plugin_name "/.libs/");

#define ADD_CHARON_PLUGIN_PATH(plugin_name) \
    printf("   " plugin_name "\n"); \
    lib->plugins->add_path(lib->plugins, BASE_PATH "src/libcharon/plugins/" plugin_name "/.libs/");

/*
const char *charon_plugins[] = {
        "tnc-tnccs", "tnc-imc", "tnccs-20", NULL // NULL est important pour marquer la fin du tableau
};

const char *ikev2_plugins[] = {
        "x509", "pem", "pkcs1", "pubkey", "openssl", "wolfssl", "nonce", NULL
};*/

//const char* expected_plugins = "x509 pem pkcs1 pubkey openssl wolfssl nonce tnc-tnccs tnc-imc tnccs-20";
// pf_route is marked as required by libipsec, understand why
char* expected_plugins = "kernel-libipsec kernel-netlink socket-default x509 pem pkcs1 pubkey openssl nonce"; // wolfssl tnc-tnccs tnc-imc tnccs-20";
//char* expected_plugins = "socket-default nonce openssl";

void configure_logs() {
    dbg_default_set_level(LEVEL_PRIVATE);
    dbg_default_set_stream(stdout);
}

static job_requeue_t initiate(cryptosmart_vpn_t* csmart_vpn) {
    printf("Create authentication configuration\n");

    ike_cfg_create_t ike = {
            .version = IKEV2,
            .local = "",
            .local_port = charon->socket->get_port(charon->socket, FALSE),
            .force_encap = FALSE,
            .fragmentation = FRAGMENTATION_NO,
            .remote = "217.111.150.165",//"172.26.25.182",
            .remote_port = 500,
            .no_certreq = TRUE,
            .ocsp_certreq = FALSE
    };
    peer_cfg_create_t peer = {
            .cert_policy = CERT_ALWAYS_SEND,
            .unique = UNIQUE_REPLACE,
            .rekey_time = 36000, /* 10h */
            .jitter_time = 600, /* 10min */
            .over_time = 1800, /* 30min */
    };
    child_cfg_create_t child = {
            .lifetime = {
                    .time = {
                            .life = 9000, /* 2.5h */
                            .rekey = 7200, /* 2h */
                            .jitter = 300 /* 5min */
                    },
            },
            .mode = MODE_TUNNEL,
            .dpd_action = ACTION_START,
            .close_action = ACTION_START,
    };
    ike_cfg_t *ike_cfg = ike_cfg_create(&ike);

    ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
    ike_cfg->add_proposal(ike_cfg, proposal_create_default_aead(PROTO_IKE));

    // Try another name than android
    peer_cfg_t *peer_cfg = peer_cfg_create("ercom", ike_cfg, &peer);
    peer_cfg->add_virtual_ip(peer_cfg, host_create_any(AF_INET));
    peer_cfg->add_virtual_ip(peer_cfg, host_create_any(AF_INET6));

    // Set PSK
    csmart_vpn->auth = auth_cfg_create();
    csmart_vpn->creds = mem_cred_create();

    csmart_vpn->auth->add(csmart_vpn->auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);

    char* secret = "<here>";
    chunk_t secret_chunk = chunk_create(secret, strlen(secret));
    shared_key_t* shared_key = shared_key_create(SHARED_IKE, chunk_clone(secret_chunk));
    identification_t *local_id = identification_create_from_string("");


    csmart_vpn->creds->add_shared(csmart_vpn->creds, shared_key, local_id, NULL);
    peer_cfg->add_auth_cfg(peer_cfg, csmart_vpn->auth, TRUE);

    auth_cfg_t *auth = auth_cfg_create();
    identification_t *gateway = identification_create_from_string("ercom");
    auth->add(auth, AUTH_RULE_IDENTITY, gateway);
    peer_cfg->add_auth_cfg(peer_cfg, auth, FALSE);

    child_cfg_t *child_cfg = child_cfg_create("android", &child);
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   "aes256gcm16-aes128gcm16-chacha20poly1305-"
                                                                   "curve25519-ecp384-ecp521-modp3072-modp4096-ecp256-modp8192"));
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   "aes256-aes192-aes128-sha384-sha256-sha512-sha1-"
                                                                   "curve25519-ecp384-ecp521-modp3072-modp4096-ecp256-modp2048-"
                                                                   "modp8192"));
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   "aes256gcm16-aes128gcm16-chacha20poly1305"));
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   "aes256-aes192-aes128-sha384-sha256-sha512-sha1"));

    traffic_selector_t *ts;
    ts = traffic_selector_create_from_cidr("0.0.0.0/0", 0, 0, 65535);
    child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
    ts = traffic_selector_create_from_cidr("0.0.0.0/0", 0, 0, 65535);
    child_cfg->add_traffic_selector(child_cfg, FALSE, ts);
    ts = traffic_selector_create_from_cidr("::/0", 0, 0, 65535);
    child_cfg->add_traffic_selector(child_cfg, TRUE, ts);
    ts = traffic_selector_create_from_cidr("::/0", 0, 0, 65535);
    child_cfg->add_traffic_selector(child_cfg, FALSE, ts);

    peer_cfg->add_child_cfg(peer_cfg, child_cfg);

    ike_sa_t *ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
                                                                  peer_cfg);
    peer_cfg->destroy(peer_cfg);

    if (!ike_sa) {
        printf("TOTO: Failed to create IKE SA with config\n");
        free(csmart_vpn);
        return JOB_REQUEUE_NONE;
    }

    // Keep IKE SA to be able to follow it status
    csmart_vpn->ike_sa = ike_sa;

    /* get an additional reference because initiate consumes one */
    // Note: I don't understand, just recopy the statement AND the comment from Android implementation !
    child_cfg->get_ref(child_cfg);

    printf("TOTO:    SUCCESS\n");
    printf("TOTO: Initiate IKE SA\n");
    status_t status = ike_sa->initiate(ike_sa, child_cfg, NULL);
    if (status != SUCCESS)
    {
        printf("TOTO: Failed to initiate IKE SA (status=%d)\n", status);
        charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
                                                    ike_sa);
        free(csmart_vpn);
        return JOB_REQUEUE_NONE;
    }
    charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
    printf("TOTO:    SUCCESS\n");


    return JOB_REQUEUE_NONE;
}

METHOD(listener_t, ike_updown, bool,
       cryptosmart_vpn_t *this, ike_sa_t *ike_sa, bool up) {
    // Check which sa receive the event by comparing ike_sa with csmart->ike_sa
    printf("LISTENER: ike_updown (up=%s)\n", up ? "true" : "false");
    return TRUE;
}

METHOD(listener_t, child_updown, bool,
       cryptosmart_vpn_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
       bool up) {
    // Check which sa receive the event by comparing ike_sa with csmart->ike_sa
    printf("LISTENER: child_updown (up=%s)\n", up ? "true" : "false");
    return TRUE;
}

METHOD(listener_t, alert, bool,
       cryptosmart_vpn_t *this, ike_sa_t *ike_sa, alert_t alert,
       va_list args) {
    switch (alert)
    {
        case ALERT_PEER_ADDR_FAILED:
            printf("LISTENER: Alert peer address failed\n");
            break;
        case ALERT_PEER_AUTH_FAILED:
            printf("LISTENER: Alert peer authentication failed\n");
            break;
        case ALERT_KEEP_ON_CHILD_SA_FAILURE:
            printf("LISTENER: Alert keep on child SA failure\n");
            break;
        case ALERT_PEER_INIT_UNREACHABLE:
            printf("LISTENER: Alert peer unreachable\n");
            break;
        default:
            break;
    }
    return TRUE;
}

cryptosmart_vpn_t* create_csmart_vpn() {
    // Use the INIT syntax of strongswan
    cryptosmart_vpn_t* csmart_vpn = malloc(sizeof(cryptosmart_vpn_t));

    csmart_vpn->listener.ike_updown = _ike_updown;
    csmart_vpn->listener.child_updown = _child_updown;
    csmart_vpn->listener.alert = _alert;

    if (charon != NULL) {
        printf("A charon service has already been created\n");
        free(csmart_vpn);
        return NULL;
    }
    if (lib != NULL) {
        printf("A service has already been created\n");
        free(csmart_vpn);
        return NULL;
    }

    printf("Init charon library\n");
    if (!library_init("strongswan.conf", "charon"))
    {
        printf("   FAILED\n");
        library_deinit();
        free(csmart_vpn);
        return NULL;
    }
    printf("   SUCCESS\n");

    printf("Init libcharon\n");
    if (!libcharon_init()) {
        printf("   FAILED\n");
        libcharon_deinit();
        library_deinit();
        free(csmart_vpn);
        return NULL;
    }
    printf("   SUCCESS\n");

    lib->settings->set_int(lib->settings, "charon.retransmit_tries", 3);

    printf("Add search path for plugins\n");
    // Plugins not loaded here, just path added to search path.
    ADD_PLUGIN_PATH("sshkey");
    ADD_PLUGIN_PATH("revocation");
    ADD_PLUGIN_PATH("pkcs1");
    ADD_PLUGIN_PATH("drbg");
    ADD_PLUGIN_PATH("pkcs7");
    ADD_PLUGIN_PATH("xcbc");
    ADD_PLUGIN_PATH("random");
    ADD_PLUGIN_PATH("dnskey");
    ADD_PLUGIN_PATH("x509"); // Déjà présent dans votre exemple, mais inclus pour être complet
    ADD_PLUGIN_PATH("openssl");
    ADD_PLUGIN_PATH("constraints");
    ADD_PLUGIN_PATH("pem");
    ADD_PLUGIN_PATH("pubkey");
    ADD_PLUGIN_PATH("cmac");
    ADD_PLUGIN_PATH("pgp");
    ADD_PLUGIN_PATH("kdf");
    ADD_PLUGIN_PATH("pkcs8");
    ADD_PLUGIN_PATH("nonce");
    //ADD_CHARON_PLUGIN_PATH("kernel_netlink");
    ADD_CHARON_PLUGIN_PATH("kernel_libipsec");
    ADD_CHARON_PLUGIN_PATH("kernel_netlink");
    ADD_CHARON_PLUGIN_PATH("counters");
    ADD_CHARON_PLUGIN_PATH("updown");
    ADD_CHARON_PLUGIN_PATH("xauth_generic");
    ADD_CHARON_PLUGIN_PATH("vici");
    ADD_CHARON_PLUGIN_PATH("socket_default");
    ADD_CHARON_PLUGIN_PATH("resolve");
    ADD_CHARON_PLUGIN_PATH("attr");

    // charon pointer is now not null
    printf("Initialize charon daemon\n");
    if (!charon->initialize(charon, expected_plugins))
    {
        printf("   FAILED\n");
        libcharon_deinit();
        library_deinit();
        free(csmart_vpn);
        return NULL;
    }
    printf("   SUCCESS\n");

    printf("TOTO: Register listener\n");
    charon->bus->add_listener(charon->bus, &(csmart_vpn->listener));
    printf("TOTO:    SUCCESS\n");

    printf("Start charon daemon\n");





    //lib->creds->create(lib->creds, csmart_vpn->creds);

    charon->start(charon);
    //charon->bus->add_listener

    lib->processor->queue_job(lib->processor,
                              (job_t*)callback_job_create((callback_job_cb_t)initiate, csmart_vpn,
                                                          NULL, NULL));

    return csmart_vpn;
}
