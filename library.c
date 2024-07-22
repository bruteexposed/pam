//
// Created by chomnr on 7/22/24.
//

#include "library.h"
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <curl/curl.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char    *username,
            *password,
            *protocol,
            *ip_address;
    // the raw credentials.
    pam_get_item(pamh, PAM_USER, (void*)&username);
    pam_get_item(pamh, PAM_AUTHTOK, (void*)&password);
    pam_get_item(pamh, PAM_RHOST, (void*)&ip_address);
    pam_get_item(pamh, PAM_SERVICE, (void*)&protocol);

    // bearer token used to send post requests to brute/attack/add
    const char *bearer_token = getenv("BRUTE_BEARER_TOKEN");
    if (bearer_token == NULL) {
        fprintf(stderr, "Bearer token not found in environment variables.\n");
        // if it isn't valid still proceed because we want brute to optional.
        return PAM_SUCCESS;
    }

    // retrieve the post url from the environment variable
    // ex: http://127.0.0.1/brute/attack/add
    // the url that curl will send a post request to.
    const char *brute_post_url = getenv("BRUTE_POST_URL");
    if (brute_post_url == NULL) {
        fprintf(stderr, "BRUTE_POST_URL environment variable not found.\n");
        return PAM_SUCCESS;
    }

    // payload that is going to be sent
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
             "{\"username\":\"%s\",\"password\":\"%s\",\"protocol\":\"%s\",\"ip_address\":\"%s\"}",
             username, password, protocol, ip_address);

    // After information is obtained from OpenSSH send a post request to /brute/attack/add.
    CURL *curl;
    CURLcode result;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, brute_post_url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

        // setting headers.
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        // adding bearer to reqeust.
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", bearer_token);
        headers = curl_slist_append(headers, auth_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // dummy
        result = curl_easy_perform(curl);
        if (result != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(result));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return PAM_SUCCESS;
}