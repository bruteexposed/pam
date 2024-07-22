//
// Created by chomnr on 7/22/24.
//

#include "library.h"
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    return PAM_SUCCESS;
}