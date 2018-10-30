#include <stdio.h>
#include "../../ssa-daemon/twilio.h"

int main(int argC, char** argV) {
    char response[100];
    char *phone = NULL;
    int success = twilio_send_message(phone, "Test Message", response);
    printf("%s:response: %s\n", success==0?"Success":"Failure", response);
    return 0;
}

