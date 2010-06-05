#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "../include/types.h"

void warn_quit(char *msg){
    printf("%s\n",msg); exit(EXIT_FAILURE); 
}

