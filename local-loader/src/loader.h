#define GETRESOURCE(x) ( char * ) &x

typedef struct {
    char data [ 4096 ];
    char code [ 24576 ];
} PICO;

typedef struct {
    int  len;
    char value[];
} RESOURCE;
