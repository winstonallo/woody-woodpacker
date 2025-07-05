#include <assert.h>
#include <unistd.h>

int
ft_strlen(char *str) {
    assert(str != NULL);

    int i = 0;
    while (str[i] != '\0')
        i++;
    return i;
}

int
put_str(int fd, char *str) {
    int bytes_written = write(fd, str, ft_strlen(str));
    if (bytes_written != ft_strlen(str)) return 1;
    return 0;
}
