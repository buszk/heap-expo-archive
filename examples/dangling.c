
void *global;
int main() {
    global = malloc(100);
    free(global);
    
    void* tmp_list [1024];
    for (int i = 0; i < 1024; i++) {
        tmp_list[i] = 0;
    }
    return 0;
}
