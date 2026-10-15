#include <emscripten.h>
#include <string>

struct Module {
    std::string asm_name;
    int wasm;
};

static Module make_module() {
    Module m;
    m.asm_name = "main.asm";
    return m;
}

void notify_js(int code) {
    EM_ASM({ console.log('status', $0); }, code);
}

int run_asm_pass(Module &m) {
    auto asmText = m.asm_name + ".s";
    return static_cast<int>(asmText.size());
}
