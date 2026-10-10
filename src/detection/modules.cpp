#include <unhide/modules.h>
#include <unhide/processes.h>
#include <unhide/signature.h>
#include <windows.h>

namespace unhide {
namespace modulos {

static std::string menorTexto(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

static bool nomeSistema(const std::string &nome) {
    std::string m = menorTexto(nome);
    if (m == "ntdll.dll") {
        return true;
    }
    if (m == "kernel32.dll") {
        return true;
    }
    if (m == "kernelbase.dll") {
        return true;
    }
    if (m == "user32.dll") {
        return true;
    }
    if (m == "gdi32.dll") {
        return true;
    }
    if (m == "advapi32.dll") {
        return true;
    }
    if (m == "msvcrt.dll") {
        return true;
    }
    if (m == "shell32.dll") {
        return true;
    }
    if (m == "explorer.exe") {
        return true;
    }
    return false;
}

static bool caminhoTemporario(const std::string &caminho) {
    std::string m = menorTexto(caminho);
    if (m.find("\\temp\\") != std::string::npos) {
        return true;
    }
    if (m.find("\\tmp\\") != std::string::npos) {
        return true;
    }
    if (m.find("\\appdata\\") != std::string::npos) {
        return true;
    }
    if (m.find("\\programdata\\") != std::string::npos) {
        return true;
    }
    if (m.find("\\users\\public\\") != std::string::npos) {
        return true;
    }
    return false;
}

static bool pastaSistemaOuProgramas(const std::string &caminho) {
    std::string m = menorTexto(caminho);
    char winDir[MAX_PATH];
    UINT t = GetWindowsDirectoryA(winDir, MAX_PATH);
    if (t > 0) {
        std::string windows = menorTexto(std::string(winDir));
        if (m.rfind(windows, 0) == 0) {
            return true;
        }
    }
    if (m.find("\\program files\\") != std::string::npos) {
        return true;
    }
    if (m.find("\\program files (x86)\\") != std::string::npos) {
        return true;
    }
    return false;
}

std::vector<modelos::ModuloSuspeito> analisarExplorer() {
    std::vector<modelos::ModuloSuspeito> saida;
    std::vector<unsigned long> pids = processos::pidsPorNome("explorer.exe");
    for (size_t k = 0; k < pids.size(); k = k + 1) {
        unsigned long pid = pids[k];
        std::vector<processos::InfoModulo> mods = processos::listarModulos(pid);
        for (size_t i = 0; i < mods.size(); i = i + 1) {
            const processos::InfoModulo &m = mods[i];
            if (m.caminho.empty()) {
                continue;
            }
            if (nomeSistema(m.nome)) {
                continue;
            }
            bool confiavel = assinatura::caminhoSistemaConfiavel(m.caminho);
            std::string estado = assinatura::verificar(m.caminho);
            bool valida = (estado == "valid");
            if (valida) {
                continue;
            }
            if (confiavel) {
                continue;
            }
            modelos::ModuloSuspeito item;
            item.nome = m.nome;
            item.caminho = m.caminho;
            item.pid = pid;
            item.processo = "explorer.exe";
            item.assinatura = estado;
            item.assinado = valida;
            if (caminhoTemporario(m.caminho)) {
                item.risco = "high-unsigned-module-in-temp-folder";
            } else if (pastaSistemaOuProgramas(m.caminho)) {
                item.risco = "low-unsigned-module-in-system-folder";
            } else {
                item.risco = "medium-unsigned-module";
            }
            bool duplicado = false;
            for (size_t j = 0; j < saida.size(); j = j + 1) {
                if (saida[j].caminho == item.caminho && saida[j].pid == item.pid) {
                    duplicado = true;
                    break;
                }
            }
            if (!duplicado) {
                saida.push_back(item);
            }
        }
    }
    return saida;
}

}
}
