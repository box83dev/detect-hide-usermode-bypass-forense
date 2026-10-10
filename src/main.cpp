#include <unhide/models.h>
#include <unhide/config.h>
#include <unhide/files.h>
#include <unhide/compare.h>
#include <unhide/modules.h>
#include <unhide/hooks.h>
#include <unhide/persistence.h>
#include <unhide/console.h>
#include <unhide/report.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

static void ajuda() {
    std::cout << "Unhide Usermode 1.0.0 - forensic scan for hidden files and Explorer hooks" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  unhide.exe [--path C:\\folder] [--full] [--output folder]" << std::endl;
    std::cout << "Everything is shown in this console. Files are only saved with --output." << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  unhide.exe" << std::endl;
    std::cout << "  unhide.exe --full" << std::endl;
    std::cout << "  unhide.exe --path C:\\Users --output results" << std::endl;
}

static bool lancadoPorExplorer() {
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    ppid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (ppid == 0) {
        return false;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (h == nullptr) {
        return false;
    }
    char nome[MAX_PATH];
    DWORD tam = sizeof(nome);
    bool eh = false;
    if (QueryFullProcessImageNameA(h, 0, nome, &tam)) {
        std::string s(nome);
        for (size_t i = 0; i < s.size(); i = i + 1) {
            if (s[i] >= 'A' && s[i] <= 'Z') {
                s[i] = (char)(s[i] + 32);
            }
        }
        size_t n = s.size();
        std::string alvo = "\\explorer.exe";
        if (n >= alvo.size() && s.compare(n - alvo.size(), alvo.size(), alvo) == 0) {
            eh = true;
        }
    }
    CloseHandle(h);
    return eh;
}

static unhide::modelos::NivelVeredito calcularVeredito(unhide::modelos::ResultadoAnalise &r) {
    r.evidencias.clear();
    bool divergenciaReal = false;
    for (size_t i = 0; i < r.divergencias.size(); i = i + 1) {
        if (!r.divergencias[i].visivelSoNoNativo.empty()) {
            divergenciaReal = true;
            std::string ev = "Win32 vs Native divergence in ";
            ev = ev + r.divergencias[i].diretorio;
            ev = ev + ": ";
            ev = ev + std::to_string(r.divergencias[i].visivelSoNoNativo.size());
            ev = ev + " item(s) visible only in the native view";
            r.evidencias.push_back(ev);
        }
    }
    bool ganchoExterno = false;
    for (size_t i = 0; i < r.ganchos.size(); i = i + 1) {
        if (r.ganchos[i].destinoExterno) {
            ganchoExterno = true;
            std::string ev = "Hook with an external destination: ";
            ev = ev + r.ganchos[i].modulo;
            ev = ev + "!";
            ev = ev + r.ganchos[i].funcao;
            ev = ev + " pid ";
            ev = ev + std::to_string(r.ganchos[i].pid);
            r.evidencias.push_back(ev);
        }
    }
    bool moduloAltoRisco = false;
    for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
        if (r.modulos[i].risco.find("high-") == 0) {
            moduloAltoRisco = true;
            std::string ev = "Unsigned module in a temp folder: ";
            ev = ev + r.modulos[i].caminho;
            r.evidencias.push_back(ev);
            break;
        }
    }
    size_t ameacasArquivo = 0;
    size_t ocultosDesconhecidos = 0;
    std::string primeiroDesconhecido;
    for (size_t i = 0; i < r.arquivosOcultos.size(); i = i + 1) {
        std::string c = r.arquivosOcultos[i].categoria;
        if (c.find("-legit") != std::string::npos) {
            continue;
        }
        if (c == "double-extension" || c == "hidden-stream" || c == "suspicious-name") {
            ameacasArquivo = ameacasArquivo + 1;
        }
        if (c == "os-protected-hidden" || c == "hidden") {
            ocultosDesconhecidos = ocultosDesconhecidos + 1;
            if (primeiroDesconhecido.empty()) {
                primeiroDesconhecido = r.arquivosOcultos[i].caminho;
            }
        }
    }
    if (divergenciaReal && (ganchoExterno || moduloAltoRisco)) {
        r.resumo = "Hiding activity confirmed by double evidence: view divergence plus a risky hook or module in Explorer.";
        return unhide::modelos::NivelVeredito::Confirmado;
    }
    if (ganchoExterno && moduloAltoRisco) {
        r.resumo = "API hook with an external destination combined with an unsigned module in Explorer. Active hiding very likely.";
        return unhide::modelos::NivelVeredito::Confirmado;
    }
    if (ganchoExterno) {
        r.resumo = "API hook with an external destination found in Explorer. Immediate investigation required.";
        return unhide::modelos::NivelVeredito::Confirmado;
    }
    if (divergenciaReal) {
        r.resumo = "Win32 vs native view divergence with no classic hook confirmed. Possible filter or one-off hook.";
        return unhide::modelos::NivelVeredito::Suspeito;
    }
    if (moduloAltoRisco) {
        r.resumo = "Unsigned module in a temp folder inside Explorer, no confirmed hook. Treat as suspicious.";
        return unhide::modelos::NivelVeredito::Suspeito;
    }
    bool moduloRelevante = false;
    for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
        if (r.modulos[i].risco.rfind("high-", 0) == 0 || r.modulos[i].risco.rfind("medium-", 0) == 0) {
            moduloRelevante = true;
            break;
        }
    }
    if (!r.modulos.empty() && moduloRelevante) {
        std::string ev = "Unsigned module outside a system folder: ";
        for (size_t i = 0; i < r.modulos.size(); i = i + 1) {
            if (r.modulos[i].risco.rfind("high-", 0) == 0 || r.modulos[i].risco.rfind("medium-", 0) == 0) {
                ev = ev + r.modulos[i].caminho;
                break;
            }
        }
        r.evidencias.push_back(ev);
    }
    if (moduloRelevante || !r.persistencias.empty()) {
        r.resumo = "No proof of active hiding. Non-Microsoft items found for manual review.";
        return unhide::modelos::NivelVeredito::Suspeito;
    }
    if (ocultosDesconhecidos > 0) {
        r.resumo = "Hidden files outside the standard Windows pattern. No active hook, manual review required.";
        std::string ev = "Unknown hidden file: ";
        ev = ev + primeiroDesconhecido;
        r.evidencias.push_back(ev);
        return unhide::modelos::NivelVeredito::Suspeito;
    }
    if (ameacasArquivo > 0) {
        r.resumo = "No hook in Explorer. Camouflaged files found for manual review.";
        return unhide::modelos::NivelVeredito::Suspeito;
    }
    if (!r.arquivosOcultos.empty()) {
        r.resumo = "Only hidden files compatible with normal Windows behavior. No hook detected.";
        return unhide::modelos::NivelVeredito::Informativo;
    }
    r.resumo = "No relevant hidden file and no hook in Explorer. System clean in this scan.";
    return unhide::modelos::NivelVeredito::Limpo;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> caminhosArg;
    bool completo = false;
    std::string pastaSaida;
    for (int i = 1; i < argc; i = i + 1) {
        std::string a(argv[i]);
        if (a == "--ajuda" || a == "--help" || a == "-h" || a == "/?") {
            ajuda();
            return 0;
        } else if (a == "--completo" || a == "--full") {
            completo = true;
        } else if ((a == "--caminho" || a == "--path") && i + 1 < argc) {
            caminhosArg.push_back(std::string(argv[i + 1]));
            i = i + 1;
        } else if ((a == "--saida" || a == "--output") && i + 1 < argc) {
            pastaSaida = std::string(argv[i + 1]);
            i = i + 1;
        }
    }
    unhide::modelos::ResultadoAnalise r;
    r.inicio = unhide::relatorio::agoraTexto();
    r.modoCompleto = completo;
    r.configuracaoExplorer = unhide::configuracao::obter();
    std::vector<std::string> bases = caminhosArg;
    if (bases.empty()) {
        bases = unhide::arquivos::caminhosPadrao(completo);
    }
    r.caminhosVarridos = bases;
    auto prog = [](const std::string &p) {
        unhide::console_saida::progresso(p);
    };
    r.arquivosOcultos = unhide::arquivos::varrer(bases, completo, prog);
    std::cout << std::endl;
    std::vector<std::string> dirsComparar;
    for (size_t i = 0; i < bases.size() && dirsComparar.size() < 12; i = i + 1) {
        dirsComparar.push_back(bases[i]);
    }
    if (!r.arquivosOcultos.empty()) {
        for (size_t i = 0; i < r.arquivosOcultos.size() && dirsComparar.size() < 20; i = i + 1) {
            std::string c = r.arquivosOcultos[i].caminho;
            size_t p = c.find_last_of('\\');
            if (p != std::string::npos) {
                std::string d = c.substr(0, p);
                bool existe = false;
                for (size_t j = 0; j < dirsComparar.size(); j = j + 1) {
                    if (dirsComparar[j] == d) {
                        existe = true;
                        break;
                    }
                }
                if (!existe) {
                    dirsComparar.push_back(d);
                }
            }
        }
    }
    r.divergencias = unhide::comparacao::compararVarios(dirsComparar, 20);
    r.modulos = unhide::modulos::analisarExplorer();
    r.ganchos = unhide::ganchos::verificarExplorer();
    r.persistencias = unhide::persistencias::verificar();
    r.veredito = calcularVeredito(r);
    r.fim = unhide::relatorio::agoraTexto();
    unhide::console_saida::exibirAchados(r);
    unhide::console_saida::exibirVeredito(r);
    if (!pastaSaida.empty()) {
        std::string salvo = unhide::relatorio::salvar(r, pastaSaida);
        std::cout << "Report saved to: " << salvo << std::endl;
    }
    if (lancadoPorExplorer()) {
        std::cout << "Press ENTER to close..." << std::endl;
        std::string espera;
        std::getline(std::cin, espera);
    }
    return 0;
}
