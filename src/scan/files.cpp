#include <unhide/files.h>
#include <unhide/signature.h>
#include <windows.h>
#include <shlobj.h>
#include <cstring>
#include <algorithm>
#include <set>

namespace unhide {
namespace arquivos {

static std::string estreito(const std::wstring &w) {
    if (w.empty()) {
        return std::string();
    }
    int tam = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (tam <= 0) {
        return std::string();
    }
    std::string s((size_t)tam - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), tam, nullptr, nullptr);
    return s;
}

static std::wstring largo(const std::string &s) {
    if (s.empty()) {
        return std::wstring();
    }
    int tam = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (tam <= 0) {
        return std::wstring();
    }
    std::wstring w((size_t)tam - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), tam);
    return w;
}

static std::string menorTexto(std::string s) {
    for (size_t i = 0; i < s.size(); i = i + 1) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        }
    }
    return s;
}

static std::string nomeBase(const std::string &caminho) {
    size_t p = caminho.find_last_of('\\');
    if (p == std::string::npos) {
        size_t q = caminho.find_last_of(':');
        if (q == std::string::npos) {
            return caminho;
        }
        return caminho.substr(q + 1);
    }
    return caminho.substr(p + 1);
}

static std::string descreverAtributos(DWORD a) {
    std::string s;
    auto soma = [&](const std::string &t) {
        if (!s.empty()) {
            s = s + "+";
        }
        s = s + t;
    };
    if (a & FILE_ATTRIBUTE_READONLY) {
        soma("ReadOnly");
    }
    if (a & FILE_ATTRIBUTE_HIDDEN) {
        soma("Hidden");
    }
    if (a & FILE_ATTRIBUTE_SYSTEM) {
        soma("System");
    }
    if (a & FILE_ATTRIBUTE_DIRECTORY) {
        soma("Directory");
    }
    if (a & FILE_ATTRIBUTE_REPARSE_POINT) {
        soma("Reparse");
    }
    if (a & FILE_ATTRIBUTE_TEMPORARY) {
        soma("Temporary");
    }
    if (s.empty()) {
        s = "Normal";
    }
    return s;
}

static bool nomeSuspeito(const std::string &nome) {
    std::string largoNome = nome;
    std::wstring w = largo(largoNome);
    for (size_t i = 0; i < w.size(); i = i + 1) {
        wchar_t c = w[i];
        if (c == 0x200B || c == 0x200C || c == 0x200D || c == 0x202E) {
            return true;
        }
    }
    if (!nome.empty()) {
        char ultimo = nome[nome.size() - 1];
        if (ultimo == ' ' || ultimo == '.') {
            return true;
        }
    }
    std::string m = menorTexto(nome);
    if (m.find(" ") != std::string::npos && m.find(".exe") != std::string::npos) {
        return true;
    }
    return false;
}

static bool extensaoDupla(const std::string &nome) {
    std::string m = menorTexto(nome);
    size_t primeiro = m.find('.');
    if (primeiro == std::string::npos) {
        return false;
    }
    size_t ultimo = m.find_last_of('.');
    if (ultimo == primeiro) {
        return false;
    }
    std::string ultima = m.substr(ultimo);
    bool perigosa = false;
    if (ultima == ".exe" || ultima == ".scr" || ultima == ".bat" || ultima == ".cmd" || ultima == ".ps1" || ultima == ".vbs" || ultima == ".js" || ultima == ".lnk" || ultima == ".com" || ultima == ".msi") {
        perigosa = true;
    }
    if (!perigosa) {
        return false;
    }
    std::string meio = m.substr(0, ultimo);
    if (meio.find(".pdf") != std::string::npos) {
        return true;
    }
    if (meio.find(".doc") != std::string::npos) {
        return true;
    }
    if (meio.find(".jpg") != std::string::npos) {
        return true;
    }
    if (meio.find(".png") != std::string::npos) {
        return true;
    }
    if (meio.find(".txt") != std::string::npos) {
        return true;
    }
    if (meio.find(".xls") != std::string::npos) {
        return true;
    }
    return false;
}

static bool deveIgnorar(const std::string &nome) {
    std::string m = menorTexto(nome);
    if (m == "winsxs") {
        return true;
    }
    if (m == "servicing") {
        return true;
    }
    if (m == "$recycle.bin") {
        return true;
    }
    if (m == "system volume information") {
        return true;
    }
    return false;
}

static bool terminaCom(const std::string &texto, const std::string &sufixo) {
    if (sufixo.size() > texto.size()) {
        return false;
    }
    return texto.compare(texto.size() - sufixo.size(), sufixo.size(), sufixo) == 0;
}

static bool dentroCacheRuido(const std::string &caminhoMenor) {
    if (caminhoMenor.find("\\inetcache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\inetcookies") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\inethistory") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\history.ie5") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\content.ie5") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\temporary internet files") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\webcache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\appcache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\domstore") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\iecompatcache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\iecompatuacache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\feeds cache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\apprepository") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\helium") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\packages\\") != std::string::npos) {
        if (caminhoMenor.find("\\ac\\") != std::string::npos) {
            return true;
        }
    }
    if (caminhoMenor.find("\\microsoft\\protect") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\credentials") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\drm") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\winmsipc") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\wwansvc") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\windows\\devicemetadatacache") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\microsoft\\windows\\retaildemo") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\playready") != std::string::npos) {
        return true;
    }
    if (caminhoMenor.find("\\temp\\winsyscache") != std::string::npos) {
        return true;
    }
    if (terminaCom(caminhoMenor, "\\microsoft\\settings")) {
        return true;
    }
    return false;
}

static bool ehEsqueletoPerfil(const std::string &caminhoMenor, const std::string &nomeMenor) {
    if (nomeMenor == "ntuser.ini") {
        return true;
    }
    if (nomeMenor == "windows sidebar") {
        return true;
    }
    if (nomeMenor == "user pinned") {
        if (caminhoMenor.find("\\quick launch\\user pinned") != std::string::npos) {
            return true;
        }
    }
    if (nomeMenor == "appdata") {
        size_t p = caminhoMenor.find("\\users\\");
        if (p != std::string::npos) {
            size_t resto = p + 7;
            size_t barra = caminhoMenor.find("\\", resto);
            if (barra != std::string::npos && barra + 8 == caminhoMenor.size()) {
                return true;
            }
        }
    }
    if (nomeMenor == "default") {
        if (terminaCom(caminhoMenor, "\\users\\default")) {
            return true;
        }
    }
    if (nomeMenor == "public") {
        if (terminaCom(caminhoMenor, "\\users\\public")) {
            return true;
        }
    }
    if (nomeMenor == "accountpictures" || nomeMenor == "libraries") {
        if (caminhoMenor.find("\\users\\public\\") != std::string::npos) {
            return true;
        }
    }
    if (nomeMenor == "desktop") {
        if (terminaCom(caminhoMenor, "\\users\\public\\desktop")) {
            return true;
        }
    }
    return false;
}

static bool ehRuidoArquivo(const std::string &caminhoMenor, const std::string &nomeMenor) {
    if (nomeMenor == "desktop.ini") {
        return true;
    }
    if (nomeMenor == "container.dat") {
        return true;
    }
    if (nomeMenor == "thumbs.db") {
        return true;
    }
    if (nomeMenor == "webcachelock.dat") {
        return true;
    }
    if (nomeMenor == "activationstore.dat.log1") {
        return true;
    }
    if (nomeMenor == "activationstore.dat.log2") {
        return true;
    }
    if (terminaCom(nomeMenor, ".regtrans-ms")) {
        return true;
    }
    if (terminaCom(nomeMenor, ".blf")) {
        return true;
    }
    if (terminaCom(nomeMenor, ".log1") || terminaCom(nomeMenor, ".log2")) {
        if (caminhoMenor.find("ntuser.dat") != std::string::npos) {
            return true;
        }
        if (caminhoMenor.find("usrclass.dat") != std::string::npos) {
            return true;
        }
        if (caminhoMenor.find("privateregistry.bin") != std::string::npos) {
            return true;
        }
        if (caminhoMenor.find("settings.dat") != std::string::npos) {
            return true;
        }
        if (caminhoMenor.find("activationstore.dat") != std::string::npos) {
            return true;
        }
        if (caminhoMenor.find("_com15.dat") != std::string::npos) {
            return true;
        }
    }
    if (nomeMenor == "credhist" || nomeMenor == "preferred") {
        if (caminhoMenor.find("\\microsoft\\protect\\") != std::string::npos) {
            return true;
        }
    }
    return false;
}

static void classificarSistema(modelos::ArquivoOculto &item) {
    std::string caminho = menorTexto(item.caminho);
    char winDir[MAX_PATH];
    UINT t = GetWindowsDirectoryA(winDir, MAX_PATH);
    if (t == 0) {
        return;
    }
    std::string windows = menorTexto(std::string(winDir));
    std::string s32 = windows + "\\system32";
    std::string s64 = windows + "\\syswow64";
    bool emSistema = false;
    if (caminho.rfind(s32, 0) == 0) {
        emSistema = true;
    }
    if (caminho.rfind(s64, 0) == 0) {
        emSistema = true;
    }
    if (caminho.find("\\winsxs\\") != std::string::npos) {
        emSistema = true;
    }
    if (emSistema) {
        bool assinado = false;
        try {
            assinado = assinatura::ehValida(item.caminho);
        } catch (...) {
            assinado = false;
        }
        if (assinado) {
            item.categoria = item.categoria + "-legit";
            item.motivo = item.motivo + " [legitimate Microsoft]";
        }
    }
}

static modelos::ArquivoOculto montarItem(const std::string &caminho, DWORD attr, const std::string &categoria, const std::string &motivo) {
    modelos::ArquivoOculto item;
    item.caminho = caminho;
    item.atributos = descreverAtributos(attr);
    item.categoria = categoria;
    item.motivo = motivo;
    item.tamanho = 0;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WIN32_FILE_ATTRIBUTE_DATA dados;
        std::wstring w = largo(caminho);
        if (GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &dados)) {
            unsigned long long alto = (unsigned long long)dados.nFileSizeHigh;
            unsigned long long baixo = (unsigned long long)dados.nFileSizeLow;
            unsigned long long total = (alto * 4294967296ULL) + baixo;
            item.tamanho = (long long)total;
        }
    }
    return item;
}

static void varrerRecursivo(const std::string &diretorio, std::vector<modelos::ArquivoOculto> &achados, bool completo, std::function<void(const std::string&)> progresso, int profundidade) {
    if (profundidade > 24) {
        return;
    }
    std::wstring wdir = largo(diretorio);
    std::wstring padrao = wdir;
    if (!padrao.empty() && padrao[padrao.size() - 1] != L'\\') {
        padrao = padrao + L"\\";
    }
    padrao = padrao + L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(padrao.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    if (progresso && profundidade <= 2) {
        try {
            progresso(diretorio);
        } catch (...) {
        }
    }
    do {
        std::wstring wn = fd.cFileName;
        if (wn == L"." || wn == L"..") {
            continue;
        }
        std::string nome = estreito(wn);
        std::string completo2 = diretorio;
        if (!completo2.empty() && completo2[completo2.size() - 1] != '\\') {
            completo2 = completo2 + "\\";
        }
        completo2 = completo2 + nome;
        DWORD attr = fd.dwFileAttributes;
        bool ehOculto = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
        bool ehSistema = (attr & FILE_ATTRIBUTE_SYSTEM) != 0;
        bool ehDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        std::string menorNome = menorTexto(nome);
        std::string menorCaminho = menorTexto(completo2);
        if (ehDir) {
            if (menorNome == ".vs") {
                continue;
            }
            if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                continue;
            }
            if (dentroCacheRuido(menorCaminho)) {
                continue;
            }
        }
        if (dentroCacheRuido(menorCaminho)) {
            continue;
        }
        if (ehRuidoArquivo(menorCaminho, menorNome)) {
            continue;
        }
        if (ehEsqueletoPerfil(menorCaminho, menorNome)) {
            continue;
        }
        if (ehOculto && ehSistema) {
            modelos::ArquivoOculto item = montarItem(completo2, attr, "os-protected-hidden", "OS-protected file hidden from the default Explorer view");
            classificarSistema(item);
            achados.push_back(item);
        } else if (ehOculto) {
            if (completo || ehDir || nomeSuspeito(nome) || extensaoDupla(nome)) {
                modelos::ArquivoOculto item = montarItem(completo2, attr, "hidden", "File with the hidden attribute");
                if (nomeSuspeito(nome)) {
                    item.categoria = "suspicious-name";
                    item.motivo = item.motivo + " + camouflaged naming trick";
                }
                if (extensaoDupla(nome)) {
                    item.categoria = "double-extension";
                    item.motivo = item.motivo + " + double extension";
                }
                classificarSistema(item);
                achados.push_back(item);
            }
        } else {
            if (completo && (nomeSuspeito(nome) || extensaoDupla(nome))) {
                modelos::ArquivoOculto item = montarItem(completo2, attr, "camouflaged", "Camouflaged name without the hidden attribute");
                classificarSistema(item);
                achados.push_back(item);
            }
        }
        if (ehDir) {
            if (deveIgnorar(nome) && !completo) {
                continue;
            }
            varrerRecursivo(completo2, achados, completo, progresso, profundidade + 1);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

std::vector<modelos::ArquivoOculto> varrer(const std::vector<std::string> &caminhos, bool completo, std::function<void(const std::string&)> progresso) {
    std::vector<modelos::ArquivoOculto> achados;
    for (size_t i = 0; i < caminhos.size(); i = i + 1) {
        try {
            varrerRecursivo(caminhos[i], achados, completo, progresso, 0);
        } catch (...) {
        }
    }
    std::vector<modelos::ArquivoOculto> unicos;
    std::set<std::string> vistos;
    for (size_t i = 0; i < achados.size(); i = i + 1) {
        std::string chave = menorTexto(achados[i].caminho);
        if (vistos.find(chave) != vistos.end()) {
            continue;
        }
        vistos.insert(chave);
        unicos.push_back(achados[i]);
    }
    return unicos;
}

std::vector<std::string> caminhosPadrao(bool completo) {
    std::vector<std::string> lista;
    char temp[MAX_PATH];
    DWORD tt = GetTempPathA(MAX_PATH, temp);
    std::string tempS;
    if (tt > 0) {
        tempS = std::string(temp);
    }
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
        std::string s(appdata);
        if (!s.empty()) {
            lista.push_back(s);
        }
    }
    char local[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local))) {
        std::string s(local);
        bool existe = false;
        for (size_t i = 0; i < lista.size(); i = i + 1) {
            if (lista[i] == s) {
                existe = true;
            }
        }
        if (!existe && !s.empty()) {
            lista.push_back(s);
        }
    }
    char comum[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, comum))) {
        std::string s(comum);
        bool existe = false;
        for (size_t i = 0; i < lista.size(); i = i + 1) {
            if (lista[i] == s) {
                existe = true;
            }
        }
        if (!existe && !s.empty()) {
            lista.push_back(s);
        }
    }
    if (!tempS.empty()) {
        bool existe = false;
        for (size_t i = 0; i < lista.size(); i = i + 1) {
            if (lista[i] == tempS) {
                existe = true;
            }
        }
        if (!existe) {
            lista.push_back(tempS);
        }
    }
    if (completo) {
        DWORD drives = GetLogicalDrives();
        for (int d = 0; d < 26; d = d + 1) {
            if (drives & (1UL << d)) {
                char raiz[4];
                raiz[0] = (char)('A' + d);
                raiz[1] = ':';
                raiz[2] = '\\';
                raiz[3] = '\0';
                UINT tipo = GetDriveTypeA(raiz);
                if (tipo == DRIVE_FIXED) {
                    char fs[16];
                    if (GetVolumeInformationA(raiz, nullptr, 0, nullptr, nullptr, nullptr, fs, sizeof(fs))) {
                        std::string nomeFs(fs);
                        for (size_t i = 0; i < nomeFs.size(); i = i + 1) {
                            char c = nomeFs[i];
                            if (c >= 'a' && c <= 'z') {
                                nomeFs[i] = (char)(c - 32);
                            }
                        }
                        if (nomeFs == "NTFS" || nomeFs == "FAT32" || nomeFs == "EXFAT") {
                            lista.push_back(std::string(raiz));
                        }
                    } else {
                        lista.push_back(std::string(raiz));
                    }
                }
            }
        }
    } else {
        std::string usuarios = "C:\\Users";
        DWORD at = GetFileAttributesA(usuarios.c_str());
        if (at != INVALID_FILE_ATTRIBUTES) {
            lista.push_back(usuarios);
        }
    }
    if (lista.empty()) {
        char perfil[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, perfil))) {
            lista.push_back(std::string(perfil));
        }
    }
    return lista;
}

}
}
