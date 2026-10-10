#include <unhide/config.h>
#include <unhide/registry.h>

namespace unhide {
namespace configuracao {

std::map<std::string, std::string> obter() {
    std::map<std::string, std::string> mapa;
    std::wstring base = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
    int superOculto = registro::lerInteiro(base, L"ShowSuperHidden", 0, false);
    int oculto = registro::lerInteiro(base, L"Hidden", 2, false);
    int extensao = registro::lerInteiro(base, L"HideFileExt", 1, false);
    char tmp[32];
    _snprintf_s(tmp, sizeof(tmp), sizeof(tmp) - 1, "%d", superOculto);
    mapa["ShowSuperHidden"] = std::string(tmp);
    _snprintf_s(tmp, sizeof(tmp), sizeof(tmp) - 1, "%d", oculto);
    mapa["Hidden"] = std::string(tmp);
    _snprintf_s(tmp, sizeof(tmp), sizeof(tmp) - 1, "%d", extensao);
    mapa["HideFileExt"] = std::string(tmp);
    if (superOculto == 0) {
        mapa["HideProtected"] = "ENABLED";
        mapa["HideProtectedDetail"] = "Explorer hides protected operating system files";
    } else {
        mapa["HideProtected"] = "DISABLED";
        mapa["HideProtectedDetail"] = "Explorer shows protected operating system files";
    }
    if (oculto == 1) {
        mapa["ShowHidden"] = "ENABLED";
    } else {
        mapa["ShowHidden"] = "DISABLED";
    }
    if (extensao == 1) {
        mapa["HideExtensions"] = "ENABLED";
    } else {
        mapa["HideExtensions"] = "DISABLED";
    }
    std::wstring chaveApp = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    std::string appInit = registro::lerValor(chaveApp, L"AppInit_DLLs", true);
    std::string appHab = registro::lerValor(chaveApp, L"LoadAppInit_DLLs", true);
    mapa["AppInit_DLLs"] = appInit;
    mapa["AppInit_Enabled"] = appHab;
    return mapa;
}

}
}
