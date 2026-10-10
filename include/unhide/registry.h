#pragma once
#include <string>
#include <map>

namespace unhide {
namespace registro {

std::string lerValor(const std::wstring &subchave, const std::wstring &nome, bool maquinaLocal);
int lerInteiro(const std::wstring &subchave, const std::wstring &nome, int padrao, bool maquinaLocal);
std::map<std::string, std::string> lerChave(const std::wstring &subchave, bool maquinaLocal);
std::wstring paraLargo(const std::string &texto);
std::string paraEstreito(const std::wstring &texto);

}
}
