#pragma once
#include <string>
#include <unhide/models.h>

namespace unhide {
namespace relatorio {

std::string salvar(const modelos::ResultadoAnalise &r, const std::string &pasta);
std::string agoraTexto();
std::string escaparJson(const std::string &texto);

}
}
